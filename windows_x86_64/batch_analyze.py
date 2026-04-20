#!/usr/bin/env python3
"""
Batch PE Unpacking Analyzer - Independent Worker Pool Architecture.

Each worker has its own vagrant VM and disk image, enabling fully parallel
provisioning and analysis with complete fault isolation.

Usage:
    # One-time: compile harness and create 4 worker VMs
    make compile
    python3 batch_analyze.py setup -n 4

    # Run batch analysis
    python3 batch_analyze.py run /path/to/samples -o ./results -t 600

    # Check worker status
    python3 batch_analyze.py status

    # Tear down all workers
    python3 batch_analyze.py teardown
"""

import argparse
import enum
import json
import logging
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("batch_analyze")

# -- Constants --

PE_EXTENSIONS = {".exe", ".dll", ".scr", ".sys"}
WORKERS_DIR = "workers"
WORKERS_CONFIG = "workers.json"
PROVISION_TIMEOUT = 300
HALT_TIMEOUT = 120
SIGTERM_GRACE = 3
MAX_CONSECUTIVE_FAILURES = 5
HPRINTF_SUCCESS_MARKERS = [
    "WtE single execution complete",
    "Unpacking complete",
    "Single execution complete",
]

# Vagrantfile template for worker VMs.
# Worker ID is derived from directory name (worker0 -> "0").
# All Ruby #{} interpolations pass through Python unchanged.
VAGRANTFILE_TEMPLATE = """\
# Auto-generated for kAFL batch analysis worker.
WORKER_ID = File.basename(__dir__).sub('worker', '')
TARGET = ENV['TARGET_HARNESS'] || 'userspace'
WORKER_DIR = File.expand_path(__dir__)
PROJECT_DIR = File.expand_path('../..', WORKER_DIR)
ROOT_DIR = File.expand_path('../../..', WORKER_DIR)

Vagrant.configure("2") do |config|
    config.vm.box = "kafl_windows"
    config.vm.define "kafl-worker-#{WORKER_ID}"

    config.vm.synced_folder ".", "/vagrant", disabled: true

    config.vm.communicator = "winrm"
    config.winrm.username = "vagrant"
    config.winrm.password = "vagrant"
    config.winrm.transport = :negotiate
    config.vm.boot_timeout = 600

    config.trigger.before :up do |trigger|
        trigger.info = "Unset HTTP_PROXY"
        ENV['HTTP_PROXY'] = nil
        ENV['HTTPS_PROXY'] = nil
        ENV['http_proxy'] = nil
        ENV['https_proxy'] = nil
    end

    config.vm.provider :libvirt do |libvirt|
        libvirt.uri = "qemu:///session"
        libvirt.graphics_type = "spice"
        libvirt.cpus = 2
        libvirt.cputopology :sockets => '1', :cores => '2', :threads => '1'
        libvirt.memory = 4096
    end

    config.trigger.after :provision do |trigger|
        trigger.info = "Provisioning worker #{WORKER_ID}"
        trigger.run = {inline: "bash -c 'source #{ROOT_DIR}/venv/bin/activate && cd #{WORKER_DIR} && #{PROJECT_DIR}/setup_target.sh -e target_harness=#{TARGET} -e bin_src=#{WORKER_DIR}/bin'"}
    end
end
"""

# -- Graceful shutdown --

_shutdown = threading.Event()


def _signal_handler(_sig, _frame):
    logger.info("Shutdown requested, finishing current samples...")
    _shutdown.set()


# -- Enums & Dataclasses --


class SampleStatus(enum.Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class WorkerInfo:
    worker_id: int
    worker_dir: Path
    vm_name: str
    disk_image: Path


@dataclass(frozen=True)
class BatchConfig:
    samples_dir: Path
    output_dir: Path
    workdir_base: Path
    timeout_seconds: int
    project_dir: Path
    force: bool
    qemu_memory: int
    kafl_extra_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class SampleResult:
    sample_name: str
    status: SampleStatus
    duration_seconds: float
    worker_id: int = -1
    error_message: Optional[str] = None
    wte_count: Optional[int] = None
    dump_file_count: int = 0


# -- Sample Discovery --


def discover_samples(samples_dir: Path) -> list[Path]:
    """Find all PE files in the samples directory, sorted alphabetically."""
    resolved = samples_dir.resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"Samples directory not found: {resolved}")

    samples = []
    for entry in sorted(resolved.iterdir()):
        if entry.is_symlink():
            real = entry.resolve()
            if not real.is_relative_to(resolved):
                logger.warning("Skipping symlink escaping dir: %s", entry.name)
                continue
        if entry.is_file() and entry.suffix.lower() in PE_EXTENSIONS:
            if entry.stat().st_size > 0:
                samples.append(entry)
            else:
                logger.warning("Skipping empty file: %s", entry.name)

    return samples


def is_already_processed(sample_path: Path, output_dir: Path) -> bool:
    """Check if a sample was already successfully processed."""
    result_file = output_dir / sample_path.stem / "result.json"
    if not result_file.exists():
        return False
    try:
        data = json.loads(result_file.read_text())
        return data.get("status") == SampleStatus.SUCCESS.value
    except (json.JSONDecodeError, OSError):
        return False


# -- Worker Setup & Teardown --


def setup_workers(project_dir: Path, num_workers: int) -> list[WorkerInfo]:
    """Create N independent worker VMs with vagrant.

    Each worker gets its own directory, Vagrantfile, VM, and disk image.
    """
    workers_base = project_dir / WORKERS_DIR
    bin_dir = project_dir / "bin"

    if not (bin_dir / "userspace" / "unpack_harness.exe").exists():
        raise RuntimeError(
            "Compiled binaries not found in bin/. Run 'make compile' first."
        )

    workers_base.mkdir(parents=True, exist_ok=True)
    workers: list[WorkerInfo] = []

    for i in range(num_workers):
        logger.info("=" * 50)
        logger.info("Setting up worker %d/%d...", i + 1, num_workers)
        worker_dir = workers_base / f"worker{i}"
        vm_name = f"kafl-worker-{i}"

        # If worker already fully set up (has snapshot), reuse it
        if _is_worker_ready(worker_dir, vm_name):
            logger.info("Worker %d already set up, reusing", i)
            disk_image = _discover_disk_image(worker_dir, vm_name)
        else:
            # Clean up any partial state from previous attempts
            if worker_dir.exists():
                logger.info("Cleaning up partial worker %d...", i)
                _destroy_worker_vm(worker_dir)
                shutil.rmtree(worker_dir)

            _create_worker_dir(worker_dir, project_dir)
            _init_worker_vm(worker_dir)
            disk_image = _discover_disk_image(worker_dir, vm_name)

        logger.info("Worker %d ready: %s (image: %s)", i, vm_name, disk_image)

        workers.append(WorkerInfo(
            worker_id=i,
            worker_dir=worker_dir,
            vm_name=vm_name,
            disk_image=disk_image,
        ))

    _save_workers_config(workers_base, workers)
    return workers


def _is_worker_ready(worker_dir: Path, vm_name: str) -> bool:
    """Check if a worker VM is already fully set up with a snapshot."""
    if not worker_dir.exists():
        return False
    if not (worker_dir / "Vagrantfile").exists():
        return False
    try:
        result = subprocess.run(
            ["vagrant", "snapshot", "list"],
            cwd=worker_dir, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return False
        return "ready_provision" in result.stdout
    except Exception:
        return False


def _destroy_worker_vm(worker_dir: Path) -> None:
    """Destroy a worker VM (best-effort, for cleanup).

    Falls back to virsh undefine if vagrant destroy fails to remove
    the libvirt domain.
    """
    worker_id = worker_dir.name.replace("worker", "")
    vm_name = f"kafl-worker-{worker_id}"
    domain_name = f"{worker_dir.name}_{vm_name}"

    try:
        subprocess.run(
            ["vagrant", "destroy", "-f"],
            cwd=worker_dir, capture_output=True, text=True, timeout=120,
        )
    except Exception as e:
        logger.debug("vagrant destroy failed (non-critical): %s", e)

    # Fallback: remove lingering libvirt domain via virsh
    for conn in ["qemu:///session", "qemu:///system"]:
        try:
            result = subprocess.run(
                ["virsh", "-c", conn, "domstate", domain_name],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                continue
            state = result.stdout.strip()
            # Any active state (running, paused, etc.) needs destroy first
            if state not in ("shut off", ""):
                subprocess.run(
                    ["virsh", "-c", conn, "destroy", domain_name],
                    capture_output=True, text=True, timeout=30,
                )
            undef = subprocess.run(
                ["virsh", "-c", conn, "undefine", domain_name,
                 "--remove-all-storage", "--snapshots-metadata"],
                capture_output=True, text=True, timeout=30,
            )
            if undef.returncode == 0:
                logger.info("Removed lingering domain %s via %s", domain_name, conn)
            else:
                logger.warning(
                    "virsh undefine failed for %s via %s: %s",
                    domain_name, conn, undef.stderr.strip(),
                )
        except Exception as e:
            logger.debug("virsh cleanup failed for %s (%s): %s", domain_name, conn, e)


def _create_worker_dir(worker_dir: Path, project_dir: Path) -> None:
    """Create worker directory with Vagrantfile, symlinks, and bin/ copy."""
    worker_dir.mkdir(parents=True)

    # Write Vagrantfile
    (worker_dir / "Vagrantfile").write_text(VAGRANTFILE_TEMPLATE)

    # Symlink shared files
    for name in ["ansible.cfg", "setup_target.sh", "setup_target.yml"]:
        src = project_dir / name
        dst = worker_dir / name
        if src.exists():
            dst.symlink_to(os.path.relpath(src, worker_dir))

    # Copy compiled binaries (each worker needs its own bin/ for target_packed.exe)
    bin_src = project_dir / "bin"
    bin_dst = worker_dir / "bin"
    shutil.copytree(bin_src, bin_dst)
    logger.debug("Created worker dir: %s", worker_dir)


def _init_worker_vm(worker_dir: Path) -> None:
    """Initialize worker VM: vagrant up -> snapshot save -> halt."""
    _run_cmd(
        ["vagrant", "up", "--no-provision"],
        cwd=worker_dir, timeout=900,
        label="vagrant up",
    )
    _run_cmd(
        ["vagrant", "snapshot", "save", "ready_provision"],
        cwd=worker_dir, timeout=120,
        label="vagrant snapshot save",
    )
    _run_cmd(
        ["vagrant", "halt"],
        cwd=worker_dir, timeout=HALT_TIMEOUT,
        label="vagrant halt",
    )


def _discover_disk_image(worker_dir: Path, vm_name: str) -> Path:
    """Find the libvirt-managed disk image for a worker VM."""
    # Method 1: vagrant machine ID -> virsh domblklist
    id_file = worker_dir / ".vagrant" / "machines" / vm_name / "libvirt" / "id"
    if id_file.exists():
        domain_id = id_file.read_text().strip()
        try:
            result = subprocess.run(
                ["virsh", "-c", "qemu:///session", "domblklist", domain_id],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and not parts[1].startswith("-"):
                        path = Path(parts[1])
                        if path.exists() and path.is_file():
                            return path
        except Exception as e:
            logger.debug("virsh domblklist failed: %s", e)

    # Method 2: search default libvirt image directories
    dir_name = worker_dir.name
    search_dirs = [
        Path.home() / ".local" / "share" / "libvirt" / "images",
        Path("/var/lib/libvirt/images"),
    ]
    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for candidate in search_dir.glob(f"{dir_name}_{vm_name}*"):
            if candidate.is_file():
                return candidate

    raise RuntimeError(
        f"Could not discover disk image for {vm_name}. "
        f"Run: virsh -c qemu:///session domblklist {vm_name}"
    )


def _save_workers_config(workers_base: Path, workers: list[WorkerInfo]) -> None:
    """Save worker config to workers.json."""
    config_data = {
        "workers": [
            {
                "worker_id": w.worker_id,
                "worker_dir": str(w.worker_dir),
                "vm_name": w.vm_name,
                "disk_image": str(w.disk_image),
            }
            for w in workers
        ],
    }
    config_path = workers_base / WORKERS_CONFIG
    config_path.write_text(json.dumps(config_data, indent=2) + "\n")
    logger.info("Workers config: %s", config_path)


def load_workers(project_dir: Path) -> list[WorkerInfo]:
    """Load worker config from workers.json with path validation."""
    config_path = project_dir / WORKERS_DIR / WORKERS_CONFIG
    if not config_path.exists():
        raise FileNotFoundError(
            "Workers not set up. Run 'python3 batch_analyze.py setup' first."
        )

    workers_base = (project_dir / WORKERS_DIR).resolve()
    data = json.loads(config_path.read_text())
    workers: list[WorkerInfo] = []

    for w in data["workers"]:
        worker_dir = Path(w["worker_dir"]).resolve()
        disk_image = Path(w["disk_image"])

        # Validate worker_dir is under workers/ directory
        if not worker_dir.is_relative_to(workers_base):
            raise ValueError(
                f"worker_dir escapes workers base: {worker_dir}"
            )
        if not disk_image.is_file():
            raise FileNotFoundError(f"Disk image missing: {disk_image}")

        workers.append(WorkerInfo(
            worker_id=w["worker_id"],
            worker_dir=worker_dir,
            vm_name=w["vm_name"],
            disk_image=disk_image,
        ))

    return workers


def teardown_workers(project_dir: Path) -> None:
    """Destroy all worker VMs and remove directories."""
    workers_base = project_dir / WORKERS_DIR
    if not workers_base.exists():
        logger.info("No workers directory found")
        return

    try:
        workers = load_workers(project_dir)
    except (FileNotFoundError, json.JSONDecodeError):
        workers = []

    for w in workers:
        logger.info("Destroying worker %d (%s)...", w.worker_id, w.vm_name)
        _destroy_worker_vm(w.worker_dir)

    # Also scan for worker dirs not in config (e.g. setup crashed before saving)
    known_dirs = {w.worker_dir for w in workers}
    for entry in sorted(workers_base.iterdir()):
        if entry.is_dir() and entry.name.startswith("worker") and entry not in known_dirs:
            logger.info("Cleaning up orphaned worker dir: %s", entry.name)
            _destroy_worker_vm(entry)

    # Prune stale vagrant global-status entries
    try:
        subprocess.run(
            ["vagrant", "global-status", "--prune"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        pass

    shutil.rmtree(workers_base)
    logger.info("All workers removed")


# -- Worker Operations --


def provision_sample(worker: WorkerInfo, sample_path: Path) -> None:
    """Provision a worker VM with a specific sample.

    Flow: copy PE -> snapshot restore -> ansible provision -> halt.
    """
    target = worker.worker_dir / "bin" / "userspace" / "target_packed.exe"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sample_path, target)
    logger.debug(
        "[W%d] Copied %s -> target_packed.exe", worker.worker_id, sample_path.name
    )

    # Restore snapshot (boots VM to clean state)
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            _run_cmd(
                ["vagrant", "snapshot", "restore", "ready_provision"],
                cwd=worker.worker_dir, timeout=PROVISION_TIMEOUT,
                label=f"W{worker.worker_id} snapshot restore",
            )
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if attempt == max_retries:
                raise
            logger.warning(
                "[W%d] Snapshot restore failed (attempt %d/%d), recovering...",
                worker.worker_id, attempt, max_retries,
            )
            # Aggressive cleanup: kill stray QEMU, force VM off, then retry
            _cleanup_kafl(Path("/nonexistent"), worker)
            _force_vm_off(worker)
            time.sleep(3)

    # Provision (ansible uploads bin/ and creates startup shortcut)
    env = {**os.environ, "TARGET_HARNESS": "unpack"}
    _run_cmd(
        ["vagrant", "provision"],
        cwd=worker.worker_dir, timeout=PROVISION_TIMEOUT,
        label=f"W{worker.worker_id} provision",
        env=env,
    )

    # Clean halt preserves disk state for QEMU-Nyx
    _halt_worker(worker)


def _halt_worker(worker: WorkerInfo) -> None:
    """Halt worker VM: clean shutdown with forced fallback + process kill.

    vagrant halt / virsh destroy sometimes leave the QEMU process alive,
    which locks the disk image and causes subsequent QEMU-Nyx launches
    to crash with 'Broken pipe'.  After VM-level halt, explicitly kill
    any remaining libvirt QEMU process for this worker's disk image.
    """
    try:
        result = subprocess.run(
            ["vagrant", "halt"],
            cwd=worker.worker_dir, capture_output=True, text=True,
            timeout=HALT_TIMEOUT,
        )
        if result.returncode == 0:
            _ensure_vm_process_dead(worker)
            return
        logger.warning("[W%d] Clean halt failed, forcing", worker.worker_id)
    except subprocess.TimeoutExpired:
        logger.warning("[W%d] Clean halt timed out, forcing", worker.worker_id)

    try:
        subprocess.run(
            ["vagrant", "halt", "-f"],
            cwd=worker.worker_dir, capture_output=True, text=True,
            timeout=60,
        )
    except Exception as e:
        logger.warning("[W%d] Forced halt failed: %s", worker.worker_id, e)

    _ensure_vm_process_dead(worker)


def _ensure_vm_process_dead(worker: WorkerInfo) -> None:
    """Kill any QEMU process still using this worker's disk image
    and verify it is actually gone before returning.

    After vagrant halt, the libvirt QEMU process sometimes survives.
    It holds the qcow2 image open, blocking QEMU-Nyx from using it.
    Retries up to 5 times with escalating waits to confirm the
    process is truly dead.
    """
    disk = str(worker.disk_image)
    max_attempts = 5

    for attempt in range(1, max_attempts + 1):
        # Kill anything using this disk image
        try:
            subprocess.run(
                ["pkill", "-9", "-f", disk],
                timeout=10, capture_output=True,
            )
        except Exception:
            pass

        time.sleep(1)

        # Verify: check if any process still references this disk
        try:
            result = subprocess.run(
                ["pgrep", "-f", disk],
                timeout=5, capture_output=True, text=True,
            )
            if result.returncode != 0 or not result.stdout.strip():
                # No process found — confirmed dead
                logger.debug(
                    "[W%d] VM process confirmed dead (attempt %d)",
                    worker.worker_id, attempt,
                )
                return
            logger.warning(
                "[W%d] VM process still alive after kill (attempt %d/%d): PIDs %s",
                worker.worker_id, attempt, max_attempts,
                result.stdout.strip().replace('\n', ', '),
            )
        except Exception:
            return  # pgrep failed, assume dead

        time.sleep(attempt)  # escalating wait: 1s, 2s, 3s, 4s, 5s

    # Last resort: virsh destroy + force kill
    logger.warning("[W%d] VM process survived %d kill attempts, virsh destroy",
                   worker.worker_id, max_attempts)
    _force_vm_off(worker)
    time.sleep(2)


def _force_vm_off(worker: WorkerInfo) -> None:
    """Force VM off via virsh destroy (best-effort, for stuck VMs)."""
    domain = f"{worker.worker_dir.name}_{worker.vm_name}"
    for conn in ["qemu:///session", "qemu:///system"]:
        try:
            subprocess.run(
                ["virsh", "-c", conn, "destroy", domain],
                capture_output=True, text=True, timeout=15,
            )
        except Exception:
            pass
    # Also try vagrant halt -f as last resort
    try:
        subprocess.run(
            ["vagrant", "halt", "-f"],
            cwd=worker.worker_dir, capture_output=True, text=True, timeout=30,
        )
    except Exception:
        pass


# -- kAFL Execution --


def run_kafl(
    workdir: Path,
    project_dir: Path,
    worker: WorkerInfo,
    timeout: int,
    qemu_memory: int,
    extra_args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess:
    """Run kafl fuzz with a worker's disk image."""
    workdir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "kafl", "fuzz",
        "--purge",
        "-w", str(workdir),
        "--log-hprintf",
        "--trace",
        "-p", "1",
        "--image", str(worker.disk_image),
        "--memory", str(qemu_memory),
    ]

    # Per-worker monitor socket and VNC on unique port per worker
    monitor_sock = workdir / "monitor.sock"
    vnc_port = 5900 + worker.worker_id  # W0=:0 (5900), W1=:1 (5901), ...
    qemu_extra = f"-monitor unix:{monitor_sock},server,nowait -vnc :{worker.worker_id}"
    cmd.append(f"--qemu-extra={qemu_extra}")
    cmd.extend(extra_args)

    logger.info("[W%d] kafl: %s", worker.worker_id, " ".join(cmd))
    start = time.time()

    # Pin each worker to dedicated physical cores to prevent Intel PT
    # MSR contention.  Worker N uses cores [N*2, N*2+1] (2 cores each,
    # matching the VM's vCPU count).  This ensures PT trace buffers and
    # MSR state are never clobbered by another VM's context switch.
    cores_per_worker = 2
    cpu_start = worker.worker_id * cores_per_worker
    cpu_end = cpu_start + cores_per_worker - 1
    taskset_prefix = ["taskset", "-c", f"{cpu_start}-{cpu_end}"]

    proc = subprocess.Popen(
        taskset_prefix + cmd, cwd=project_dir,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("[W%d] kafl timed out after %ds", worker.worker_id, timeout)
        _kill_process_tree(proc)
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        # Kill any orphaned QEMU children that survived process group kill
        _cleanup_kafl(workdir, worker)
        raise subprocess.TimeoutExpired(cmd, timeout, stdout, stderr)

    elapsed = time.time() - start

    # Log output on failure or suspiciously fast exit
    if proc.returncode != 0 or elapsed < 30:
        log_fn = logger.error if proc.returncode != 0 else logger.warning
        log_fn(
            "[W%d] kafl rc=%d (%.1fs)", worker.worker_id, proc.returncode, elapsed
        )
        if stdout:
            for line in stdout.strip().splitlines()[-20:]:
                log_fn("  stdout: %s", line)
        if stderr:
            for line in stderr.strip().splitlines()[-20:]:
                log_fn("  stderr: %s", line)

    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Kill the process, its process group, and all descendant processes.

    Uses /proc traversal to find children that escaped the process group
    (e.g. QEMU spawned by kafl with a new session).
    """
    # Collect all descendant PIDs before killing anything
    descendants = _get_descendant_pids(proc.pid)

    # 1) Kill the process group (covers same-session children)
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        try:
            proc.wait(timeout=SIGTERM_GRACE)
        except subprocess.TimeoutExpired:
            os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass

    # 2) Kill any descendants that survived (different session/group)
    for pid in descendants:
        try:
            os.kill(pid, signal.SIGKILL)
            logger.debug("Killed orphaned descendant PID %d", pid)
        except ProcessLookupError:
            pass


def _get_descendant_pids(parent_pid: int) -> list[int]:
    """Recursively find all descendant PIDs using ps (portable)."""
    try:
        result = subprocess.run(
            ["ps", "-o", "pid=", "--ppid", str(parent_pid)],
            capture_output=True, text=True, timeout=5,
        )
        children = [int(p.strip()) for p in result.stdout.split() if p.strip()]
    except Exception:
        return []
    descendants = list(children)
    for child in children:
        descendants.extend(_get_descendant_pids(child))
    return descendants


# -- Result Validation & Collection --


def validate_results(workdir: Path) -> tuple[bool, int, Optional[int]]:
    """Check analysis results by parsing hprintf log and dump artifacts.

    Success criteria (any of):
      1. hprintf contains a known success marker, OR
      2. dump directory has WtE fulldump directories (dumps > 0)
    The second criterion catches timeout cases where the harness was
    killed before printing the completion message but WtE dumps exist.
    """
    hprintf_log = workdir / "hprintf_00.log"
    success = False
    wte_count = None
    dump_count = 0

    if hprintf_log.exists():
        content = hprintf_log.read_text(errors="replace")
        for marker in HPRINTF_SUCCESS_MARKERS:
            if marker in content:
                success = True
                break
        match = re.search(r"WtE count:\s*(\d+)", content)
        if match:
            wte_count = int(match.group(1))

    dump_dir = workdir / "dump"
    if dump_dir.is_dir():
        dump_count = sum(1 for f in dump_dir.rglob("*") if f.is_file())

    # Fallback WtE count from timeline if hprintf didn't report it
    if wte_count is None:
        tl = dump_dir / "wte_timeline.txt" if dump_dir.is_dir() else None
        if tl and tl.exists():
            lines = [l for l in tl.read_text(errors="replace").splitlines()
                     if l.strip() and not l.startswith("#")]
            # Exclude EP_INIT line (seq 000)
            wte_lines = [l for l in lines if "EP_INIT" not in l]
            if wte_lines:
                wte_count = len(wte_lines)

    # If dumps exist (beyond EP_INIT fulldump_000), consider it a success
    if not success and dump_count > 0:
        # Count actual WtE fulldump directories (not just files)
        if dump_dir.is_dir():
            wte_dumps = [d for d in dump_dir.iterdir()
                         if d.is_dir() and d.name.startswith("fulldump_")
                         and "ep_initial" not in d.name]
            if wte_dumps:
                success = True

    return success, dump_count, wte_count


def collect_results(
    workdir: Path,
    output_dir: Path,
    sample_name: str,
    result: SampleResult,
) -> Path:
    """Copy analysis results to per-sample output directory."""
    sample_out = output_dir / sample_name
    sample_out.mkdir(parents=True, exist_ok=True)

    for name, is_dir in [
        ("hprintf_00.log", False),
        ("pt_trace_dump_0", False),
        ("dump", True),
        ("traces", True),
        ("logs", True),
    ]:
        src = workdir / name
        dst = sample_out / name
        if not src.exists():
            continue
        if is_dir:
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)

    result_data = {
        "sample_name": result.sample_name,
        "status": result.status.value,
        "duration_seconds": round(result.duration_seconds, 1),
        "worker_id": result.worker_id,
        "error_message": result.error_message,
        "wte_count": result.wte_count,
        "dump_file_count": result.dump_file_count,
        "timestamp": datetime.now().isoformat(),
    }
    (sample_out / "result.json").write_text(
        json.dumps(result_data, indent=2) + "\n"
    )
    return sample_out


def _safe_validate(workdir: Path) -> tuple[bool, int, Optional[int]]:
    """Validate results, returning defaults on any error."""
    try:
        if workdir.exists():
            return validate_results(workdir)
    except Exception as exc:
        logger.debug("validate_results failed for %s: %s", workdir, exc)
    return False, 0, None


def _cleanup_kafl(workdir: Path, worker: Optional[WorkerInfo] = None) -> None:
    """Kill stray QEMU processes and reap zombies to prevent cascading failures.

    Zombie QEMU processes hold /dev/kvm file descriptors and KVM kernel
    resources.  When enough accumulate, new QEMU instances can't init KVM
    and die with 'Broken pipe' at the Nyx handshake.  This function:
      1. Kills QEMU matching this worker's disk image (scoped)
      2. Kills ALL orphan qemu-system-x86_64 not in a known worker set (global)
      3. Waits for zombie reaping
    """
    # --- Scoped kill: this worker's QEMU ---
    patterns = [f"qemu-system-x86_64.*{re.escape(str(workdir))}"]
    if worker is not None:
        patterns.append(
            f"qemu-system-x86_64.*{re.escape(str(worker.disk_image))}"
        )
    for pattern in patterns:
        try:
            subprocess.run(
                ["pkill", "-TERM", "-f", pattern],
                timeout=10, capture_output=True,
            )
        except Exception as exc:
            logger.debug("pkill TERM failed (non-critical): %s", exc)

    time.sleep(SIGTERM_GRACE)

    for pattern in patterns:
        try:
            subprocess.run(
                ["pkill", "-9", "-f", pattern],
                timeout=10, capture_output=True,
            )
        except Exception as exc:
            logger.debug("pkill KILL failed (non-critical): %s", exc)

    # --- Global zombie sweep: kill ALL kAFL-spawned QEMU ---
    # kAFL QEMUs always have '-fast_vm_reload' in their cmdline.
    # Vagrant/libvirt QEMUs never do.  This is the safest filter.
    try:
        subprocess.run(
            ["pkill", "-9", "-f", "fast_vm_reload"],
            timeout=10, capture_output=True,
        )
        logger.debug("Global pkill -9 -f fast_vm_reload completed")
    except Exception as exc:
        logger.debug("Global zombie sweep failed (non-critical): %s", exc)

    # Wait for kernel to reap killed processes and release KVM resources
    time.sleep(2)

    # ── Aggressive residue cleanup for this workdir ─────────────────
    # When QEMU crashes mid-run it leaves shm segments, stale sockets,
    # and fragmented pages.  Clearing these between samples prevents
    # cascading ToPA / Broken-pipe failures over long batches.
    try:
        # 1) Per-workdir monitor sockets & lock files
        for pat in ("monitor.sock", "*.lock", "*.pid"):
            for p in Path(workdir).rglob(pat):
                try:
                    p.unlink()
                except OSError:
                    pass
    except Exception as exc:
        logger.debug("workdir residue cleanup failed: %s", exc)

    try:
        # 2) Orphan Nyx/kAFL shm segments (best-effort, global)
        for shm in Path("/dev/shm").glob("kafl_*"):
            try:
                shm.unlink()
            except OSError:
                pass
        for shm in Path("/dev/shm").glob("nyx_*"):
            try:
                shm.unlink()
            except OSError:
                pass
    except Exception as exc:
        logger.debug("/dev/shm cleanup failed: %s", exc)

    try:
        # 3) Trigger memory compaction to refresh Order-9 (2MB) pool
        #    used by Intel PT ToPA buffer allocation.
        Path("/proc/sys/vm/compact_memory").write_text("1\n")
    except Exception as exc:
        logger.debug("compact_memory failed: %s", exc)


# -- Single Sample Processing --


def process_sample(
    sample_path: Path,
    worker: WorkerInfo,
    config: BatchConfig,
) -> SampleResult:
    """Process one PE sample on a specific worker.

    Pipeline: provision VM -> run kafl -> validate -> collect results.
    """
    sample_name = sample_path.stem.replace(" ", "_")
    start = time.time()
    workdir = config.workdir_base / sample_name
    result: Optional[SampleResult] = None

    try:
        # Phase 0: Kill any stray QEMU from previous run on this worker
        _cleanup_kafl(workdir, worker)

        # Phase 1: Provision worker VM with this sample
        logger.info("[W%d] Provisioning: %s", worker.worker_id, sample_name)
        provision_sample(worker, sample_path)

        # Phase 2: Run kAFL analysis
        logger.info("[W%d] Analyzing: %s", worker.worker_id, sample_name)
        run_kafl(
            workdir, config.project_dir, worker,
            config.timeout_seconds, config.qemu_memory,
            config.kafl_extra_args,
        )

        # Phase 3: Validate
        success, dump_count, wte_count = validate_results(workdir)
        duration = time.time() - start

        result = SampleResult(
            sample_name=sample_name,
            status=SampleStatus.SUCCESS if success else SampleStatus.ERROR,
            duration_seconds=duration,
            worker_id=worker.worker_id,
            error_message=None if success else "No success marker in hprintf log",
            wte_count=wte_count,
            dump_file_count=dump_count,
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        success, dump_count, wte_count = _safe_validate(workdir)
        result = SampleResult(
            sample_name=sample_name,
            status=SampleStatus.SUCCESS if success else SampleStatus.TIMEOUT,
            duration_seconds=duration,
            worker_id=worker.worker_id,
            error_message=None if success else f"Timed out after {config.timeout_seconds}s",
            wte_count=wte_count,
            dump_file_count=dump_count,
        )

    except Exception as e:
        duration = time.time() - start
        logger.error("[W%d] Error processing %s: %s", worker.worker_id, sample_name, e)
        _, dump_count, wte_count = _safe_validate(workdir)
        result = SampleResult(
            sample_name=sample_name,
            status=SampleStatus.ERROR,
            duration_seconds=duration,
            worker_id=worker.worker_id,
            error_message=str(e),
            wte_count=wte_count,
            dump_file_count=dump_count,
        )

    finally:
        if result is None:
            result = SampleResult(
                sample_name=sample_name,
                status=SampleStatus.ERROR,
                duration_seconds=time.time() - start,
                worker_id=worker.worker_id,
                error_message="Interrupted",
            )
        if workdir.exists():
            collect_results(workdir, config.output_dir, sample_name, result)
        _cleanup_kafl(workdir, worker)
        # Remove workdir after collecting results to avoid duplicate storage
        if workdir.exists():
            try:
                shutil.rmtree(workdir)
                logger.debug("Removed workdir: %s", workdir)
            except OSError as exc:
                logger.debug("Failed to remove workdir %s: %s", workdir, exc)

        # On failure: restore snapshot to reset disk to clean state
        # so the next sample doesn't inherit corrupted VM state
        if result.status != SampleStatus.SUCCESS:
            _recover_worker(worker)

    return result


def _recover_worker(worker: WorkerInfo) -> bool:
    """Restore worker VM to clean snapshot state after a failure.

    Returns True if recovery succeeded.
    """
    logger.info("[W%d] Recovering worker (snapshot restore)...", worker.worker_id)
    _cleanup_kafl(Path("/nonexistent"), worker)
    _force_vm_off(worker)
    try:
        _run_cmd(
            ["vagrant", "snapshot", "restore", "ready_provision"],
            cwd=worker.worker_dir, timeout=120,
            label=f"W{worker.worker_id} recovery restore",
        )
        _halt_worker(worker)
        logger.info("[W%d] Worker recovered", worker.worker_id)
        return True
    except Exception as exc:
        logger.error("[W%d] Worker recovery failed: %s", worker.worker_id, exc)
        return False


# -- Worker Loop & Batch Orchestration --


@dataclass
class BatchProgress:
    """Thread-safe progress counter for batch processing."""

    done: int = 0
    success: int = 0
    fail: int = 0
    lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.lock = threading.Lock()

    def record(self, status: SampleStatus) -> tuple[int, int, int]:
        """Record a result and return (done, success, fail) snapshot."""
        with self.lock:
            self.done += 1
            if status == SampleStatus.SUCCESS:
                self.success += 1
            else:
                self.fail += 1
            return self.done, self.success, self.fail


def worker_loop(
    worker: WorkerInfo,
    sample_queue: queue.Queue,
    config: BatchConfig,
    results: list[SampleResult],
    results_lock: threading.Lock,
    total: int,
    progress: BatchProgress,
) -> None:
    """Per-worker thread: dequeue and process samples sequentially."""
    consecutive_failures = 0
    recovery_attempted = False

    while not _shutdown.is_set():
        try:
            sample = sample_queue.get_nowait()
        except queue.Empty:
            break

        try:
            result = process_sample(sample, worker, config)

            if result.status == SampleStatus.SUCCESS:
                consecutive_failures = 0
                recovery_attempted = False
            else:
                consecutive_failures += 1

            with results_lock:
                results.append(result)

            done, ok, fail = progress.record(result.status)

            icon = {
                SampleStatus.SUCCESS: "OK",
                SampleStatus.TIMEOUT: "TIMEOUT",
                SampleStatus.ERROR: "FAIL",
            }.get(result.status, "?")

            logger.info(
                "[%d/%d] W%d %s -> %s (%.1fs, WtE=%s, dumps=%d) [ok=%d fail=%d]",
                done, total, worker.worker_id, result.sample_name, icon,
                result.duration_seconds,
                result.wte_count if result.wte_count is not None else "?",
                result.dump_file_count,
                ok, fail,
            )

            # Circuit breaker: on consecutive failures, attempt recovery once
            # before giving up
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                if not recovery_attempted:
                    logger.warning(
                        "[W%d] %d consecutive failures, attempting worker recovery...",
                        worker.worker_id, consecutive_failures,
                    )
                    if _recover_worker(worker):
                        consecutive_failures = 0
                        recovery_attempted = True
                        continue
                logger.error(
                    "[W%d] %d consecutive failures (recovery %s), stopping worker",
                    worker.worker_id, consecutive_failures,
                    "already tried" if recovery_attempted else "failed",
                )
                break

        except Exception as e:
            logger.error(
                "[W%d] Unexpected error: %s", worker.worker_id, e, exc_info=True
            )
            consecutive_failures += 1
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                if not recovery_attempted:
                    logger.warning(
                        "[W%d] Attempting worker recovery...",
                        worker.worker_id,
                    )
                    if _recover_worker(worker):
                        consecutive_failures = 0
                        recovery_attempted = True
                        continue
                logger.error(
                    "[W%d] Stopping after %d failures",
                    worker.worker_id, consecutive_failures,
                )
                break

        finally:
            sample_queue.task_done()


def run_batch(config: BatchConfig, workers: list[WorkerInfo]) -> list[SampleResult]:
    """Run batch analysis with independent worker pool."""
    # Clear shutdown flag from any previous run
    _shutdown.clear()

    samples = discover_samples(config.samples_dir)
    if not samples:
        logger.error("No PE files found in %s", config.samples_dir)
        return []

    logger.info("Found %d samples", len(samples))

    # Filter already processed
    if not config.force:
        pending = [s for s in samples if not is_already_processed(s, config.output_dir)]
        skipped = len(samples) - len(pending)
        if skipped:
            logger.info(
                "Skipping %d already-processed samples (use --force to re-run)",
                skipped,
            )
    else:
        pending = samples

    results: list[SampleResult] = []
    results_lock = threading.Lock()
    progress = BatchProgress()

    # Add skipped results
    for s in samples:
        if s not in pending:
            results.append(SampleResult(
                sample_name=s.stem,
                status=SampleStatus.SKIPPED,
                duration_seconds=0.0,
            ))

    total = len(pending)
    if total == 0:
        logger.info("Nothing to process")
        return results

    # Create sample queue
    sample_q: queue.Queue = queue.Queue()
    for s in pending:
        sample_q.put(s)

    num_workers = min(len(workers), total)
    active_workers = workers[:num_workers]

    logger.info(
        "Processing %d samples with %d independent workers (fully parallel)",
        total, num_workers,
    )

    # Launch worker threads with staggered start to avoid
    # concurrent snapshot restore / KVM init contention
    WORKER_START_DELAY = 5  # seconds between each worker launch
    threads = []
    for i, worker in enumerate(active_workers):
        t = threading.Thread(
            target=worker_loop,
            args=(worker, sample_q, config, results, results_lock, total, progress),
            name=f"W{worker.worker_id}",
            daemon=True,
        )
        threads.append(t)
        t.start()
        if i < len(active_workers) - 1:
            logger.info("Staggering worker start (%ds delay)...", WORKER_START_DELAY)
            time.sleep(WORKER_START_DELAY)

    # Wait for completion
    for t in threads:
        t.join()

    # Drain unprocessed samples (all workers hit circuit breaker or shutdown)
    while True:
        try:
            sample = sample_q.get_nowait()
            results.append(SampleResult(
                sample_name=sample.stem,
                status=SampleStatus.ERROR,
                duration_seconds=0.0,
                error_message="Worker pool exhausted before sample was processed",
            ))
        except queue.Empty:
            break

    unprocessed = sum(
        1 for r in results
        if r.error_message == "Worker pool exhausted before sample was processed"
    )
    if unprocessed > 0:
        logger.error("%d samples unprocessed (all workers stopped)", unprocessed)

    return results


# -- Reporting --


def generate_report(results: list[SampleResult], output_dir: Path) -> None:
    """Write summary report to console and file."""
    if not results:
        return

    succeeded = [r for r in results if r.status == SampleStatus.SUCCESS]
    failed = [r for r in results if r.status == SampleStatus.ERROR]
    timed_out = [r for r in results if r.status == SampleStatus.TIMEOUT]
    skipped = [r for r in results if r.status == SampleStatus.SKIPPED]

    logger.info("")
    logger.info("=" * 60)
    logger.info("  BATCH ANALYSIS REPORT")
    logger.info("=" * 60)
    logger.info("  Total:     %d", len(results))
    logger.info("  Succeeded: %d", len(succeeded))
    logger.info("  Failed:    %d", len(failed))
    logger.info("  Timed out: %d", len(timed_out))
    logger.info("  Skipped:   %d", len(skipped))

    if succeeded:
        avg = sum(r.duration_seconds for r in succeeded) / len(succeeded)
        total_dumps = sum(r.dump_file_count for r in succeeded)
        logger.info("  Avg time:  %.1fs (successful samples)", avg)
        logger.info("  Total dumps: %d", total_dumps)

    # Show details for active results (limit output for large batches)
    active = [r for r in results if r.status != SampleStatus.SKIPPED]
    show_limit = 200
    if active:
        logger.info("")
        logger.info(
            "%-40s %-10s %5s %8s %6s %6s",
            "Sample", "Status", "W#", "Time", "WtE", "Dumps",
        )
        logger.info("-" * 80)
        for r in active[:show_limit]:
            logger.info(
                "%-40s %-10s %5d %7.1fs %6s %6d",
                r.sample_name[:40], r.status.value, r.worker_id,
                r.duration_seconds,
                str(r.wte_count) if r.wte_count is not None else "-",
                r.dump_file_count,
            )
        if len(active) > show_limit:
            logger.info("  ... and %d more (see batch_report.json)", len(active) - show_limit)

    # Write JSON report (summary + failures only for large batches)
    failures_list = [
        {
            "sample_name": r.sample_name,
            "status": r.status.value,
            "duration_seconds": round(r.duration_seconds, 1),
            "worker_id": r.worker_id,
            "error_message": r.error_message,
            "wte_count": r.wte_count,
            "dump_file_count": r.dump_file_count,
        }
        for r in results
        if r.status in (SampleStatus.ERROR, SampleStatus.TIMEOUT)
    ]

    report_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": len(results),
            "succeeded": len(succeeded),
            "failed": len(failed),
            "timed_out": len(timed_out),
            "skipped": len(skipped),
        },
        "failures": failures_list,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "batch_report.json"
    report_path.write_text(json.dumps(report_data, indent=2) + "\n")
    logger.info("Report: %s", report_path)


# -- Utility --


def _run_cmd(
    cmd: list[str],
    cwd: Path,
    timeout: int,
    label: str,
    env: Optional[dict] = None,
) -> subprocess.CompletedProcess:
    """Run a subprocess with timeout and logging."""
    logger.debug("Running: %s (cwd=%s)", " ".join(cmd), cwd)
    try:
        result = subprocess.run(
            cmd, cwd=cwd, timeout=timeout,
            capture_output=True, text=True,
            env=env,
        )
        if result.returncode != 0:
            logger.error(
                "%s failed (rc=%d):\nstdout: %s\nstderr: %s",
                label, result.returncode,
                result.stdout[-500:] if result.stdout else "",
                result.stderr[-500:] if result.stderr else "",
            )
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr,
            )
        return result
    except subprocess.TimeoutExpired:
        logger.error("%s timed out after %ds", label, timeout)
        raise


def resolve_qemu_memory(project_dir: Path) -> int:
    """Read qemu_memory from kafl.yaml (default: 4096)."""
    kafl_yaml = project_dir / "kafl.yaml"
    if not kafl_yaml.exists():
        return 4096

    for line in kafl_yaml.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("qemu_memory:"):
            try:
                return int(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass
    return 4096


# -- CLI Subcommands --


def cmd_setup(args: argparse.Namespace) -> None:
    project_dir = Path(__file__).resolve().parent
    workers = setup_workers(project_dir, args.workers)
    logger.info("")
    logger.info("Setup complete: %d workers ready", len(workers))
    for w in workers:
        logger.info(
            "  W%d: %s (image: %s)", w.worker_id, w.vm_name, w.disk_image
        )


def cmd_run(args: argparse.Namespace) -> None:
    project_dir = Path(__file__).resolve().parent

    workers = load_workers(project_dir)
    if not workers:
        logger.error("No workers found. Run 'setup' first.")
        sys.exit(1)

    qemu_memory = resolve_qemu_memory(project_dir)

    config = BatchConfig(
        samples_dir=args.samples_dir.resolve(),
        output_dir=args.output_dir.resolve(),
        workdir_base=args.workdir.resolve(),
        timeout_seconds=args.timeout,
        project_dir=project_dir,
        force=args.force,
        qemu_memory=qemu_memory,
        kafl_extra_args=tuple(args.kafl_args) if args.kafl_args else (),
    )

    config.output_dir.mkdir(parents=True, exist_ok=True)

    # File logging
    file_handler = logging.FileHandler(config.output_dir / "batch_analyze.log")
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S",
    ))
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    logger.info("Batch run starting")
    logger.info("  Samples:  %s", config.samples_dir)
    logger.info("  Output:   %s", config.output_dir)
    logger.info("  Workdir:  %s", config.workdir_base)
    logger.info("  Workers:  %d", len(workers))
    logger.info("  Timeout:  %ds", config.timeout_seconds)
    logger.info("  Memory:   %d MB", config.qemu_memory)

    # Install signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        results = run_batch(config, workers)
    finally:
        # Halt all workers on exit
        for w in workers:
            try:
                _halt_worker(w)
            except Exception:
                pass

    generate_report(results, config.output_dir)

    failed = sum(
        1 for r in results
        if r.status in (SampleStatus.ERROR, SampleStatus.TIMEOUT)
    )
    sys.exit(1 if failed > 0 else 0)


def cmd_teardown(_args: argparse.Namespace) -> None:
    project_dir = Path(__file__).resolve().parent
    teardown_workers(project_dir)


def cmd_status(_args: argparse.Namespace) -> None:
    project_dir = Path(__file__).resolve().parent
    try:
        workers = load_workers(project_dir)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)

    logger.info("Workers: %d", len(workers))
    for w in workers:
        try:
            result = subprocess.run(
                ["vagrant", "status", "--machine-readable"],
                cwd=w.worker_dir, capture_output=True, text=True, timeout=30,
            )
            state = "unknown"
            for line in result.stdout.splitlines():
                parts = line.split(",")
                if len(parts) >= 4 and parts[2] == "state":
                    state = parts[3]

            image_ok = w.disk_image.exists()
            image_gb = w.disk_image.stat().st_size / (1024**3) if image_ok else 0

            logger.info(
                "  W%d: %-12s image=%s (%.1f GB)",
                w.worker_id, state,
                "OK" if image_ok else "MISSING",
                image_gb,
            )
        except Exception as e:
            logger.info("  W%d: ERROR (%s)", w.worker_id, e)


# -- Entry Point --


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch PE unpacking analysis with independent worker VMs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s setup -n 4              # Create 4 worker VMs (one-time)
  %(prog)s run ./samples -t 600    # Analyze all samples
  %(prog)s status                  # Check worker health
  %(prog)s teardown                # Destroy all workers
""",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    p_setup = sub.add_parser("setup", help="Create independent worker VMs")
    p_setup.add_argument(
        "-n", "--workers", type=int, default=4,
        help="Number of workers to create (default: 4)",
    )
    p_setup.set_defaults(func=cmd_setup)

    # run
    p_run = sub.add_parser("run", help="Run batch analysis")
    p_run.add_argument("samples_dir", type=Path,
                       help="Directory containing packed PE samples")
    p_run.add_argument("-o", "--output-dir", type=Path,
                       default=Path("./batch_results"),
                       help="Output directory (default: ./batch_results)")
    p_run.add_argument("-w", "--workdir", type=Path,
                       default=Path("/tmp/kafl_batch"),
                       help="kAFL working directory base (default: /tmp/kafl_batch)")
    p_run.add_argument("-t", "--timeout", type=int, default=600,
                       help="Per-sample timeout in seconds (default: 600)")
    p_run.add_argument("--force", action="store_true",
                       help="Re-process already-completed samples")
    p_run.add_argument("--kafl-args", nargs="*",
                       help="Extra arguments for kafl fuzz")
    p_run.set_defaults(func=cmd_run)

    # teardown
    p_teardown = sub.add_parser("teardown", help="Destroy all worker VMs")
    p_teardown.set_defaults(func=cmd_teardown)

    # status
    p_status = sub.add_parser("status", help="Show worker VM status")
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-7s] %(message)s",
        datefmt="%H:%M:%S",
    )

    args.func(args)


if __name__ == "__main__":
    main()
