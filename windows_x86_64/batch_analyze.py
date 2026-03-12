#!/usr/bin/env python3
"""
Batch PE Unpacking Analyzer for kAFL.

Automates parallel kAFL unpacking analysis across multiple packed PE samples.
Creates standalone qcow2 copies of the provisioned disk image so multiple
VMs can run simultaneously without file locking conflicts.

Usage:
    python3 batch_analyze.py /path/to/samples_dir -o ./results -t 600 -n 2
"""

import argparse
import concurrent.futures
import enum
import json
import logging
import os
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

PE_EXTENSIONS = {".exe", ".dll", ".scr", ".sys"}
PROVISION_TIMEOUT_SECONDS = 300
VAGRANT_HALT_TIMEOUT_SECONDS = 120
CLEANUP_HALT_TIMEOUT_SECONDS = 60
SIGTERM_GRACE_SECONDS = 3
HPRINTF_SUCCESS_MARKERS = [
    "WtE single execution complete",
    "Unpacking complete",
    "Single execution complete",
]


class SampleStatus(enum.Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


QEMU_IMG_CONVERT_TIMEOUT_SECONDS = 600


@dataclass(frozen=True)
class BatchConfig:
    samples_dir: Path
    output_dir: Path
    workdir_base: Path
    image_dir: Path
    timeout_seconds: int
    project_dir: Path
    force: bool
    num_workers: int
    base_image: Path
    qemu_memory: int = 4096
    kafl_extra_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class SampleResult:
    sample_name: str
    status: SampleStatus
    duration_seconds: float
    error_message: Optional[str] = None
    wte_count: Optional[int] = None
    dump_file_count: int = 0


# -- Discovery & Resume --

def discover_samples(samples_dir: Path) -> list[Path]:
    """Find all PE files in the samples directory, sorted alphabetically."""
    resolved_dir = samples_dir.resolve()
    if not resolved_dir.is_dir():
        raise FileNotFoundError(f"Samples directory not found: {resolved_dir}")

    samples = []
    for entry in sorted(resolved_dir.iterdir()):
        if entry.is_symlink():
            real = entry.resolve()
            if not real.is_relative_to(resolved_dir):
                logger.warning("Skipping symlink escaping samples dir: %s", entry.name)
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


# -- Disk Image Management --

@dataclass(frozen=True)
class KaflYamlConfig:
    base_image: Path
    qemu_memory: int


def resolve_kafl_yaml(project_dir: Path) -> KaflYamlConfig:
    """Read kafl.yaml to find the base disk image path and qemu_memory."""
    kafl_yaml = project_dir / "kafl.yaml"
    if not kafl_yaml.exists():
        raise FileNotFoundError(f"kafl.yaml not found in {project_dir}")

    content = kafl_yaml.read_text()
    base_image: Optional[Path] = None
    qemu_memory = 256  # kafl default

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("qemu_image:"):
            value = stripped.split(":", 1)[1].strip().strip("'\"")
            if "@format" in value:
                value = value.replace("@format ", "")
                value = value.replace("{env[HOME]}", os.environ["HOME"])
            path = Path(value)
            if not path.exists():
                raise FileNotFoundError(f"Base image not found: {path}")
            base_image = path.resolve()
        elif stripped.startswith("qemu_memory:"):
            try:
                qemu_memory = int(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass

    if base_image is None:
        raise ValueError("qemu_image not found in kafl.yaml")

    return KaflYamlConfig(base_image=base_image, qemu_memory=qemu_memory)


def _detect_image_format(image_path: Path) -> str:
    """Detect the actual format of a disk image using qemu-img info."""
    try:
        result = subprocess.run(
            ["qemu-img", "info", "--output=json", str(image_path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            info = json.loads(result.stdout)
            fmt = info.get("format", "raw")
            logger.debug("Detected image format: %s -> %s", image_path.name, fmt)
            return fmt
    except Exception as e:
        logger.warning("Failed to detect image format: %s", e)
    return "raw"


def create_standalone_image(base_image: Path, output_path: Path) -> Path:
    """Create a standalone copy of the base image.

    Uses the same format as the base image to avoid conversion issues.
    The copy has NO backing file reference, so vagrant can freely modify
    the base for the next sample while QEMU uses this copy for analysis.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base_format = _detect_image_format(base_image)
    # Use the same output format to avoid conversion artifacts
    out_format = base_format

    start = time.time()
    cmd = [
        "qemu-img", "convert",
        "-f", base_format,
        "-O", out_format,
        str(base_image),
        str(output_path),
    ]
    logger.info("Converting: %s (%s) -> %s (%s)", base_image.name, base_format, output_path.name, out_format)
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        timeout=QEMU_IMG_CONVERT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(f"qemu-img convert failed: {result.stderr}")

    elapsed = time.time() - start
    size_mb = output_path.stat().st_size / (1024 * 1024)
    logger.info(
        "Created standalone image: %s (%.0f MB, %.1fs)",
        output_path.name, size_mb, elapsed,
    )
    return output_path


def remove_worker_image(image_path: Path, *, keep_on_failure: bool = False) -> None:
    """Remove a standalone qcow2 worker image.

    Args:
        image_path: Path to the qcow2 image file.
        keep_on_failure: If True, skip deletion (keep image for debugging).
    """
    if keep_on_failure:
        logger.info("Keeping worker image for debugging: %s", image_path)
        return
    try:
        if image_path.exists():
            size_mb = image_path.stat().st_size / (1024 * 1024)
            image_path.unlink()
            logger.debug("Removed worker image: %s (%.0f MB freed)", image_path.name, size_mb)
    except OSError as e:
        logger.debug("Failed to remove image %s: %s", image_path, e)


# -- Environment Preflight Check --

def preflight_check(project_dir: Path) -> None:
    """Verify environment is clean before starting batch analysis.

    Checks for:
      1. Stray QEMU processes (from previous kafl runs)
      2. Vagrant/libvirt VM in unexpected state
      3. Snapshot 'ready_provision' availability

    If issues are found, attempts automatic recovery:
      kill QEMU → vagrant destroy → vagrant up → snapshot save
    """
    logger.info("Running preflight checks...")

    # 1. Kill any stray QEMU processes
    stray_qemu = _find_stray_qemu()
    if stray_qemu:
        logger.warning("Found %d stray QEMU process(es), killing...", len(stray_qemu))
        _kill_all_qemu()
        time.sleep(2)

    # 2. Check vagrant/libvirt state
    if not _is_vagrant_healthy(project_dir):
        logger.warning("Vagrant VM is in an unhealthy state, rebuilding...")
        _rebuild_vagrant(project_dir)
        return

    # 3. Verify snapshot exists and is restorable
    if not _test_snapshot_restore(project_dir):
        logger.warning("Snapshot 'ready_provision' unusable, rebuilding...")
        _rebuild_vagrant(project_dir)
        return

    logger.info("Preflight checks passed")


def _find_stray_qemu() -> list[str]:
    """Find stray QEMU processes."""
    try:
        result = subprocess.run(
            ["pgrep", "-af", "qemu-system-x86_64"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()
    except Exception:
        pass
    return []


def _kill_all_qemu() -> None:
    """Kill all QEMU processes."""
    try:
        subprocess.run(["pkill", "-9", "qemu-system-x86_64"],
                        capture_output=True, timeout=10)
    except Exception as e:
        logger.debug("pkill qemu failed: %s", e)


def _is_vagrant_healthy(project_dir: Path) -> bool:
    """Check if vagrant VM is in a usable state."""
    try:
        result = subprocess.run(
            ["vagrant", "status", "--machine-readable"],
            cwd=project_dir, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return False
        # Check for known bad states
        output = result.stdout
        # machine-readable format: timestamp,target,type,data
        for line in output.splitlines():
            parts = line.split(",")
            if len(parts) >= 4 and parts[2] == "state":
                state = parts[3]
                logger.info("Vagrant VM state: %s", state)
                # Valid states: shutoff, running, not_created
                if state in ("shutoff", "not_created"):
                    return True
                if state == "running":
                    # Running is OK, vagrant halt will handle it
                    return True
                # paused, crashed, etc. → unhealthy
                logger.warning("Vagrant VM in unexpected state: %s", state)
                return False
        return True
    except Exception as e:
        logger.warning("Vagrant status check failed: %s", e)
        return False


def _test_snapshot_restore(project_dir: Path) -> bool:
    """Test if 'ready_provision' snapshot can be restored."""
    try:
        # List snapshots to check if it exists
        result = subprocess.run(
            ["vagrant", "snapshot", "list"],
            cwd=project_dir, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return False
        if "ready_provision" not in result.stdout:
            logger.warning("Snapshot 'ready_provision' not found")
            return False

        # Try actual restore
        result = subprocess.run(
            ["vagrant", "snapshot", "restore", "ready_provision"],
            cwd=project_dir, capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            logger.warning("Snapshot restore failed: %s", result.stderr[-300:])
            return False

        # Halt after successful test restore
        subprocess.run(
            ["vagrant", "halt", "-f"],
            cwd=project_dir, capture_output=True, timeout=60,
        )
        return True
    except Exception as e:
        logger.warning("Snapshot test failed: %s", e)
        return False


def _rebuild_vagrant(project_dir: Path) -> None:
    """Full rebuild: destroy → up → snapshot save."""
    logger.info("Rebuilding vagrant VM (this may take a few minutes)...")

    steps = [
        (["vagrant", "destroy", "-f"], "vagrant destroy", 120),
        (["vagrant", "up", "--no-provision"], "vagrant up", 600),
        (["vagrant", "snapshot", "save", "ready_provision"], "snapshot save", 120),
    ]

    for cmd, label, timeout in steps:
        logger.info("  Running: %s", label)
        try:
            result = subprocess.run(
                cmd, cwd=project_dir, capture_output=True, text=True,
                timeout=timeout,
            )
            if result.returncode != 0:
                logger.error(
                    "%s failed (rc=%d): %s",
                    label, result.returncode,
                    result.stderr[-500:] if result.stderr else "",
                )
                raise RuntimeError(f"Vagrant rebuild failed at: {label}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Vagrant rebuild timed out at: {label}")

    logger.info("Vagrant VM rebuilt successfully")


# -- VM Provisioning --

def provision_vm(sample_path: Path, project_dir: Path) -> None:
    """Copy sample to bin/ and provision the VM via Makefile."""
    target_path = project_dir / "bin" / "userspace" / "target_packed.exe"
    target_path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy2(sample_path, target_path)
    logger.info("Copied %s -> target_packed.exe", sample_path.name)

    _run_cmd(
        ["make", "provision_unpack"],
        cwd=project_dir,
        timeout=PROVISION_TIMEOUT_SECONDS,
        label="make provision_unpack",
    )

    # Clean shutdown (not -f) is required: forced poweroff leaves qcow2
    # in a dirty state that prevents QEMU-Nyx from booting successfully.
    _run_cmd(
        ["vagrant", "halt"],
        cwd=project_dir,
        timeout=VAGRANT_HALT_TIMEOUT_SECONDS,
        label="vagrant halt",
    )


def _run_cmd(
    cmd: list[str],
    cwd: Path,
    timeout: int,
    label: str,
) -> subprocess.CompletedProcess:
    """Run a subprocess with timeout and logging."""
    logger.debug("Running: %s (timeout=%ds)", " ".join(cmd), timeout)
    try:
        result = subprocess.run(
            cmd, cwd=cwd, timeout=timeout,
            capture_output=True, text=True,
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


# -- kAFL Execution --

def run_kafl(
    workdir: Path,
    project_dir: Path,
    timeout: int,
    image_path: Optional[Path] = None,
    qemu_memory: Optional[int] = None,
    extra_args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess:
    """Run kafl fuzz and wait for completion or timeout."""
    cmd = [
        "kafl", "fuzz",
        "--purge",
        "-w", str(workdir),
        "--log-hprintf",
        "-p", "1",
    ]
    if image_path is not None:
        cmd.extend(["--image", str(image_path)])
    if qemu_memory is not None:
        cmd.extend(["--memory", str(qemu_memory)])
    cmd.extend(extra_args)

    logger.info("Running: %s", " ".join(cmd))

    proc = subprocess.Popen(
        cmd, cwd=project_dir,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("kAFL timed out after %ds, killing process tree...", timeout)
        _kill_process_tree(proc)
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        raise subprocess.TimeoutExpired(cmd, timeout, stdout, stderr)

    logger.debug("kAFL exited with rc=%d", proc.returncode)
    if proc.returncode != 0:
        logger.error("kAFL failed (rc=%d)", proc.returncode)
        if stdout and stdout.strip():
            for line in stdout.strip().splitlines()[-20:]:
                logger.error("  stdout: %s", line)
        if stderr and stderr.strip():
            for line in stderr.strip().splitlines()[-20:]:
                logger.error("  stderr: %s", line)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Kill the process and its entire process group."""
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        try:
            proc.wait(timeout=SIGTERM_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


# -- Result Validation & Collection --

def validate_results(workdir: Path) -> tuple[bool, int, Optional[int]]:
    """Check if analysis completed successfully by parsing hprintf log."""
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

    collect_items = [
        ("hprintf_00.log", False),
        ("pt_trace_dump_0", False),
        ("dump", True),
        ("traces", True),
        ("logs", True),
    ]

    for name, is_dir in collect_items:
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
        "error_message": result.error_message,
        "wte_count": result.wte_count,
        "dump_file_count": result.dump_file_count,
        "timestamp": datetime.now().isoformat(),
    }
    (sample_out / "result.json").write_text(
        json.dumps(result_data, indent=2) + "\n"
    )

    logger.info("Results saved to %s", sample_out)
    return sample_out


# -- Single Sample Processing --

# Lock to serialize vagrant provisioning (single disk image + single vagrant VM)
_provision_lock = threading.Lock()

# Counter for progress logging
_progress_counter = {"done": 0}
_progress_lock = threading.Lock()


def process_sample(
    sample_path: Path,
    config: BatchConfig,
    total: int,
) -> SampleResult:
    """Process a single packed PE sample end-to-end.

    Pipeline:
      1. [LOCKED] Provision VM with this sample's PE binary
      2. [LOCKED] Create qcow2 overlay of the provisioned disk image
      3. [UNLOCKED] Run kAFL with the overlay (parallel with other workers)
      4. Collect results, cleanup overlay
    """
    sample_name = sample_path.stem
    start_time = time.time()
    result: Optional[SampleResult] = None
    worker_workdir = config.workdir_base / sample_name
    image_path = config.image_dir / f"{sample_name}.qcow2"

    try:
        # Phase 1+2: Provision + create standalone image (serialized)
        # Lock ensures only one thread uses vagrant at a time, and the
        # base image is free (no QEMU has it open as a backing file).
        with _provision_lock:
            logger.info("[PROVISION] %s: provisioning VM...", sample_name)
            provision_vm(sample_path, config.project_dir)

            logger.info("[PROVISION] %s: creating standalone disk image...", sample_name)
            create_standalone_image(config.base_image, image_path)

        # Phase 3: Run kAFL analysis (parallel)
        # The standalone qcow2 has no backing file reference, so it
        # doesn't lock the base image — vagrant can provision the next sample.
        if not image_path.exists():
            raise FileNotFoundError(f"Standalone image missing before kafl: {image_path}")
        logger.info(
            "[ANALYZE] %s: starting kAFL (image: %s, %.0f MB)...",
            sample_name, image_path.name,
            image_path.stat().st_size / (1024 * 1024),
        )
        run_kafl(
            worker_workdir,
            config.project_dir,
            config.timeout_seconds,
            image_path=image_path,
            qemu_memory=config.qemu_memory,
            extra_args=config.kafl_extra_args,
        )

        # Phase 4: Validate
        success, dump_count, wte_count = validate_results(worker_workdir)
        duration = time.time() - start_time

        status = SampleStatus.SUCCESS if success else SampleStatus.ERROR
        error_msg = None if success else "No success marker in hprintf log"

        result = SampleResult(
            sample_name=sample_name,
            status=status,
            duration_seconds=duration,
            error_message=error_msg,
            wte_count=wte_count,
            dump_file_count=dump_count,
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        _, dump_count, wte_count = _safe_validate(worker_workdir)
        result = SampleResult(
            sample_name=sample_name,
            status=SampleStatus.TIMEOUT,
            duration_seconds=duration,
            error_message=f"Timed out after {config.timeout_seconds}s",
            wte_count=wte_count,
            dump_file_count=dump_count,
        )

    except Exception as e:
        duration = time.time() - start_time
        logger.error("[ERROR] %s: %s", sample_name, e)
        _, dump_count, wte_count = _safe_validate(worker_workdir)
        result = SampleResult(
            sample_name=sample_name,
            status=SampleStatus.ERROR,
            duration_seconds=duration,
            error_message=str(e),
            wte_count=wte_count,
            dump_file_count=dump_count,
        )

    finally:
        if result is None:
            result = SampleResult(
                sample_name=sample_name,
                status=SampleStatus.ERROR,
                duration_seconds=time.time() - start_time,
                error_message="Interrupted",
            )
        if worker_workdir.exists():
            collect_results(worker_workdir, config.output_dir, sample_name, result)
        is_failure = result is not None and result.status != SampleStatus.SUCCESS
        remove_worker_image(image_path, keep_on_failure=is_failure)
        _cleanup_kafl(worker_workdir)

        with _progress_lock:
            _progress_counter["done"] += 1
            done = _progress_counter["done"]

        status_icon = {
            SampleStatus.SUCCESS: "OK",
            SampleStatus.TIMEOUT: "TIMEOUT",
            SampleStatus.ERROR: "FAIL",
        }.get(result.status, "?")

        logger.info(
            "[%d/%d] %s -> %s (%.1fs, WtE=%s, dumps=%d)",
            done, total, sample_name, status_icon,
            result.duration_seconds,
            result.wte_count if result.wte_count is not None else "?",
            result.dump_file_count,
        )

    return result


def _safe_validate(workdir: Path) -> tuple[bool, int, Optional[int]]:
    """Validate results, returning defaults on any error."""
    try:
        if workdir.exists():
            return validate_results(workdir)
    except Exception:
        logger.debug("validate_results failed for %s", workdir, exc_info=True)
    return False, 0, None


def _cleanup_kafl(workdir: Path) -> None:
    """Kill stray QEMU processes scoped to a specific workdir."""
    try:
        pattern = f"qemu-system-x86_64.*{re.escape(str(workdir))}"
        subprocess.run(
            ["pkill", "-f", pattern],
            timeout=10, capture_output=True,
        )
    except Exception as e:
        logger.debug("pkill failed (non-critical): %s", e)


def cleanup_all(project_dir: Path) -> None:
    """Force-halt vagrant VM (called once at the end)."""
    try:
        subprocess.run(
            ["vagrant", "halt", "-f"],
            cwd=project_dir,
            timeout=CLEANUP_HALT_TIMEOUT_SECONDS,
            capture_output=True,
        )
    except Exception as e:
        logger.debug("vagrant halt failed (non-critical): %s", e)


# -- Batch Orchestration --

def run_batch(config: BatchConfig) -> list[SampleResult]:
    """Run batch analysis across all samples with parallel workers."""
    samples = discover_samples(config.samples_dir)
    if not samples:
        logger.error("No PE files found in %s", config.samples_dir)
        return []

    logger.info("Found %d samples in %s", len(samples), config.samples_dir)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    # Filter already-processed samples
    if not config.force:
        pending = [s for s in samples if not is_already_processed(s, config.output_dir)]
        skipped_count = len(samples) - len(pending)
        if skipped_count > 0:
            logger.info(
                "Skipping %d already-processed samples (use --force to re-run)",
                skipped_count,
            )
    else:
        pending = samples

    results: list[SampleResult] = []

    for s in samples:
        if s not in pending:
            results.append(SampleResult(
                sample_name=s.stem,
                status=SampleStatus.SKIPPED,
                duration_seconds=0.0,
            ))

    total = len(pending)
    if total == 0:
        logger.info("Nothing to process.")
        return results

    # Reset progress counter
    _progress_counter["done"] = 0

    num_workers = min(config.num_workers, total)
    logger.info(
        "Processing %d samples with %d parallel worker(s)",
        total, num_workers,
    )
    logger.info(
        "Pipeline: provision is serialized, analysis runs in parallel"
    )

    if num_workers == 1:
        # Sequential mode — simpler, no thread pool overhead
        for sample in pending:
            result = process_sample(sample, config, total)
            results.append(result)
    else:
        # Parallel mode — provision serialized via lock, analysis in parallel
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=num_workers,
            thread_name_prefix="worker",
        ) as executor:
            futures = {
                executor.submit(process_sample, sample, config, total): sample
                for sample in pending
            }
            for future in concurrent.futures.as_completed(futures):
                sample = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    logger.error("Unexpected error processing %s: %s", sample.name, e)
                    result = SampleResult(
                        sample_name=sample.stem,
                        status=SampleStatus.ERROR,
                        duration_seconds=0.0,
                        error_message=f"Thread error: {e}",
                    )
                results.append(result)

    return results


# -- Reporting --

def generate_report(results: list[SampleResult], output_dir: Path) -> None:
    """Write summary report to console and files."""
    if not results:
        logger.info("No results to report.")
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
    logger.info("")

    logger.info("%-40s %-10s %8s %6s %6s", "Sample", "Status", "Time(s)", "WtE", "Dumps")
    logger.info("-" * 74)
    for r in results:
        if r.status == SampleStatus.SKIPPED:
            continue
        logger.info(
            "%-40s %-10s %8.1f %6s %6d",
            r.sample_name[:40],
            r.status.value,
            r.duration_seconds,
            str(r.wte_count) if r.wte_count is not None else "-",
            r.dump_file_count,
        )

    report_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": len(results),
            "succeeded": len(succeeded),
            "failed": len(failed),
            "timed_out": len(timed_out),
            "skipped": len(skipped),
        },
        "results": [
            {
                "sample_name": r.sample_name,
                "status": r.status.value,
                "duration_seconds": round(r.duration_seconds, 1),
                "error_message": r.error_message,
                "wte_count": r.wte_count,
                "dump_file_count": r.dump_file_count,
            }
            for r in results
        ],
    }

    report_path = output_dir / "batch_report.json"
    report_path.write_text(json.dumps(report_data, indent=2) + "\n")
    logger.info("Report written to %s", report_path)


# -- CLI --

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch PE unpacking analysis using kAFL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/packed_samples
  %(prog)s /path/to/packed_samples -n 2 -o ./results -t 600
  %(prog)s /path/to/packed_samples -n 4 --force
        """,
    )
    parser.add_argument("samples_dir", type=Path,
                        help="Directory containing packed PE samples")
    parser.add_argument("-n", "--workers", type=int, default=2,
                        help="Number of parallel VMs/workers (default: 2)")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("./batch_results"),
                        help="Output directory for results (default: ./batch_results)")
    parser.add_argument("-w", "--workdir", type=Path, default=Path("/dev/shm/kafl_batch"),
                        help="Base kAFL working directory (default: /dev/shm/kafl_batch)")
    parser.add_argument("--image-dir", type=Path, default=None,
                        help="Directory for standalone disk images (default: next to base image)")
    parser.add_argument("-t", "--timeout", type=int, default=600,
                        help="Per-sample timeout in seconds (default: 600)")
    parser.add_argument("--force", action="store_true",
                        help="Re-process already-completed samples")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_format = "%(asctime)s [%(levelname)-7s] %(message)s"
    logging.basicConfig(level=log_level, format=log_format, datefmt="%H:%M:%S")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(args.output_dir / "batch_analyze.log")
    file_handler.setFormatter(logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S"))
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    project_dir = Path(__file__).resolve().parent

    # Resolve base disk image and qemu_memory from kafl.yaml
    try:
        kafl_config = resolve_kafl_yaml(project_dir)
    except (FileNotFoundError, ValueError) as e:
        logger.error("Failed to resolve kafl.yaml: %s", e)
        sys.exit(1)

    base_image = kafl_config.base_image
    qemu_memory = kafl_config.qemu_memory

    # Default image_dir: same directory as the base image
    image_dir = args.image_dir
    if image_dir is None:
        image_dir = base_image.parent / "batch_images"
    image_dir = image_dir.resolve()
    image_dir.mkdir(parents=True, exist_ok=True)

    config = BatchConfig(
        samples_dir=args.samples_dir.resolve(),
        output_dir=args.output_dir.resolve(),
        workdir_base=args.workdir.resolve(),
        image_dir=image_dir,
        timeout_seconds=args.timeout,
        project_dir=project_dir,
        force=args.force,
        num_workers=args.workers,
        base_image=base_image,
        qemu_memory=qemu_memory,
    )

    logger.info("Batch Analyzer starting")
    logger.info("  Samples:    %s", config.samples_dir)
    logger.info("  Output:     %s", config.output_dir)
    logger.info("  Workdir:    %s", config.workdir_base)
    logger.info("  Image dir:  %s", config.image_dir)
    logger.info("  Workers:    %d", config.num_workers)
    logger.info("  Timeout:    %ds per sample", config.timeout_seconds)
    logger.info("  Base image: %s", config.base_image)
    logger.info("  QEMU RAM:   %d MB", config.qemu_memory)

    # Preflight: ensure clean environment
    try:
        preflight_check(config.project_dir)
    except RuntimeError as e:
        logger.error("Preflight check failed: %s", e)
        logger.error("Please manually run: vagrant destroy -f && vagrant up --no-provision && vagrant snapshot save 'ready_provision'")
        sys.exit(1)

    try:
        results = run_batch(config)
    finally:
        cleanup_all(config.project_dir)

    generate_report(results, config.output_dir)

    failed = sum(1 for r in results if r.status in (SampleStatus.ERROR, SampleStatus.TIMEOUT))
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
