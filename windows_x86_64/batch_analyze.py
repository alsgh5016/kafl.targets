#!/usr/bin/env python3
"""
Batch PE Unpacking Analyzer for kAFL.

Automates sequential kAFL unpacking analysis across multiple packed PE samples.
For each sample: provision VM → run kAFL → collect results.

Usage:
    python3 batch_analyze.py /path/to/samples_dir -o ./results -t 600
"""

import argparse
import enum
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
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


@dataclass(frozen=True)
class BatchConfig:
    samples_dir: Path
    output_dir: Path
    workdir: Path
    timeout_seconds: int
    project_dir: Path
    force: bool
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
        # Skip symlinks that escape the samples directory
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


# -- VM Provisioning --

def provision_vm(sample_path: Path, project_dir: Path, timeout: int) -> None:
    """Copy sample to bin/ and provision the VM via Makefile."""
    target_path = project_dir / "bin" / "userspace" / "target_packed.exe"
    target_path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy2(sample_path, target_path)
    logger.info("Copied %s -> %s", sample_path.name, target_path)

    # Run make provision_unpack (restores vagrant, uploads binaries)
    logger.info("Provisioning VM...")
    _run_cmd(
        ["make", "provision_unpack"],
        cwd=project_dir,
        timeout=PROVISION_TIMEOUT_SECONDS,
        label="make provision_unpack",
    )

    # Halt vagrant VM (Makefile has this commented out)
    logger.info("Halting vagrant VM...")
    _run_cmd(
        ["vagrant", "halt", "-f"],
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
            cmd,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            text=True,
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
    extra_args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess:
    """Run kafl fuzz and wait for completion or timeout."""
    cmd = [
        "kafl", "fuzz",
        "--purge",
        "-w", str(workdir),
        "--log-hprintf",
        "-p", "1",
        *extra_args,
    ]
    logger.info("Running: %s", " ".join(cmd))

    proc = subprocess.Popen(
        cmd,
        cwd=project_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,  # new process group for cleanup
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

    # kAFL exits non-zero on habort (expected) — we check hprintf log instead
    logger.debug("kAFL exited with rc=%d", proc.returncode)
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

    # Count dump files
    dump_dir = workdir / "dump"
    if dump_dir.is_dir():
        for root, _, files in os.walk(dump_dir):
            dump_count += len(files)

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

    # Files/dirs to collect
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

    # Write result metadata
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

def process_sample(sample_path: Path, config: BatchConfig) -> SampleResult:
    """Process a single packed PE sample end-to-end."""
    sample_name = sample_path.stem
    start_time = time.time()
    result: Optional[SampleResult] = None

    try:
        # 1. Provision VM with this sample
        provision_vm(sample_path, config.project_dir, timeout=PROVISION_TIMEOUT_SECONDS)

        # 2. Run kAFL analysis
        run_kafl(
            config.workdir,
            config.project_dir,
            config.timeout_seconds,
            config.kafl_extra_args,
        )

        # 3. Validate results
        success, dump_count, wte_count = validate_results(config.workdir)
        duration = time.time() - start_time

        status = SampleStatus.SUCCESS if success else SampleStatus.ERROR
        error_msg = None if success else "Analysis did not complete (no success marker in hprintf log)"

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
        _, dump_count, wte_count = _safe_validate(config.workdir)
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
        _, dump_count, wte_count = _safe_validate(config.workdir)
        result = SampleResult(
            sample_name=sample_name,
            status=SampleStatus.ERROR,
            duration_seconds=duration,
            error_message=str(e),
            wte_count=wte_count,
            dump_file_count=dump_count,
        )

    finally:
        # Build fallback result if none was assigned (e.g. KeyboardInterrupt)
        if result is None:
            result = SampleResult(
                sample_name=sample_name,
                status=SampleStatus.ERROR,
                duration_seconds=time.time() - start_time,
                error_message="Interrupted",
            )
        # Always try to collect whatever results exist
        if config.workdir.exists():
            collect_results(config.workdir, config.output_dir, sample_name, result)
        cleanup_vm(config.project_dir, config.workdir)

    return result


def _safe_validate(workdir: Path) -> tuple[bool, int, Optional[int]]:
    """Validate results, returning defaults on any error."""
    try:
        if workdir.exists():
            return validate_results(workdir)
    except Exception:
        logger.debug("validate_results failed for %s", workdir, exc_info=True)
    return False, 0, None


def cleanup_vm(project_dir: Path, workdir: Optional[Path] = None) -> None:
    """Force-halt vagrant VM and kill stray QEMU processes."""
    try:
        subprocess.run(
            ["vagrant", "halt", "-f"],
            cwd=project_dir,
            timeout=CLEANUP_HALT_TIMEOUT_SECONDS,
            capture_output=True,
        )
    except Exception as e:
        logger.debug("vagrant halt failed (non-critical): %s", e)

    # Kill stray QEMU processes scoped to our workdir
    try:
        pattern = "qemu-system-x86_64"
        if workdir is not None:
            pattern = f"qemu-system-x86_64.*{re.escape(str(workdir))}"
        subprocess.run(
            ["pkill", "-f", pattern],
            timeout=10,
            capture_output=True,
        )
    except Exception as e:
        logger.debug("pkill failed (non-critical): %s", e)


# -- Batch Orchestration --

def run_batch(config: BatchConfig) -> list[SampleResult]:
    """Run batch analysis across all samples."""
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
            logger.info("Skipping %d already-processed samples (use --force to re-run)", skipped_count)
    else:
        pending = samples

    results: list[SampleResult] = []

    # Add skipped results for already-processed samples
    for s in samples:
        if s not in pending:
            results.append(SampleResult(
                sample_name=s.stem,
                status=SampleStatus.SKIPPED,
                duration_seconds=0.0,
            ))

    total = len(pending)
    for i, sample in enumerate(pending, 1):
        logger.info("=" * 60)
        logger.info("[%d/%d] Processing: %s", i, total, sample.name)
        logger.info("=" * 60)

        result = process_sample(sample, config)
        results.append(result)

        status_icon = {
            SampleStatus.SUCCESS: "OK",
            SampleStatus.TIMEOUT: "TIMEOUT",
            SampleStatus.ERROR: "FAIL",
        }.get(result.status, "?")

        logger.info(
            "[%d/%d] %s -> %s (%.1fs, WtE=%s, dumps=%d)",
            i, total, sample.name, status_icon,
            result.duration_seconds,
            result.wte_count if result.wte_count is not None else "?",
            result.dump_file_count,
        )

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

    # Console summary
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

    # Per-sample table
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

    # JSON report
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
  %(prog)s /path/to/packed_samples -o ./results -t 600
  %(prog)s /path/to/packed_samples --force  # re-process all
        """,
    )
    parser.add_argument("samples_dir", type=Path, help="Directory containing packed PE samples")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("./batch_results"),
                        help="Output directory for results (default: ./batch_results)")
    parser.add_argument("-w", "--workdir", type=Path, default=Path("/dev/shm/kafl_batch"),
                        help="kAFL working directory (default: /dev/shm/kafl_batch)")
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

    # Also log to file
    args.output_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(args.output_dir / "batch_analyze.log")
    file_handler.setFormatter(logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S"))
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    # Resolve project directory (where Makefile lives)
    project_dir = Path(__file__).resolve().parent

    config = BatchConfig(
        samples_dir=args.samples_dir.resolve(),
        output_dir=args.output_dir.resolve(),
        workdir=args.workdir.resolve(),
        timeout_seconds=args.timeout,
        project_dir=project_dir,
        force=args.force,
    )

    logger.info("Batch Analyzer starting")
    logger.info("  Samples:  %s", config.samples_dir)
    logger.info("  Output:   %s", config.output_dir)
    logger.info("  Workdir:  %s", config.workdir)
    logger.info("  Timeout:  %ds per sample", config.timeout_seconds)

    results = run_batch(config)
    generate_report(results, config.output_dir)

    # Exit with error if any samples failed
    failed = sum(1 for r in results if r.status in (SampleStatus.ERROR, SampleStatus.TIMEOUT))
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
