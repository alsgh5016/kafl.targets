#!/usr/bin/env python3
"""
Auto-batch runner: continuously processes samples with automatic worker recovery.

Wraps batch_analyze.py in a retry loop that:
1. Runs batch analysis on remaining samples
2. Cleans up empty results and removes completed targets
3. If samples remain, tears down workers, re-creates them, and repeats
4. Stops when all samples are processed or max rounds exceeded

Usage:
    python3 auto_batch.py ./targets/ -o ./batch_results -n 4 -t 600

    # With custom max rounds and workdir
    python3 auto_batch.py ./targets/ -o ./batch_results -n 4 -t 600 \
        -w /root/kafl_workdir --max-rounds 50
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path


def count_remaining_targets(targets_dir: Path) -> int:
    """Count .exe files remaining in targets directory."""
    return len(list(targets_dir.glob("*.exe")))


def count_results(results_dir: Path) -> int:
    """Count completed result directories."""
    if not results_dir.exists():
        return 0
    return len([d for d in results_dir.iterdir() if d.is_dir()])


def run_cmd(cmd: list[str], label: str, cwd: Path = None) -> int:
    """Run a command, printing output in real-time. Returns exit code."""
    print(f"\n{'='*60}")
    print(f"[auto_batch] {label}")
    print(f"[auto_batch] $ {' '.join(cmd)}")
    print(f"{'='*60}\n")

    result = subprocess.run(cmd, cwd=cwd)
    return result.returncode


def run_batch_round(
    targets_dir: Path,
    results_dir: Path,
    num_workers: int,
    timeout: int,
    workdir: Path,
    extra_args: list[str],
    project_dir: Path,
) -> int:
    """Run one round of batch analysis. Returns exit code."""
    cmd = [
        sys.executable, "batch_analyze.py", "run",
        str(targets_dir),
        "-o", str(results_dir),
        "-t", str(timeout),
    ]
    if workdir:
        cmd.extend(["-w", str(workdir)])
    cmd.extend(extra_args)

    return run_cmd(cmd, "Running batch analysis", cwd=project_dir)


def cleanup_results(
    results_dir: Path,
    targets_dir: Path,
    project_dir: Path,
) -> None:
    """Run cleanup_results.py to remove empties and completed targets."""
    cmd = [
        sys.executable, "cleanup_results.py",
        "--results-dir", str(results_dir),
        "--targets-dir", str(targets_dir),
    ]
    run_cmd(cmd, "Cleaning up results", cwd=project_dir)


def teardown_workers(project_dir: Path) -> None:
    """Tear down all worker VMs."""
    run_cmd(
        [sys.executable, "batch_analyze.py", "teardown"],
        "Tearing down workers",
        cwd=project_dir,
    )


def setup_workers(num_workers: int, project_dir: Path) -> int:
    """Set up fresh worker VMs. Returns exit code."""
    return run_cmd(
        [sys.executable, "batch_analyze.py", "setup", "-n", str(num_workers)],
        f"Setting up {num_workers} workers",
        cwd=project_dir,
    )


def auto_batch(args: argparse.Namespace) -> None:
    project_dir = Path(__file__).resolve().parent
    targets_dir = args.targets_dir.resolve()
    results_dir = args.results_dir.resolve()

    initial_count = count_remaining_targets(targets_dir)
    if initial_count == 0:
        print("[auto_batch] No .exe files found in targets directory")
        return

    print(f"[auto_batch] Starting auto-batch")
    print(f"[auto_batch]   Targets dir:  {targets_dir}")
    print(f"[auto_batch]   Results dir:  {results_dir}")
    print(f"[auto_batch]   Workers:      {args.num_workers}")
    print(f"[auto_batch]   Timeout:      {args.timeout}s")
    print(f"[auto_batch]   Max rounds:   {args.max_rounds}")
    print(f"[auto_batch]   Initial samples: {initial_count}")

    total_start = time.time()

    for round_num in range(1, args.max_rounds + 1):
        remaining = count_remaining_targets(targets_dir)
        results_count = count_results(results_dir)

        if remaining == 0:
            print(f"\n[auto_batch] All samples processed!")
            break

        print(f"\n{'#'*60}")
        print(f"[auto_batch] ROUND {round_num}/{args.max_rounds}")
        print(f"[auto_batch]   Remaining: {remaining}, Completed: {results_count}")
        print(f"{'#'*60}")

        # Check if workers exist, setup or recycle as needed
        workers_config = project_dir / "workers" / "workers.json"
        need_setup = not workers_config.exists() or round_num > 1

        if need_setup:
            if round_num > 1:
                print(f"\n[auto_batch] Recycling workers...")
                teardown_workers(project_dir)
                time.sleep(3)
            else:
                print(f"\n[auto_batch] Setting up workers (first round)...")

            rc = setup_workers(args.num_workers, project_dir)
            if rc != 0:
                print(f"[auto_batch] Worker setup failed (rc={rc}), retrying...")
                teardown_workers(project_dir)
                time.sleep(5)
                rc = setup_workers(args.num_workers, project_dir)
                if rc != 0:
                    print(f"[auto_batch] Worker setup failed again, aborting")
                    break

        # Run batch
        run_batch_round(
            targets_dir, results_dir,
            args.num_workers, args.timeout,
            args.workdir, args.extra_args,
            project_dir,
        )

        # Cleanup: remove empty results, delete completed targets
        cleanup_results(results_dir, targets_dir, project_dir)

        # Check progress
        new_remaining = count_remaining_targets(targets_dir)
        processed_this_round = remaining - new_remaining

        elapsed = time.time() - total_start
        print(f"\n[auto_batch] Round {round_num} complete:")
        print(f"[auto_batch]   Processed this round: {processed_this_round}")
        print(f"[auto_batch]   Remaining: {new_remaining}")
        print(f"[auto_batch]   Total elapsed: {elapsed/60:.1f}m")

        if processed_this_round == 0:
            print(f"[auto_batch] No progress this round - "
                  f"remaining {new_remaining} samples may be problematic")
            if round_num >= 3:
                print(f"[auto_batch] 3 rounds with no progress, stopping")
                break
            print(f"[auto_batch] Will retry with fresh workers...")

    # Final summary
    final_remaining = count_remaining_targets(targets_dir)
    final_results = count_results(results_dir)
    total_elapsed = time.time() - total_start

    print(f"\n{'='*60}")
    print(f"[auto_batch] FINAL SUMMARY")
    print(f"[auto_batch]   Initial samples:  {initial_count}")
    print(f"[auto_batch]   Completed:        {final_results}")
    print(f"[auto_batch]   Remaining:        {final_remaining}")
    print(f"[auto_batch]   Total time:       {total_elapsed/60:.1f}m")
    print(f"{'='*60}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auto-batch runner with automatic worker recovery"
    )
    parser.add_argument(
        "targets_dir", type=Path,
        help="Directory containing .exe samples",
    )
    parser.add_argument(
        "-o", "--results-dir", type=Path, default=Path("./batch_results"),
        help="Output directory (default: ./batch_results)",
    )
    parser.add_argument(
        "-n", "--num-workers", type=int, default=4,
        help="Number of worker VMs (default: 4)",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=600,
        help="Per-sample timeout in seconds (default: 600)",
    )
    parser.add_argument(
        "-w", "--workdir", type=Path, default=None,
        help="kAFL workdir base path",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=100,
        help="Maximum retry rounds (default: 100)",
    )
    parser.add_argument(
        "extra_args", nargs="*", default=[],
        help="Extra arguments passed to batch_analyze.py run",
    )

    args = parser.parse_args()
    auto_batch(args)


if __name__ == "__main__":
    main()
