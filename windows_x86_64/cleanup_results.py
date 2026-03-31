#!/usr/bin/env python3
"""
Clean up batch analysis results based on dump contents.

- If a sample has no actual dump files: remove its result directory
- If a sample has valid dumps: remove the corresponding .exe from targets/

Usage:
    python3 cleanup_results.py [--results-dir ./batch_results] [--targets-dir ./targets] [--dry-run]
"""

import argparse
import shutil
import sys
from pathlib import Path


def has_dump_data(dump_dir: Path) -> bool:
    """Check if dump directory contains actual dump files (not just empty dir)."""
    if not dump_dir.exists() or not dump_dir.is_dir():
        return False
    # Check for any real files (e.g., .bin, memory_map.txt) inside dump/
    dump_files = [f for f in dump_dir.rglob("*") if f.is_file()]
    return len(dump_files) > 0


def cleanup(results_dir: Path, targets_dir: Path, dry_run: bool) -> None:
    if not results_dir.exists():
        print(f"Results directory not found: {results_dir}")
        sys.exit(1)

    sample_dirs = sorted(
        d for d in results_dir.iterdir() if d.is_dir()
    )

    if not sample_dirs:
        print("No sample directories found")
        return

    removed_results = 0
    removed_targets = 0
    kept = 0

    for sample_dir in sample_dirs:
        sample_name = sample_dir.name
        dump_dir = sample_dir / "dump"

        if has_dump_data(dump_dir):
            # Valid dumps exist → remove target .exe
            kept += 1
            target_exe = targets_dir / f"{sample_name}.exe"
            if target_exe.exists():
                if dry_run:
                    print(f"  [DRY-RUN] Would remove target: {target_exe}")
                else:
                    target_exe.unlink()
                    print(f"  Removed target: {target_exe}")
                removed_targets += 1
            else:
                print(f"  OK (dumps exist, target already removed): {sample_name}")
        else:
            # No dumps → remove result directory
            if dry_run:
                print(f"  [DRY-RUN] Would remove empty result: {sample_dir}")
            else:
                shutil.rmtree(sample_dir)
                print(f"  Removed empty result: {sample_name}")
            removed_results += 1

    print()
    print(f"Summary:")
    print(f"  Total samples:      {len(sample_dirs)}")
    print(f"  With dumps (kept):  {kept}")
    print(f"  No dumps (removed): {removed_results}")
    print(f"  Targets removed:    {removed_targets}")
    if dry_run:
        print("  (dry-run mode, no changes made)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Clean up batch results: remove empty results, remove completed targets"
    )
    parser.add_argument(
        "--results-dir", type=Path, default=Path("./batch_results"),
        help="Batch results directory (default: ./batch_results)",
    )
    parser.add_argument(
        "--targets-dir", type=Path, default=Path("./targets"),
        help="Targets directory containing .exe files (default: ./targets)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be done without making changes",
    )
    args = parser.parse_args()
    cleanup(args.results_dir, args.targets_dir, args.dry_run)


if __name__ == "__main__":
    main()
