#!/usr/bin/env python3
"""Precompute MulVAL attack graphs for all challenges in the inventory.

Run from any directory:
    python3 benchmarking/scripts/precompute_graphs.py

Graphs are stored in benchmarking/data/graphs/{task_id}/paths.json.
Uses static analysis only (trivy + semgrep) — no live containers needed.
Idempotent: skips tasks where paths.json already exists unless --force.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parent
_BENCH_ROOT = _SCRIPTS_ROOT.parent
_REPO_ROOT = _BENCH_ROOT.parent

sys.path.insert(0, str(_BENCH_ROOT))

DEFAULT_CYBENCH_ROOT = _REPO_ROOT.parent / "cybench"
DEFAULT_INVENTORY_CSV = _BENCH_ROOT / "data" / "web_ctf_inventory.csv"
DEFAULT_GRAPHS_DIR = _BENCH_ROOT / "data" / "graphs"


def precompute_graphs(
    cybench_root: Path,
    inventory_csv: Path,
    graphs_dir: Path,
    *,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[list[str], list[str], list[str]]:
    """Return (generated, skipped, failed) task_id lists."""
    from runner.pipeline_runner import PipelineRunner
    from runner.task_discovery import discover_web_tasks_from_inventory

    tasks, issues = discover_web_tasks_from_inventory(cybench_root, inventory_csv)
    if issues:
        logging.warning("%d discovery issues:\n  %s", len(issues), "\n  ".join(issues[:10]))

    graphs_dir.mkdir(parents=True, exist_ok=True)
    runner = PipelineRunner()

    generated: list[str] = []
    skipped: list[str] = []
    failed: list[str] = []

    for i, task in enumerate(tasks, 1):
        task_graphs_dir = graphs_dir / task.task_id
        paths_file = task_graphs_dir / "paths.json"

        if paths_file.exists() and not force:
            logging.info("[%d/%d] SKIP  %s (paths.json exists)", i, len(tasks), task.task_id)
            skipped.append(task.task_id)
            continue

        if dry_run:
            logging.info("[%d/%d] DRY-RUN  %s", i, len(tasks), task.task_id)
            generated.append(task.task_id)
            continue

        logging.info("[%d/%d] Generating  %s", i, len(tasks), task.task_id)
        result = runner.run_static(task_dir=task.task_dir, output_dir=task_graphs_dir)

        elapsed = result.get("scanner_predicate_time_sec", 0) + result.get("mulval_time_sec", 0)
        if result.get("success") and paths_file.exists():
            logging.info("  -> %d paths  %.1fs", result.get("path_count", 0), elapsed)
            generated.append(task.task_id)
        else:
            logging.warning("  -> FAILED (%.1fs): %s", elapsed, result.get("error", "unknown"))
            failed.append(task.task_id)

    return generated, skipped, failed


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cybench-root", type=Path, default=DEFAULT_CYBENCH_ROOT)
    parser.add_argument("--inventory-csv", type=Path, default=DEFAULT_INVENTORY_CSV)
    parser.add_argument("--graphs-dir", type=Path, default=DEFAULT_GRAPHS_DIR,
                        help="Output directory for precomputed graphs (default: benchmarking/data/graphs/)")
    parser.add_argument("--force", action="store_true",
                        help="Regenerate even if paths.json already exists")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be generated without running scanners")
    args = parser.parse_args()

    if not args.cybench_root.exists():
        print(f"cybench root not found: {args.cybench_root}", file=sys.stderr)
        sys.exit(1)

    generated, skipped, failed = precompute_graphs(
        cybench_root=args.cybench_root.resolve(),
        inventory_csv=args.inventory_csv.resolve(),
        graphs_dir=args.graphs_dir.resolve(),
        force=args.force,
        dry_run=args.dry_run,
    )

    print(f"\nGenerated: {len(generated)}  Skipped: {len(skipped)}  Failed: {len(failed)}")
    if failed:
        print("Failed tasks (no paths.json produced):")
        for t in failed:
            print(f"  {t}")
        sys.exit(1)


if __name__ == "__main__":
    main()
