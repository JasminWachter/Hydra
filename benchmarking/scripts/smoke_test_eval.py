#!/usr/bin/env python3
"""Smoke test the evaluation pipeline end-to-end with the hybrid_reasoner_agent.

Picks one task from the inventory (or a task you specify), starts its Docker
environment, optionally uses precomputed graphs, runs the hybrid reasoner for a
small number of turns, then validates the output structure.

Pass/fail is based on pipeline completion without errors — not on whether the
agent captures the flag.

Usage:
    python3 benchmarking/scripts/smoke_test_eval.py
    python3 benchmarking/scripts/smoke_test_eval.py --task-id benchmark__hkcert-ctf__CTF-Challenges__CTF-2020__3._Web_Exploitation__6._LockPickDuck_v3
    python3 benchmarking/scripts/smoke_test_eval.py --precomputed-graphs-dir benchmarking/data/graphs
    python3 benchmarking/scripts/smoke_test_eval.py --max-turns 3
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parent
_BENCH_ROOT = _SCRIPTS_ROOT.parent
_REPO_ROOT = _BENCH_ROOT.parent

sys.path.insert(0, str(_BENCH_ROOT))
sys.path.insert(0, str(_BENCH_ROOT / "agent_solve_evaluation"))

DEFAULT_CYBENCH_ROOT = _REPO_ROOT.parent / "cybench"
DEFAULT_INVENTORY_CSV = _BENCH_ROOT / "data" / "web_ctf_inventory.csv"
DEFAULT_RESULTS_DIR = _BENCH_ROOT / "results" / "smoke_tests"
DEFAULT_PRECOMPUTED_GRAPHS = _BENCH_ROOT / "data" / "graphs"


def _pick_task(cybench_root: Path, inventory_csv: Path, task_id: str | None) -> str | None:
    """Return a task_id to test: use the given one, or pick the first with metadata."""
    from runner.task_discovery import discover_web_tasks_from_inventory

    tasks, _ = discover_web_tasks_from_inventory(cybench_root, inventory_csv)
    if not tasks:
        return None

    if task_id:
        ids = {t.task_id for t in tasks}
        if task_id not in ids:
            logging.error("task_id %r not in inventory", task_id)
            return None
        return task_id

    # Pick first task that has metadata.json
    for task in tasks:
        if (task.task_dir / "metadata" / "metadata.json").exists():
            return task.task_id

    return tasks[0].task_id


def _check_run_output(run_dir: Path, task_id: str) -> list[str]:
    """Return a list of failure reasons; empty list means all checks passed."""
    failures = []

    if not run_dir.exists():
        return [f"run_dir missing: {run_dir}"]

    manifest = run_dir / "manifest.json"
    if not manifest.exists():
        failures.append("manifest.json missing")
    else:
        data = json.loads(manifest.read_text())
        if "hybrid_reasoner_agent" not in data.get("agents", []):
            failures.append("hybrid_reasoner_agent not listed in manifest")

    metrics = run_dir / "metrics.json"
    if not metrics.exists():
        failures.append("metrics.json missing")
    else:
        records = json.loads(metrics.read_text())
        task_records = [r for r in records if r["task_id"] == task_id]
        if not task_records:
            failures.append(f"no metrics record for task_id={task_id!r}")
        else:
            for rec in task_records:
                if rec.get("agent") == "hybrid_reasoner_agent":
                    if rec.get("environment_status") not in ("ok", "metadata_error"):
                        failures.append(
                            f"unexpected environment_status: {rec.get('environment_status')!r}"
                        )

    summary = run_dir / "summary.json"
    if not summary.exists():
        failures.append("summary.json missing")

    return failures


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
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--task-id", type=str, default=None,
                        help="Specific task_id to smoke-test (default: first task with metadata)")
    parser.add_argument("--max-turns", type=int, default=5,
                        help="Max agent turns (default: 5 to keep smoke test fast)")
    parser.add_argument("--model", type=str, default=None,
                        help="Model override (default: CAI_MODEL env var)")
    parser.add_argument("--precomputed-graphs-dir", type=Path,
                        default=DEFAULT_PRECOMPUTED_GRAPHS if DEFAULT_PRECOMPUTED_GRAPHS.exists() else None,
                        metavar="DIR",
                        help="Directory of precomputed paths.json files per task_id")
    parser.add_argument("--compose-up-timeout-sec", type=int, default=180)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.cybench_root.exists():
        print(f"cybench root not found: {args.cybench_root}", file=sys.stderr)
        sys.exit(1)

    task_id = _pick_task(
        args.cybench_root.resolve(),
        args.inventory_csv.resolve(),
        args.task_id,
    )
    if not task_id:
        print("No suitable task found in inventory.", file=sys.stderr)
        sys.exit(1)

    logging.info("Smoke testing task: %s", task_id)
    logging.info("Max turns: %d", args.max_turns)
    if args.precomputed_graphs_dir:
        logging.info("Precomputed graphs dir: %s", args.precomputed_graphs_dir)

    import os
    model = args.model or os.environ.get("CAI_MODEL", "alias1")

    from run_evaluation import run_evaluation

    result = run_evaluation(
        cybench_root=args.cybench_root.resolve(),
        inventory_csv=args.inventory_csv.resolve(),
        results_dir=args.results_dir.resolve(),
        agents=["hybrid_reasoner_agent"],
        attempts=1,
        max_turns=args.max_turns,
        model=model,
        compose_timeout=args.compose_up_timeout_sec,
        nmap_profile="fast",
        reuse_graphs=False,
        precomputed_graphs_dir=args.precomputed_graphs_dir.resolve() if args.precomputed_graphs_dir else None,
        max_tasks=None,
        task_ids_filter=[task_id],
        run_requirements=False,
        verbose=args.verbose,
    )

    run_dir = Path(result["run_dir"])
    failures = _check_run_output(run_dir, task_id)

    print()
    print("=" * 60)
    if failures:
        print("SMOKE TEST FAILED")
        for f in failures:
            print(f"  - {f}")
        print(f"\nRun dir: {run_dir}")
        sys.exit(1)
    else:
        metrics = result.get("metrics", [])
        hybrid_rec = next(
            (r for r in metrics if r.get("agent") == "hybrid_reasoner_agent"), {}
        )
        paths_available = hybrid_rec.get("paths_available", False)
        path_count = hybrid_rec.get("path_count", 0)
        env_status = hybrid_rec.get("environment_status", "unknown")

        print("SMOKE TEST PASSED")
        print(f"  task_id:         {task_id}")
        print(f"  env_status:      {env_status}")
        print(f"  paths_available: {paths_available} ({path_count} paths)")
        print(f"  run_dir:         {run_dir}")
    print("=" * 60)


if __name__ == "__main__":
    main()
