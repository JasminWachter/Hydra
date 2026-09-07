#!/usr/bin/env python3
"""CyBench attack-graph quality benchmark runner.

Executes the full pipeline (scanner → predicate generation → MulVAL attack graph)
on every web challenge in web_ctf_inventory.csv and writes results to:

    <results_dir>/run_YYYYMMDD_HHMMSS/

Output files:
    manifest.json   — run metadata
    summary.json    — aggregate statistics
    metrics.json    — per-task result list
    metrics.csv     — per-task CSV
    tasks/<id>/     — per-task artefacts (paths.json, predicates, scan results)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent
_AG_QUALITY_DIR = THIS_DIR / "attack_graph_quality"

# runner/containers under benchmarking/; graph metric helpers under attack_graph_quality/
sys.path.insert(0, str(THIS_DIR))
sys.path.insert(0, str(_AG_QUALITY_DIR))

DEFAULT_CYBENCH_ROOT = REPO_ROOT.parent / "cybench"
DEFAULT_INVENTORY_CSV = THIS_DIR / "data" / "web_ctf_inventory.csv"
DEFAULT_RESULTS_DIR = THIS_DIR / "results" / "attack_graph_quality"

from runner.task_discovery import discover_web_tasks_from_inventory
from runner.simple_task import SimpleTask
from runner.single_task_runner import SingleTaskRunner
from metrics import (
    compute_goal_reachability,
    compute_vulnerability_coverage,
    compute_noise_path_pct,
    build_aggregate_summary,
)

METRICS_CSV_FIELDS = [
    "task_id", "ruleset", "scanner_set", "task_mode",
    "goal_reachability",
    "pipeline_time_sec", "scanner_predicate_time_sec", "mulval_time_sec",
    "container_startup_time_sec",
    "path_count",
    "required_vulns", "total_required_vulns", "covered_vulns",
    "vuln_coverage_pct", "all_vulns_present", "missing_vulns",
    "noise_path_pct",
    "notes",
]


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )


def _run_requirements(task_dir: Path) -> None:
    """Run metadata/requirements.sh if present (e.g. pull Docker images)."""
    req_script = task_dir / "metadata" / "requirements.sh"
    if not req_script.exists():
        return
    import subprocess
    logging.info(f"    Running requirements.sh for {task_dir.name}")
    try:
        subprocess.run(
            ["bash", str(req_script)],
            cwd=str(task_dir),
            timeout=120,
            check=False,
        )
    except Exception as exc:
        logging.warning(f"    requirements.sh failed: {exc}")


def run_benchmark(
    cybench_root: Path,
    results_dir: Path,
    scanners: str = "trivy,semgrep,nmap",
    nmap_profile: str = "full",
    run_task_requirements: bool = False,
    compose_up_timeout_sec: int = 180,
    max_tasks: Optional[int] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    setup_logging(verbose)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"run_{timestamp}"
    run_dir = results_dir / run_id
    tasks_dir = run_dir / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)

    logging.info(f"Results directory: {run_dir}")

    all_tasks, issues = discover_web_tasks_from_inventory(cybench_root, DEFAULT_INVENTORY_CSV)
    all_task_count = len(all_tasks)
    logging.info(f"Discovered {all_task_count} web tasks ({len(issues)} discovery issues)")
    if issues:
        for issue in issues[:5]:
            logging.warning(f"  {issue}")
        if len(issues) > 5:
            logging.warning(f"  … and {len(issues) - 5} more")

    tasks = all_tasks[:max_tasks] if max_tasks else all_tasks
    logging.info(f"Running {len(tasks)} tasks  (scanners={scanners}, nmap={nmap_profile})")
    logging.info("=" * 70)

    per_task_metrics: List[Dict[str, Any]] = []

    for i, task in enumerate(tasks, 1):
        logging.info(f"[{i}/{len(tasks)}] {task.task_id}  [{task.task_mode}]")

        task_output_dir = tasks_dir / task.task_id
        task_output_dir.mkdir(parents=True, exist_ok=True)

        if run_task_requirements:
            _run_requirements(task.task_dir)

        simple_task = SimpleTask(
            task_id=task.task_id,
            task_dir=task.task_dir,
            task_mode=task.task_mode,
            required_vulns=task.required_vulns or [],
        )

        runner = SingleTaskRunner(
            task=simple_task,
            output_dir=task_output_dir,
            nmap_profile=nmap_profile,
        )
        runner.container_manager.compose_timeout = compose_up_timeout_sec

        wall_start = time.time()
        try:
            runner.run()
        except Exception as exc:
            logging.error(f"  Unhandled exception: {exc}")
            runner.result = {"success": False, "error": str(exc),
                             "task_mode": task.task_mode,
                             "scanner_predicate_time_sec": 0.0, "mulval_time_sec": 0.0}
        wall_elapsed = round(time.time() - wall_start, 4)
        container_startup_time_sec = round(runner.container_manager.startup_time_sec, 4)
        pipeline_time_sec = round(max(0.0, wall_elapsed - container_startup_time_sec), 4)

        r = runner.result
        path_count = r.get("path_count", 0)
        error_note = r.get("error", "")

        paths_json_file = task_output_dir / "paths.json"
        paths_data: Dict[str, Any] = {}
        if paths_json_file.exists():
            try:
                paths_data = json.loads(paths_json_file.read_text())
            except Exception:
                pass

        required_vulns = task.required_vulns or []
        goal_reachable = compute_goal_reachability(paths_data)
        vuln_metrics = compute_vulnerability_coverage(required_vulns, paths_data)
        noise_pct = compute_noise_path_pct(required_vulns, paths_data)

        notes_parts = []
        if error_note:
            notes_parts.append(f"error:{error_note[:120]}")
        if vuln_metrics.get("missing_vulns"):
            notes_parts.append(f"missing_vulns:{vuln_metrics['missing_vulns']}")

        metric: Dict[str, Any] = {
            "task_id": task.task_id,
            "ruleset": "combined_rules",
            "scanner_set": scanners,
            "task_mode": task.task_mode,
            "goal_reachability": goal_reachable,
            "pipeline_time_sec": pipeline_time_sec,
            "scanner_predicate_time_sec": r.get("scanner_predicate_time_sec", 0.0),
            "mulval_time_sec": r.get("mulval_time_sec", 0.0),
            "container_startup_time_sec": container_startup_time_sec,
            "path_count": path_count,
            "required_vulns": ";".join(required_vulns),
            "total_required_vulns": vuln_metrics["total_required_vulns"],
            "covered_vulns": vuln_metrics["covered_vulns"],
            "vuln_coverage_pct": vuln_metrics["vuln_coverage_pct"],
            "all_vulns_present": vuln_metrics["all_vulns_present"],
            "missing_vulns": vuln_metrics["missing_vulns"],
            "noise_path_pct": noise_pct,
            "notes": ";".join(notes_parts),
        }
        per_task_metrics.append(metric)

        status = "✓" if metric["goal_reachability"] else "✗"
        logging.info(f"  {status} {path_count} paths  pipeline={pipeline_time_sec:.1f}s  "
                     f"docker={container_startup_time_sec:.1f}s")

        if i % 10 == 0 or i == len(tasks):
            reached = sum(1 for m in per_task_metrics if m["goal_reachability"])
            logging.info(f"  Progress {i}/{len(tasks)} — goal_reachability {reached}/{i}")

    summary = build_aggregate_summary(per_task_metrics)

    manifest = {
        "run_id": run_id,
        "evaluation_track": "attack_graph_quality",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cybench_root": str(cybench_root),
        "ruleset": "combined_rules",
        "scanners": scanners,
        "nmap_profile": nmap_profile,
        "nmap_ports": None,
        "run_task_requirements": run_task_requirements,
        "compose_up_timeout_sec": compose_up_timeout_sec,
        "all_discovered_web_task_count": all_task_count,
        "task_count": len(tasks),
        "task_ids": [t.task_id for t in tasks],
        "web_inventory_csv": str(DEFAULT_INVENTORY_CSV),
        "inventory_issue_count": len(issues),
    }

    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    (run_dir / "metrics.json").write_text(json.dumps(per_task_metrics, indent=2))

    with (run_dir / "metrics.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=METRICS_CSV_FIELDS)
        writer.writeheader()
        for m in per_task_metrics:
            writer.writerow({k: m.get(k, "") for k in METRICS_CSV_FIELDS})

    n = summary.get("task_count", len(per_task_metrics))
    gt_n = summary.get("gt_task_count", 0)
    goal_reached_n = round(n * summary.get("goal_reachability_rate_pct", 0) / 100)

    def _fmt(val: Any, suffix: str = "") -> str:
        return f"{val:.1f}{suffix}" if isinstance(val, float) else "n/a"

    logging.info("=" * 70)
    logging.info("BENCHMARK COMPLETE")
    logging.info(f"  Tasks run             : {n}  (ground-truth tasks: {gt_n})")
    logging.info(f"  Goal reachability     : {goal_reached_n}/{n} "
                 f"({summary['goal_reachability_rate_pct']:.1f}%)")
    logging.info(f"  Vuln coverage (mean)  : {_fmt(summary.get('mean_vuln_coverage_pct'), '%')}")
    logging.info(f"  All vulns present     : {_fmt(summary.get('all_vulns_present_rate_pct'), '%')} "
                 f"of {gt_n} ground-truth tasks")
    logging.info(f"  Noise paths (mean)    : {_fmt(summary.get('mean_noise_path_pct'), '%')}")
    logging.info(f"  Predicate time p50    : {_fmt(summary.get('predicate_time_p50_sec'), 's')}  "
                 f"mean={_fmt(summary.get('predicate_time_mean_sec'), 's')}")
    logging.info(f"  MulVAL time p50       : {_fmt(summary.get('mulval_time_p50_sec'), 's')}  "
                 f"mean={_fmt(summary.get('mulval_time_mean_sec'), 's')}")
    logging.info(f"  Pipeline time p50     : {_fmt(summary.get('pipeline_time_p50_sec'), 's')}  "
                 f"mean={_fmt(summary.get('pipeline_time_mean_sec'), 's')}")
    logging.info(f"  Results saved to      : {run_dir}")

    return {"run_dir": str(run_dir), "manifest": manifest, "summary": summary,
            "per_task_metrics": per_task_metrics}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run CyBench web attack-graph quality benchmark",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--cybench-root", type=Path, default=DEFAULT_CYBENCH_ROOT,
                        help="Path to CyBench repository root")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR,
                        help="Root results directory; each run saved under run_<timestamp>/")
    parser.add_argument("--scanners", default="trivy,semgrep,nmap",
                        help="Comma-separated scanner list")
    parser.add_argument("--nmap-profile", default="full", choices=["full", "fast"],
                        help="Nmap scan profile")
    parser.add_argument("--run-task-requirements", action="store_true",
                        help="Execute metadata/requirements.sh before each task")
    parser.add_argument("--compose-up-timeout-sec", type=int, default=180,
                        help="Seconds to wait for docker compose up")
    parser.add_argument("--max-tasks", type=int, default=None,
                        help="Cap number of tasks (for quick tests)")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    args.cybench_root = args.cybench_root.resolve()
    args.results_dir = args.results_dir.resolve()

    if not args.cybench_root.exists():
        print(f"Error: CyBench root not found: {args.cybench_root}", file=sys.stderr)
        sys.exit(1)

    if not DEFAULT_INVENTORY_CSV.exists():
        print(f"Error: Inventory CSV not found: {DEFAULT_INVENTORY_CSV}", file=sys.stderr)
        sys.exit(1)

    run_benchmark(
        cybench_root=args.cybench_root,
        results_dir=args.results_dir,
        scanners=args.scanners,
        nmap_profile=args.nmap_profile,
        run_task_requirements=args.run_task_requirements,
        compose_up_timeout_sec=args.compose_up_timeout_sec,
        max_tasks=args.max_tasks,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
