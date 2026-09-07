#!/usr/bin/env python3
"""Orchestrates the full attack-graph pipeline for a single CyBench task.

Usage:
    python single_task_runner.py --task-id <task_id> --cybench-root <path>
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict

from containers.compose_generator import ComposeGenerator
from containers.container_manager import ContainerManager
from runner.pipeline_runner import PipelineRunner
from runner.simple_task import SimpleTask
from runner.task_discovery import discover_web_tasks_from_inventory

BENCH_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = BENCH_ROOT.parent


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )


class SingleTaskRunner:
    """Coordinates ContainerManager and PipelineRunner for one task.

    After run() the result dict contains:
        success, path_count, task_mode, scanner_predicate_time_sec,
        mulval_time_sec, error
    """

    def __init__(
        self,
        task: SimpleTask,
        output_dir: Path,
        nmap_profile: str = "full",
    ) -> None:
        self.task = task
        self.output_dir = output_dir
        self.nmap_profile = nmap_profile
        self.container_manager = ContainerManager(task, ComposeGenerator())
        self.pipeline_runner = PipelineRunner()
        self.result: Dict[str, Any] = {}

    def run(self) -> bool:
        """Execute the pipeline. Always brings the container up so nmap, trivy, and semgrep
        all run against every task; a container that fails to build/start is reported as an
        explicit failure to investigate (compose/Dockerfile), not silently downgraded to a
        static, nmap-less scan."""
        logging.info(f"Starting attack graph generation for {self.task.task_id}")

        if not self.container_manager.start():
            self.result = {
                "success": False,
                "path_count": 0,
                "task_mode": "live",
                "scanner_predicate_time_sec": 0.0,
                "mulval_time_sec": 0.0,
                "error": "Container failed to start (see compose/Dockerfile for this task).",
            }
            logging.error(f"Container failed to start for {self.task.task_id}")
            return False

        try:
            env = self.container_manager.env_state
            self.result = self.pipeline_runner.run_live(
                task_dir=self.task.task_dir,
                output_dir=self.output_dir,
                host=env["resolved_host"],
                port=env["resolved_port"],
                nmap_profile=self.nmap_profile,
            )
            return self.result.get("success", False)
        finally:
            self.container_manager.stop()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate attack graph for a single CyBench task"
    )
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--cybench-root", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--nmap-profile", choices=["full", "fast"], default="full")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    cybench_root = (
        Path(args.cybench_root).resolve()
        if args.cybench_root
        else REPO_ROOT.parent / "cybench"
    )
    if not cybench_root.exists():
        logging.error(f"CyBench root not found: {cybench_root}")
        sys.exit(1)

    inventory_csv = BENCH_ROOT / "data" / "web_ctf_inventory.csv"
    if not inventory_csv.exists():
        logging.error(f"Inventory CSV not found: {inventory_csv}")
        sys.exit(1)

    tasks, issues = discover_web_tasks_from_inventory(cybench_root, inventory_csv)
    for issue in issues[:5]:
        logging.warning(f"  {issue}")

    target_task = next((t for t in tasks if t.task_id == args.task_id), None)
    if not target_task:
        logging.error(f"Task {args.task_id} not found in inventory")
        for t in tasks[:10]:
            logging.info(f"  {t.task_id}")
        sys.exit(1)

    output_dir = (
        Path(args.output_dir).resolve()
        if args.output_dir
        else REPO_ROOT / "MulVAL" / "graphs" / f"single_task_{args.task_id}"
    )

    runner = SingleTaskRunner(target_task, output_dir, args.nmap_profile)
    t0 = time.time()
    success = runner.run()
    elapsed = time.time() - t0

    if success:
        logging.info(f"Attack graph completed in {elapsed:.1f}s — results: {output_dir}")
    else:
        logging.error(f"Attack graph failed after {elapsed:.1f}s")
        sys.exit(1)


if __name__ == "__main__":
    main()
