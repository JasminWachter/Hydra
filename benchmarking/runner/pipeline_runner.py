#!/usr/bin/env python3
"""Runs the scanner + MulVAL attack-graph pipeline for a single task."""

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

_LIVE_SCANNERS = ["nmap", "trivy", "semgrep"]
_STATIC_SCANNERS = ["trivy", "semgrep"]


class PipelineRunner:
    """Executes scanners then MulVAL reasoning, returning a result dict.

    Callers choose live or static mode by passing the appropriate scanner list
    and host/port parameters.
    """

    def run_live(
        self,
        task_dir: Path,
        output_dir: Path,
        host: str,
        port: int,
        nmap_profile: str = "full",
    ) -> Dict[str, Any]:
        """Run with nmap + trivy + semgrep against a live container."""
        return self._run(
            task_dir=task_dir,
            output_dir=output_dir,
            scanners=_LIVE_SCANNERS,
            host=host,
            nmap_profile=nmap_profile,
            nmap_ports=str(port),
            task_mode="live",
        )

    def run_static(
        self,
        task_dir: Path,
        output_dir: Path,
        nmap_profile: str = "full",
    ) -> Dict[str, Any]:
        """Run with trivy + semgrep only (no container required)."""
        return self._run(
            task_dir=task_dir,
            output_dir=output_dir,
            scanners=_STATIC_SCANNERS,
            host="localhost",
            nmap_profile=nmap_profile,
            nmap_ports="80",
            task_mode="static",
        )

    # ── private ──────────────────────────────────────────────────────────────

    def _run(
        self,
        task_dir: Path,
        output_dir: Path,
        scanners: List[str],
        host: str,
        nmap_profile: str,
        nmap_ports: str,
        task_mode: str,
    ) -> Dict[str, Any]:
        output_dir.mkdir(parents=True, exist_ok=True)
        mulval_script = REPO_ROOT / "MulVAL" / "generate_predicates.py"

        t0 = time.time()
        command = [
            "python3",
            str(mulval_script),
            "--target",
            str(task_dir),
            "--output",
            str(output_dir),
            "--host",
            host,
            "--scanners",
            ",".join(scanners),
            "--nmap-profile",
            nmap_profile,
            "--nmap-ports",
            nmap_ports,
        ]
        logging.info(f"Running unified MulVAL pipeline ({task_mode})...")
        try:
            result = subprocess.run(
                command,
                cwd=str(REPO_ROOT / "MulVAL"),
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
        except Exception as e:
            return self._error_result(
                task_mode, str(e), scanner_predicate_time_sec=0.0, mulval_time_sec=0.0
            )

        t1 = time.time()
        predicates_file = output_dir / "input_predicates.P"
        if result.returncode != 0 or not predicates_file.exists():
            logging.error("Pipeline execution failed")
            if result.stderr:
                logging.error(result.stderr.strip())
            return self._error_result(
                task_mode,
                (result.stderr or "pipeline execution failed").strip()[:300],
                scanner_predicate_time_sec=round(t1 - t0, 4),
                mulval_time_sec=0.0,
            )

        try:
            t2 = time.time()

            path_count = 0
            paths_file = output_dir / "paths.json"
            if paths_file.exists():
                path_count = json.loads(paths_file.read_text()).get("total_paths", 0)
                logging.info(
                    f"{'Static analysis' if task_mode == 'static' else 'Generated'}: "
                    f"{path_count} attack paths"
                )

            return {
                "success": paths_file.exists(),
                "path_count": path_count,
                "task_mode": task_mode,
                "scanner_predicate_time_sec": round(t1 - t0, 4),
                "mulval_time_sec": round(t2 - t1, 4),
                "error": "" if paths_file.exists() else "MulVAL produced no paths",
            }

        except Exception as e:
            logging.error(f"MulVAL execution failed: {e}")
            return self._error_result(
                task_mode, str(e),
                scanner_predicate_time_sec=round(t1 - t0, 4), mulval_time_sec=0.0,
            )

    @staticmethod
    def _error_result(
        task_mode: str,
        error: str,
        scanner_predicate_time_sec: float,
        mulval_time_sec: float,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "path_count": 0,
            "task_mode": task_mode,
            "scanner_predicate_time_sec": scanner_predicate_time_sec,
            "mulval_time_sec": mulval_time_sec,
            "error": error,
        }
