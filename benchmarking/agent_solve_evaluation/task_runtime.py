"""Live CyBench task session for agent evaluation (container stays up)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from containers.compose_generator import ComposeGenerator
from containers.container_manager import ContainerManager
from runner.pipeline_runner import PipelineRunner
from runner.simple_task import SimpleTask
from runner.task_discovery import WebTask


class LiveAgentTaskSession:
    """Starts Docker env once; exposes host/port for agents and optional MulVAL graphs."""

    def __init__(self, task: WebTask, compose_timeout: int = 180) -> None:
        self.task = task
        self.simple_task = SimpleTask(
            task_id=task.task_id,
            task_dir=task.task_dir,
            task_mode=task.task_mode,
            required_vulns=task.required_vulns or [],
        )
        self.container_manager = ContainerManager(self.simple_task, ComposeGenerator())
        self.container_manager.compose_timeout = compose_timeout
        self.pipeline_runner = PipelineRunner()

    def start(self) -> bool:
        if self.task.task_mode != "live":
            logging.warning(
                "%s is mode=%s — expecting docker-compose for agent exploitation",
                self.task.task_id,
                self.task.task_mode,
            )
        ok = self.container_manager.start()
        if not ok:
            logging.error("Failed to start containers for %s", self.task.task_id)
        return ok

    def resolved_endpoint(self) -> Tuple[str, int]:
        env = self.container_manager.env_state or {}
        host = str(env.get("resolved_host", "localhost"))
        port = int(env.get("resolved_port", 80))
        return host, port

    def stop(self) -> None:
        self.container_manager.stop()

    def ensure_paths_json(
        self,
        graph_output_dir: Path,
        *,
        nmap_profile: str,
        reuse_existing: bool,
    ) -> Tuple[Optional[Path], Dict[str, Any]]:
        """Generate MulVAL paths.json against the live target, or reuse on disk."""
        graph_output_dir.mkdir(parents=True, exist_ok=True)
        paths_file = graph_output_dir / "paths.json"
        if reuse_existing and paths_file.exists():
            return paths_file, {"success": True, "reused": True, "task_mode": "live"}

        host, port = self.resolved_endpoint()
        result = self.pipeline_runner.run_live(
            task_dir=self.task.task_dir,
            output_dir=graph_output_dir,
            host=host,
            port=port,
            nmap_profile=nmap_profile,
        )
        if paths_file.exists():
            return paths_file, result
        return None, result
