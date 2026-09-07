#!/usr/bin/env python3
"""Docker container lifecycle management for CyBench challenge tasks."""

import json
import logging
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from containers.compose_generator import ComposeGenerator
from runner.simple_task import SimpleTask
from runner.task_discovery import find_compose_file


class ContainerManager:
    """Starts, exposes, and stops the Docker environment for one task."""

    def __init__(self, task: SimpleTask, compose_generator: ComposeGenerator) -> None:
        self.task = task
        self._compose_generator = compose_generator
        self.env_state: Optional[Dict[str, Any]] = None
        self.scratch_dir: Optional[Path] = None
        self.compose_file: Optional[Path] = None
        self.project_name = re.sub(r'[^a-z0-9-]', '-', task.task_id.lower())
        # Callers may set this before calling start()
        self.compose_timeout: int = 180
        # Set by start(); wall-clock seconds spent on Docker build + up only.
        self.startup_time_sec: float = 0.0

    # ── public API ───────────────────────────────────────────────────────────

    def start(self, compose_timeout: Optional[int] = None) -> bool:
        """Build and start the task container. Returns True on success.

        Sets self.startup_time_sec to the wall-clock time spent on Docker
        operations (build + up + port resolution).  This value can be
        subtracted from total wall-clock time to obtain pipeline-only time.
        """
        timeout = compose_timeout if compose_timeout is not None else self.compose_timeout
        logging.info(
            f"Starting container for {self.task.task_id} (Project: {self.project_name})"
        )
        _start_ts = time.time()
        try:
            self.scratch_dir = Path(tempfile.mkdtemp(prefix=f"cybench_{self.task.task_id}_"))
            compose_file = find_compose_file(self.task.task_dir)

            if not compose_file:
                if not self._compose_generator.generate(self.task, self.scratch_dir):
                    logging.error("No compose file or Dockerfile found in task directory")
                    return False
                compose_file = self.scratch_dir / "docker-compose.yml"

            # Copy entire task tree so all build contexts are available
            shutil.copytree(self.task.task_dir, self.scratch_dir, dirs_exist_ok=True)

            try:
                relative = compose_file.relative_to(self.task.task_dir)
            except ValueError:
                relative = Path(compose_file.name)
            self.compose_file = self.scratch_dir / relative

            self._compose_generator.fix_build_contexts(self.compose_file, self.scratch_dir)

            subprocess.run(
                ["docker", "network", "create", "shared_net"],
                capture_output=True, text=True,
            )
            self._cleanup_existing_containers()

            cmd = [
                "docker", "compose", "-p", self.project_name,
                "-f", str(self.compose_file), "up", "-d", "--build",
            ]
            logging.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, cwd=str(self.scratch_dir),
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0:
                logging.error(f"Docker compose failed: {result.stderr}")
                return False

            self.env_state = self._resolve_service_endpoint()
            if not self.env_state:
                logging.error("Failed to resolve service endpoint")
                self.startup_time_sec = round(time.time() - _start_ts, 4)
                return False

            self.startup_time_sec = round(time.time() - _start_ts, 4)
            logging.info(
                f"Container started: "
                f"{self.env_state['resolved_host']}:{self.env_state['resolved_port']} "
                f"(startup: {self.startup_time_sec:.1f}s)"
            )
            return True

        except Exception as e:
            self.startup_time_sec = round(time.time() - _start_ts, 4)
            logging.error(f"Failed to start container: {e}")
            return False

    def stop(self) -> None:
        """Tear down the container and remove the scratch directory."""
        if not self.scratch_dir:
            return
        try:
            logging.info(
                f"Stopping container for {self.task.task_id} (Project: {self.project_name})"
            )
            if self.compose_file and self.compose_file.exists():
                result = subprocess.run(
                    [
                        "docker", "compose", "-p", self.project_name,
                        "-f", str(self.compose_file), "down", "-v", "--rmi", "all",
                    ],
                    cwd=str(self.scratch_dir),
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0:
                    logging.info("Container stopped successfully")
                else:
                    logging.warning(f"Container stop warning: {result.stderr}")
            else:
                logging.warning("No compose file found for cleanup")
        except Exception as e:
            logging.error(f"Failed to stop container: {e}")
        finally:
            if self.scratch_dir and self.scratch_dir.exists():
                try:
                    shutil.rmtree(self.scratch_dir)
                except Exception as e:
                    logging.warning(f"Failed to cleanup scratch directory: {e}")

    # ── private helpers ──────────────────────────────────────────────────────

    def _resolve_service_endpoint(self) -> Optional[Dict[str, Any]]:
        if not self.scratch_dir or not self.compose_file:
            return None
        try:
            result = subprocess.run(
                [
                    "docker", "compose", "-p", self.project_name,
                    "-f", str(self.compose_file), "ps", "--format", "json",
                ],
                cwd=str(self.scratch_dir),
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                logging.error(f"Failed to get container info: {result.stderr}")
                return self._fallback_endpoint_resolution()

            try:
                containers = [
                    json.loads(line)
                    for line in result.stdout.strip().split('\n')
                    if line.strip()
                ]
            except json.JSONDecodeError:
                return self._fallback_endpoint_resolution()

            if not containers:
                return self._fallback_endpoint_resolution()

            main_container = None
            for c in containers:
                if c.get("State") == "running":
                    if any(pub.get("PublishedPort") for pub in c.get("Publishers") or []):
                        main_container = c
                        break
                    elif main_container is None:
                        main_container = c

            if not main_container:
                logging.error("No running container found")
                return None

            host_port = 80
            for pub in main_container.get("Publishers", []):
                if pub.get("PublishedPort"):
                    host_port = pub["PublishedPort"]
                    break

            resolved_host, resolved_port = "localhost", int(host_port)
            if not self._wait_for_tcp(resolved_host, resolved_port, timeout=30):
                logging.error(f"Service not reachable on {resolved_host}:{resolved_port}")
                return None

            return {
                "resolved_host": resolved_host,
                "resolved_port": resolved_port,
                "container_name": main_container.get("Name", ""),
                "compose_file": str(self.compose_file),
                "scratch_dir": str(self.scratch_dir),
            }

        except Exception as e:
            logging.error(f"Failed to resolve endpoint: {e}")
            return None

    def _fallback_endpoint_resolution(self) -> Optional[Dict[str, Any]]:
        """Parse the compose file directly to find a port mapping."""
        try:
            compose_file = self._find_compose_file_in_scratch()
            if not compose_file:
                logging.error("No compose file found for fallback resolution")
                return None

            with compose_file.open('r') as f:
                compose_data = yaml.safe_load(f)

            for service_name, service_config in compose_data.get('services', {}).items():
                for mapping in service_config.get('ports', []):
                    if isinstance(mapping, str) and ':' in mapping:
                        host_port = int(mapping.split(':')[0])
                        if self._wait_for_tcp("localhost", host_port, timeout=30):
                            logging.info(f"Using fallback endpoint: localhost:{host_port}")
                            return {
                                "resolved_host": "localhost",
                                "resolved_port": host_port,
                                "container_name": service_name,
                                "compose_file": str(compose_file),
                                "scratch_dir": str(self.scratch_dir),
                            }

            logging.error("No reachable port mapping found in compose file")
            return None

        except Exception as e:
            logging.error(f"Fallback endpoint resolution failed: {e}")
            return None

    def _find_compose_file_in_scratch(self) -> Optional[Path]:
        if not self.scratch_dir:
            return None
        for name in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml'):
            p = self.scratch_dir / name
            if p.exists():
                return p
        return None

    def _cleanup_existing_containers(self) -> None:
        for name in ('web_flag', 'web_service', 'app', 'challenge'):
            subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True, text=True, timeout=30,
            )

    @staticmethod
    def _wait_for_tcp(host: str, port: int, timeout: int = 30) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((host, port)) == 0:
                    sock.close()
                    return True
                sock.close()
            except Exception:
                pass
            time.sleep(1)
        return False
