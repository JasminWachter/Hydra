#!/usr/bin/env python3
"""Generates and fixes docker-compose files for Dockerfile-only challenge tasks."""

import logging
import re
import shutil
from pathlib import Path

import yaml

from containers.port_inference import PortInferrer
from runner.simple_task import SimpleTask


_DOCKERFILE_LOCATIONS = [
    'Dockerfile',
    'challenge/Dockerfile',
    'chall/Dockerfile',
    'app/Dockerfile',
    'env/Dockerfile',
    'src/Dockerfile',
    'dist/Dockerfile',
]


class ComposeGenerator:
    """Creates and repairs docker-compose files for tasks that only have a Dockerfile."""

    def generate(self, task: SimpleTask, scratch_dir: Path) -> bool:
        """Generate a docker-compose.yml in scratch_dir from the task's Dockerfile.

        Returns True if a compose file was written successfully.
        """
        dockerfile, context_dir = self._find_dockerfile(task.task_dir)
        if dockerfile is None:
            return False

        exposed_ports = PortInferrer.from_dockerfile(dockerfile)
        if not exposed_ports:
            exposed_ports = PortInferrer.from_source(context_dir)
        if not exposed_ports:
            exposed_ports = ['8080']
            logging.debug(f"No port detected for {task.task_id}, defaulting to 8080")

        seen: set = set()
        exposed_ports = [p for p in exposed_ports if not (p in seen or seen.add(p))]

        service_name = re.sub(r'[^a-z0-9]', '-', task.task_id.lower())[:50].strip('-')
        compose_content = {
            'services': {
                service_name: {
                    'build': {
                        'context': str(context_dir.relative_to(task.task_dir))
                    },
                    'ports': [f"{p}:{p}" for p in exposed_ports],
                    'networks': ['default'],
                }
            },
            'networks': {'default': {'driver': 'bridge'}},
        }

        shutil.copytree(task.task_dir, scratch_dir, dirs_exist_ok=True)

        compose_file = scratch_dir / "docker-compose.yml"
        with compose_file.open('w') as f:
            yaml.dump(compose_content, f)

        logging.info(f"Generated compose for {service_name}: ports={exposed_ports}")
        return True

    def fix_build_contexts(self, compose_file: Path, scratch_dir: Path) -> None:
        """Normalise build contexts and fix broken COPY/ADD paths in Dockerfiles."""
        if not compose_file.exists():
            return

        try:
            with compose_file.open('r') as f:
                content = f.read()
            content = re.sub(r'^version:\s*["\'].*?["\'].*?\n', '', content, flags=re.MULTILINE)
            compose_data = yaml.safe_load(content)
        except Exception as e:
            logging.error(f"Failed to parse compose file {compose_file}: {e}")
            return

        for service_name, service_config in compose_data.get('services', {}).items():
            build_info = service_config.get('build')
            if not build_info:
                continue

            build_context, dockerfile_path = self._extract_build_info(build_info)
            build_path = self._resolve_build_path(
                compose_file.parent, build_context, scratch_dir
            )

            if not build_path.exists():
                build_path = self._find_alternative_context(
                    compose_file.parent, build_info, service_name, build_context
                )

            df_path = build_path / dockerfile_path
            if df_path.exists():
                self._fix_dockerfile_paths(df_path, build_path)

        try:
            with compose_file.open('w') as f:
                yaml.dump(compose_data, f)
        except Exception as e:
            logging.error(f"Failed to write fixed compose file: {e}")

    # ── private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _find_dockerfile(task_dir: Path) -> tuple:
        """Return (dockerfile_path, context_dir) or (None, None)."""
        for location in _DOCKERFILE_LOCATIONS:
            candidate = task_dir / location
            if candidate.exists():
                return candidate, candidate.parent
        return None, None

    @staticmethod
    def _extract_build_info(build_info) -> tuple:
        if isinstance(build_info, str):
            return build_info, 'Dockerfile'
        if isinstance(build_info, dict):
            return build_info.get('context', '.'), build_info.get('dockerfile', 'Dockerfile')
        return '.', 'Dockerfile'

    @staticmethod
    def _resolve_build_path(compose_dir: Path, build_context: str, scratch_dir: Path) -> Path:
        build_path = (compose_dir / build_context).resolve()
        try:
            build_path.relative_to(scratch_dir.resolve())
        except ValueError:
            build_path = compose_dir
        return build_path

    @staticmethod
    def _find_alternative_context(
        compose_dir: Path,
        build_info,
        service_name: str,
        original_context: str,
    ) -> Path:
        for alt in ('./', './src', './app', './chall', './challenge', './dist'):
            alt_path = (compose_dir / alt).resolve()
            if alt_path.exists():
                if isinstance(build_info, str):
                    build_info = alt
                elif isinstance(build_info, dict):
                    build_info['context'] = alt
                logging.info(
                    f"Fixed build context for {service_name}: "
                    f"{original_context} -> {alt}"
                )
                return alt_path
        return compose_dir

    @staticmethod
    def _fix_dockerfile_paths(dockerfile: Path, context_dir: Path) -> None:
        """Rewrite broken COPY/ADD source paths to alternatives that exist."""
        try:
            lines = dockerfile.read_text().splitlines(keepends=True)
            changed = False
            new_lines = []
            for line in lines:
                match = re.match(
                    r'^(COPY|ADD)\s+(?:--[a-z-]+=[\w/:-]+\s+)*([\w./-]+)\s+([\w./-]+)',
                    line,
                    re.IGNORECASE,
                )
                if match:
                    _instruction, src, _dest = match.groups()
                    if not (context_dir / src).resolve().exists():
                        for prefix in ('chall/', 'challenge/', 'app/', 'src/'):
                            alt = prefix + src.lstrip('./')
                            if (context_dir / alt).resolve().exists():
                                line = line.replace(src, f"./{alt}")
                                logging.info(
                                    f"Fixed Dockerfile COPY path: {src} -> ./{alt}"
                                )
                                changed = True
                                break
                new_lines.append(line)

            if changed:
                dockerfile.write_text(''.join(new_lines))
        except Exception as e:
            logging.warning(f"Failed to fix Dockerfile {dockerfile}: {e}")
