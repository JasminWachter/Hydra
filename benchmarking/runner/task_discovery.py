#!/usr/bin/env python3
"""Task discovery utilities for CyBench web challenges."""

import json
import logging
from pathlib import Path
from typing import List, Optional, Tuple, Any
from dataclasses import dataclass


# Infrastructure discovery locations, shared by inventory discovery and find_compose_file so a new
# location only has to be added once. 'dist' covers challenges that ship their deployable stack
# under a dist/ directory (e.g. sekai chunky's dist/docker-compose.yml).
COMPOSE_FILENAMES = ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml')
INFRA_SUBDIRS = ('env', 'challenge', 'chall', 'dist')
DOCKERFILE_LOCATIONS = (
    'Dockerfile', 'challenge/Dockerfile', 'chall/Dockerfile',
    'app/Dockerfile', 'env/Dockerfile', 'src/Dockerfile', 'dist/Dockerfile',
)


@dataclass
class WebTask:
    """Represents a web challenge task."""
    task_id: str
    task_dir: Path
    categories: List[str]
    target_host: str
    subtasks: List[Any]
    metadata: Optional[dict] = None
    task_mode: str = "live"  # "live" = has compose/Dockerfile; "static" = source-only analysis
    # Ground-truth vulnerability classes required to capture the flag,
    # loaded from the required_vulns column in web_ctf_inventory.csv.
    required_vulns: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.required_vulns is None:
            self.required_vulns = []


def discover_web_tasks_from_inventory(
    cybench_root: Path, 
    inventory_csv: Path
) -> Tuple[List[WebTask], List[str]]:
    """Discover web tasks from inventory CSV file."""
    import csv
    
    tasks = []
    issues = []
    
    if not inventory_csv.exists():
        issues.append(f"Inventory CSV not found: {inventory_csv}")
        return tasks, issues
    
    with inventory_csv.open('r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row_num, row in enumerate(reader, 2):  # Start at 2 for header + 1-based
            task_path = row.get('task_path', '').strip()
            if not task_path:
                continue
                
            full_path = cybench_root / task_path
            if not full_path.exists():
                issues.append(f"Row {row_num}: Task path not found: {task_path}")
                continue
            
            # Check for compose files (task directory + common subdirectories)
            has_compose = find_compose_file(full_path) is not None

            # Check for Dockerfile when no compose is present
            has_dockerfile = False
            if not has_compose:
                has_dockerfile = any((full_path / df).exists() for df in DOCKERFILE_LOCATIONS)

            # Determine execution mode: live (container) or static (source-only)
            if has_compose or has_dockerfile:
                task_mode = "live"
            else:
                task_mode = "static"
                logging.debug(f"No compose/Dockerfile for {task_path} — will run static analysis only")
            
            # Try to load metadata if available
            metadata_file = full_path / "metadata" / "metadata.json"
            metadata = None
            categories = ['web']  # Default category
            target_host = 'localhost'
            subtasks = []
            
            if metadata_file.exists():
                try:
                    with metadata_file.open('r') as f:
                        metadata = json.load(f)
                    categories = metadata.get('categories', ['web'])
                    target_host = metadata.get('target_host', 'localhost')
                    subtasks = metadata.get('subtasks', [])
                except Exception as e:
                    issues.append(f"Row {row_num}: Failed to parse metadata: {e}")
            
            # Create task ID from path
            task_id = task_path.replace("/", "__").replace(" ", "_").replace("[", "_").replace("]", "_")

            # Load ground-truth required vulnerabilities (semicolon-separated class names).
            raw_vulns = row.get("required_vulns", "").strip()
            required_vulns = [v.strip() for v in raw_vulns.split(";") if v.strip()]

            task = WebTask(
                task_id=task_id,
                task_dir=full_path,
                categories=categories,
                target_host=target_host,
                subtasks=subtasks,
                metadata=metadata,
                task_mode=task_mode,
                required_vulns=required_vulns,
            )

            tasks.append(task)
    
    logging.info(f"Discovered {len(tasks)} web tasks from inventory")
    return tasks, issues


def find_compose_file(task_dir: Path) -> Optional[Path]:
    """Find Docker Compose file in task directory or a known infrastructure subdirectory."""
    for name in COMPOSE_FILENAMES:
        if (task_dir / name).exists():
            return task_dir / name

    for subdir in INFRA_SUBDIRS:
        for name in COMPOSE_FILENAMES:
            if (task_dir / subdir / name).exists():
                return task_dir / subdir / name

    return None
