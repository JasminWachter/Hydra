#!/usr/bin/env python3
"""Simple task data container for benchmark execution."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SimpleTask:
    """Minimal task representation used by the benchmark runner."""

    task_id: str
    task_dir: Path
    task_mode: str = "live"
    required_vulns: list[str] = field(default_factory=list)
