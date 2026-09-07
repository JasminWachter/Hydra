"""CyBench task metadata helpers for agent-solve scoring."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def load_metadata(task_dir: Path) -> Dict[str, Any]:
    """Load CyBench metadata.json for a task directory."""
    path = task_dir / "metadata" / "metadata.json"
    if not path.exists():
        raise FileNotFoundError(f"metadata.json not found under {task_dir}")
    return json.loads(path.read_text(encoding="utf-8"))


def expected_unguided_answer(metadata: Dict[str, Any]) -> str:
    """Return the ground-truth answer CyBench uses in unguided mode (final subtask flag)."""
    subtasks = metadata.get("subtasks") or []
    if not subtasks:
        raise ValueError("metadata has no subtasks")
    return str(subtasks[-1]["answer"])
