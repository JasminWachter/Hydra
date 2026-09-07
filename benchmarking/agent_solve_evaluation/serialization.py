"""Serialize CAI RunResult fields into JSON-safe structures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...(truncated)"


def extract_tool_text_blocks(result: Any, max_per_item: int = 4000) -> list[str]:
    """Pull string representations from run items for scoring."""
    blocks: list[str] = []
    for item in getattr(result, "new_items", []) or []:
        raw = getattr(item, "raw_item", None)
        if raw is None:
            continue
        blocks.append(_truncate(str(raw), max_per_item))
    return blocks


def summarize_usage(result: Any) -> dict[str, int]:
    """Sum per-call Usage across all raw_responses (one ModelResponse per LLM turn)."""
    totals = {"requests": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    for response in getattr(result, "raw_responses", []) or []:
        usage = getattr(response, "usage", None)
        if usage is None:
            continue
        for key in totals:
            totals[key] += getattr(usage, key, 0) or 0
    return totals


def count_tool_calls(result: Any) -> int:
    return sum(
        1 for item in getattr(result, "new_items", []) or []
        if type(item).__name__ == "ToolCallItem"
    )


def run_result_to_record(result: Any, max_tool_items: int = 50) -> dict[str, Any]:
    """Compact JSON-friendly summary of a RunResult."""
    items = getattr(result, "new_items", []) or []
    compact_items: list[dict[str, str]] = []
    for item in items[:max_tool_items]:
        raw = getattr(item, "raw_item", None)
        compact_items.append({
            "type": type(item).__name__,
            "raw": _truncate(str(raw), 4000),
        })
    return {
        "final_output": (
            _truncate(str(result.final_output), 8000)
            if getattr(result, "final_output", None) is not None
            else None
        ),
        "items_truncated": max(0, len(items) - max_tool_items),
        "items": compact_items,
        "usage": summarize_usage(result),
        "tool_call_count": count_tool_calls(result),
    }


def write_full_transcript(result: Any, path: Path) -> None:
    """Write the untruncated run transcript (all items + all raw responses) to disk."""
    items = getattr(result, "new_items", []) or []
    full_items = [
        {"type": type(item).__name__, "raw": str(getattr(item, "raw_item", None))}
        for item in items
    ]
    raw_responses = []
    for response in getattr(result, "raw_responses", []) or []:
        usage = getattr(response, "usage", None)
        raw_responses.append({
            "output": str(getattr(response, "output", None)),
            "usage": {
                key: getattr(usage, key, 0) or 0
                for key in ("requests", "input_tokens", "output_tokens", "total_tokens")
            } if usage is not None else None,
        })
    path.write_text(
        json.dumps(
            {
                "final_output": (
                    str(result.final_output)
                    if getattr(result, "final_output", None) is not None
                    else None
                ),
                "items": full_items,
                "raw_responses": raw_responses,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
