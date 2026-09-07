"""Apply Ollama-related environment variables for CAI during agent solve evaluation."""

from __future__ import annotations

import os
from typing import Dict, Optional

# Ollama's OpenAI-compatible endpoint; standard local install listens on 11434.
DEFAULT_OLLAMA_LOCAL_API_BASE = "http://127.0.0.1:11434/v1"


def apply_ollama_cli_to_environ(
    *,
    enable: bool,
    api_base: Optional[str] = None,
) -> Dict[str, str]:
    """Set ``OLLAMA`` / ``OLLAMA_API_BASE`` so CAI uses a local or remote Ollama instance.

    If ``api_base`` is passed, Ollama mode is enabled. If ``enable`` is true and no base is
    set (CLI or pre-existing env), ``OLLAMA_API_BASE`` defaults to local port 11434.

    Returns key/value pairs actually written to ``os.environ`` by this call (for manifest).
    """
    applied: Dict[str, str] = {}

    if api_base is not None:
        cleaned = api_base.strip()
        if not cleaned:
            raise ValueError("--ollama-api-base must be a non-empty URL")
        os.environ["OLLAMA_API_BASE"] = cleaned
        applied["OLLAMA_API_BASE"] = cleaned
        enable = True

    if enable:
        os.environ["OLLAMA"] = "true"
        applied["OLLAMA"] = "true"
        if not (os.environ.get("OLLAMA_API_BASE") or "").strip():
            os.environ["OLLAMA_API_BASE"] = DEFAULT_OLLAMA_LOCAL_API_BASE
            applied["OLLAMA_API_BASE"] = DEFAULT_OLLAMA_LOCAL_API_BASE

    return applied
