"""Tests for Ollama env wiring (no CAI / network)."""

from __future__ import annotations

import os
import sys
import unittest
import unittest.mock
from pathlib import Path

_EVAL = Path(__file__).resolve().parent.parent / "agent_solve_evaluation"
sys.path.insert(0, str(_EVAL))

from ollama_runtime import DEFAULT_OLLAMA_LOCAL_API_BASE, apply_ollama_cli_to_environ  # noqa: E402


class TestOllamaRuntime(unittest.TestCase):
    def test_no_flags_leaves_env(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"OLLAMA": "0"}, clear=False):
            applied = apply_ollama_cli_to_environ(enable=False, api_base=None)
            self.assertEqual(applied, {})

    def test_ollama_sets_local_default_when_base_missing(self) -> None:
        env = {"PATH": os.environ.get("PATH", "")}
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            applied = apply_ollama_cli_to_environ(enable=True, api_base=None)
            self.assertEqual(applied["OLLAMA"], "true")
            self.assertEqual(applied["OLLAMA_API_BASE"], DEFAULT_OLLAMA_LOCAL_API_BASE)
            self.assertEqual(os.environ["OLLAMA_API_BASE"], DEFAULT_OLLAMA_LOCAL_API_BASE)

    def test_preserves_existing_api_base(self) -> None:
        cloud = "https://ollama.example.com/v1"
        env = {"OLLAMA_API_BASE": cloud}
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            applied = apply_ollama_cli_to_environ(enable=True, api_base=None)
            self.assertEqual(applied, {"OLLAMA": "true"})
            self.assertEqual(os.environ["OLLAMA_API_BASE"], cloud)

    def test_api_base_implies_enable_and_overrides(self) -> None:
        env = {"OLLAMA_API_BASE": "http://old/v1"}
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            applied = apply_ollama_cli_to_environ(enable=False, api_base="https://new/v1")
            self.assertEqual(applied["OLLAMA"], "true")
            self.assertEqual(applied["OLLAMA_API_BASE"], "https://new/v1")
            self.assertEqual(os.environ["OLLAMA"], "true")

    def test_empty_api_base_raises(self) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                apply_ollama_cli_to_environ(enable=False, api_base="  ")


if __name__ == "__main__":
    unittest.main()
