"""Unit tests for shared benchmarking utilities (no Docker / no API calls)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_BENCH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BENCH))
sys.path.insert(0, str(_BENCH / "agent_solve_evaluation"))

from common.cybench_metadata import expected_unguided_answer, load_metadata  # noqa: E402
from common.pass_at_k import pass_at_k_unbiased  # noqa: E402
from scoring import build_transcript, score_transcript  # noqa: E402


class TestPassAtK(unittest.TestCase):
    def test_pass_at_three_attempts(self) -> None:
        self.assertEqual(pass_at_k_unbiased(3, 0, 3), 0.0)
        self.assertEqual(pass_at_k_unbiased(3, 1, 3), 1.0)
        self.assertEqual(pass_at_k_unbiased(3, 3, 3), 1.0)


class TestCybenchMetadata(unittest.TestCase):
    def test_expected_answer_last_subtask(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "metadata").mkdir()
            meta = {
                "subtasks": [
                    {"question": "a", "answer": "no"},
                    {"question": "flag?", "answer": "FLAG{abc}"},
                ]
            }
            (p / "metadata" / "metadata.json").write_text(json.dumps(meta))
            md = load_metadata(p)
            self.assertEqual(expected_unguided_answer(md), "FLAG{abc}")


class TestScoring(unittest.TestCase):
    def test_exact_line_match(self) -> None:
        transcript = build_transcript("noise\nFLAG{X}", [])
        r = score_transcript("FLAG{X}", transcript)
        self.assertTrue(r["exact_match"])
        self.assertTrue(r["solved_primary"])

    def test_contains_without_exact(self) -> None:
        transcript = "here FLAG{X} trailing"
        r = score_transcript("FLAG{X}", transcript)
        self.assertFalse(r["exact_match"])
        self.assertTrue(r["contains_answer"])


class TestGoalReachability(unittest.TestCase):
    """The recon overview is always present; it must not count as reaching the objective."""

    def setUp(self) -> None:
        sys.path.insert(0, str(_BENCH / "attack_graph_quality"))
        from metrics import compute_goal_reachability
        self.reach = compute_goal_reachability

    def test_recon_only_is_not_goal_reached(self) -> None:
        data = {"total_paths": 2, "paths": [
            {"goal": "recon_complete(h,web_fingerprint)", "length": 3},
            {"goal": "recon_complete(h,host_reachable)", "length": 3},
        ]}
        self.assertFalse(self.reach(data))

    def test_exploit_path_is_goal_reached(self) -> None:
        data = {"total_paths": 2, "paths": [
            {"goal": "compromise(h,web_user)", "length": 4},
            {"goal": "recon_complete(h,host_reachable)", "length": 3},
        ]}
        self.assertTrue(self.reach(data))

    def test_empty_is_not_reached(self) -> None:
        self.assertFalse(self.reach({"total_paths": 0, "paths": []}))


if __name__ == "__main__":
    unittest.main()
