#!/usr/bin/env python3
"""Benchmark metric computation for CyBench attack-graph evaluation.

Public API:
  - compute_goal_reachability(paths_data) -> bool
  - compute_vulnerability_coverage(required_vulns, paths_data) -> dict
  - compute_noise_path_pct(required_vulns, paths_data) -> float | None
  - build_aggregate_summary(per_task_metrics) -> dict

Vulnerability coverage is driven by ground-truth required_vulns loaded from
web_ctf_inventory.csv (column: required_vulns, semicolon-separated class names).
"""

from __future__ import annotations

import statistics
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Vulnerability class → text signatures searched in path step fields
# (goal, rule_description, derived_fact, description)
# ---------------------------------------------------------------------------

VULNERABILITY_SIGNATURES: Dict[str, List[str]] = {
    "xss": [
        "xss", "XSS", "cross_site_script", "cross-site scripting",
        "T1185", "dom_xss", "stored_xss", "reflected_xss",
    ],
    "sqli": [
        "SQL inject", "SQLi", "sqli", "sql_inject", "UNION SELECT", "T1190",
    ],
    "nosqli": [
        "NoSQL inject", "nosql", "NoSQLi", "$gt", "$ne",
    ],
    "ssti": [
        "SSTI", "ssti", "template inject", "Template injection",
        "jinja", "twig", "plantuml", "java.el", "EL injection",
    ],
    "ssrf": [
        "SSRF", "ssrf", "server_side_request", "server-side request forgery",
    ],
    "cmdi": [
        "command inject", "CMDi", "Command injection", "exec_achieved",
        "remote code execution", "RCE", "rce", "code execution",
    ],
    "path_traversal": [
        "path traversal", "path_traversal", "directory traversal",
        "T1083", "lfi", "local file inclusion",
    ],
    "file_upload": [
        "file upload", "Upload RCE", "webshell", "malicious file",
    ],
    "auth_bypass": [
        "auth bypass", "Authentication bypass", "T1078", "auth_bypass",
        "type coercion", "type juggling", "loose comparison",
        "jwt", "otp bypass", "weak comparison",
    ],
    "idor": [
        "IDOR", "idor", "broken access control", "broken_access",
    ],
    "prototype_pollution": [
        "prototype pollution", "prototype_pollution", "__proto__",
    ],
    "deserialization": [
        "deserializ", "unserializ", "pickle", "T1059",
    ],
    "request_smuggling": [
        "request smuggling", "http smuggling", "Transfer-Encoding",
        "Content-Length desync",
    ],
    "git_exposure": [
        "git", ".git", "git_exposure", "reflog", "git history",
        "source code disclosure",
    ],
    "xxe": [
        "xxe", "XXE", "xml external entity", "xml_injection",
    ],
    "cve": [
        "CVE-", "cve_", "Local CVE exploit", "exploit_possible", "vuln(",
    ],
    "cache_poisoning": [
        "cache poisoning", "cache_poisoning", "cache deception",
    ],
    "info_disclosure": [
        "information disclosure", "info_disclosure", "source code exposure",
        "T1592", "recon_complete",
    ],
    "other": [],
}


def _path_text(path: Dict[str, Any]) -> str:
    """Concatenate all searchable text fields of a single path."""
    parts = [path.get("goal", "")]
    for step in path.get("steps", []):
        parts.append(step.get("rule_description", ""))
        parts.append(step.get("derived_fact", ""))
        parts.append(step.get("description", ""))
    return " ".join(parts).lower()


def _path_contains_vuln(path_text: str, vuln_class: str) -> bool:
    """Return True if path_text contains any signature for vuln_class."""
    sigs = VULNERABILITY_SIGNATURES.get(vuln_class, [])
    return any(sig.lower() in path_text for sig in sigs)


def compute_goal_reachability(paths_data: Dict[str, Any]) -> bool:
    """Return True if at least one path reaches an *objective* goal.

    recon_complete paths are the always-present reconnaissance/attack-surface overview —
    orientation only, never a confirmed exploit — so they are excluded here. Counting them
    would inflate reachability to ~100% (every reachable target has a recon overview) and mask
    whether an actual compromise/execCode/flag objective was reached.
    """
    if not paths_data:
        return False
    if paths_data.get("total_paths", 0) <= 0:
        return False

    for path in paths_data.get("paths", []):
        goal = str(path.get("goal", ""))
        if goal.startswith("recon_complete("):
            continue
        length = path.get("length", 0)
        if length >= 2 or "compromise(" in goal or "execCode(" in goal or "flag_obtained(" in goal:
            return True

    return False


def compute_vulnerability_coverage(
    required_vulns: List[str],
    paths_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Compute how many of the ground-truth required vulnerabilities appear
    in at least one generated path."""
    if not required_vulns:
        return {
            "total_required_vulns": 0,
            "covered_vulns": 0,
            "vuln_coverage_pct": None,
            "all_vulns_present": False,
            "missing_vulns": "",
        }

    paths = paths_data.get("paths", []) if paths_data else []
    path_texts = [_path_text(p) for p in paths]

    covered: set = set()
    for vuln_class in required_vulns:
        if any(_path_contains_vuln(pt, vuln_class) for pt in path_texts):
            covered.add(vuln_class)

    total = len(required_vulns)
    covered_count = len(covered)
    missing = [v for v in required_vulns if v not in covered]

    return {
        "total_required_vulns": total,
        "covered_vulns": covered_count,
        "vuln_coverage_pct": round(covered_count / total * 100, 2),
        "all_vulns_present": covered_count == total,
        "missing_vulns": ";".join(missing),
    }


def compute_noise_path_pct(
    required_vulns: List[str],
    paths_data: Dict[str, Any],
) -> Optional[float]:
    """Return the percentage of generated paths that contain none of the
    required vulnerability signatures."""
    if not required_vulns:
        return None

    paths = paths_data.get("paths", []) if paths_data else []
    if not paths:
        return None

    noise_count = 0
    for path in paths:
        pt = _path_text(path)
        if not any(_path_contains_vuln(pt, v) for v in required_vulns):
            noise_count += 1

    return round(noise_count / len(paths) * 100, 2)


def build_aggregate_summary(per_task_metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-task metrics into run-level summary statistics."""
    n = len(per_task_metrics)
    if n == 0:
        return {}

    goal_reached = sum(1 for m in per_task_metrics if m.get("goal_reachability"))

    gt_tasks = [m for m in per_task_metrics if m.get("total_required_vulns", 0) > 0]
    if gt_tasks:
        vuln_cov_vals = [m["vuln_coverage_pct"] for m in gt_tasks
                         if m.get("vuln_coverage_pct") is not None]
        mean_vuln_coverage = round(statistics.mean(vuln_cov_vals), 2) if vuln_cov_vals else 0.0
        all_present_count = sum(1 for m in gt_tasks if m.get("all_vulns_present"))
        all_present_rate = round(all_present_count / len(gt_tasks) * 100, 2)

        noise_vals = [m["noise_path_pct"] for m in gt_tasks
                      if m.get("noise_path_pct") is not None]
        mean_noise_path = round(statistics.mean(noise_vals), 2) if noise_vals else None
    else:
        mean_vuln_coverage = None
        all_present_rate = None
        mean_noise_path = None

    def _sorted(key: str) -> List[float]:
        return sorted(m.get(key, 0.0) for m in per_task_metrics)

    def _percentile(lst: List[float], p: float) -> float:
        if not lst:
            return 0.0
        idx = max(0, int(len(lst) * p / 100) - 1)
        return round(lst[idx], 4)

    predicate_times = _sorted("scanner_predicate_time_sec")
    mulval_times = _sorted("mulval_time_sec")
    pipeline_times = _sorted("pipeline_time_sec")
    timeout_count = sum(1 for m in per_task_metrics if "timeout" in str(m.get("notes", "")))

    return {
        "task_count": n,
        "gt_task_count": len(gt_tasks),
        "goal_reachability_rate_pct": round(goal_reached / n * 100, 2),
        "timeout_count": timeout_count,
        "mean_vuln_coverage_pct": mean_vuln_coverage,
        "all_vulns_present_rate_pct": all_present_rate,
        "mean_noise_path_pct": mean_noise_path,
        "predicate_time_p50_sec": _percentile(predicate_times, 50),
        "predicate_time_mean_sec": round(statistics.mean(predicate_times), 4),
        "mulval_time_p50_sec": _percentile(mulval_times, 50),
        "mulval_time_mean_sec": round(statistics.mean(mulval_times), 4),
        "pipeline_time_p50_sec": _percentile(pipeline_times, 50),
        "pipeline_time_mean_sec": round(statistics.mean(pipeline_times), 4),
    }
