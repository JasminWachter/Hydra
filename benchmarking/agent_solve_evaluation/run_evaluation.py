#!/usr/bin/env python3
"""CyBench-aligned agent solve benchmark: red-team baseline vs hybrid reasoner."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_EVAL_ROOT = Path(__file__).resolve().parent
_BENCH_ROOT = _EVAL_ROOT.parent
_REPO_ROOT = _BENCH_ROOT.parent

sys.path.insert(0, str(_BENCH_ROOT))
sys.path.insert(0, str(_EVAL_ROOT))

from ollama_runtime import apply_ollama_cli_to_environ  # noqa: E402
from common.cybench_metadata import expected_unguided_answer, load_metadata  # noqa: E402
from common.pass_at_k import pass_at_k_unbiased  # noqa: E402
from runner.task_discovery import WebTask, discover_web_tasks_from_inventory  # noqa: E402

from runners import (  # noqa: E402
    run_agent_async,
    run_hybrid_reasoner_attempt,
    run_raw_scanner_attempt,
    run_redteam_attempt,
)
from scoring import build_transcript, score_transcript  # noqa: E402
from serialization import extract_tool_text_blocks, run_result_to_record, write_full_transcript  # noqa: E402
from task_runtime import LiveAgentTaskSession  # noqa: E402

DEFAULT_CYBENCH_ROOT = _REPO_ROOT.parent / "cybench"
DEFAULT_INVENTORY_CSV = _BENCH_ROOT / "data" / "web_ctf_inventory.csv"
DEFAULT_RESULTS_DIR = _BENCH_ROOT / "results" / "agent_solve_evaluation"

METRICS_CSV_FIELDS = [
    "task_id",
    "agent",
    "attempts_configured",
    "correct_attempts",
    "pass_at_k",
    "k",
    "pass_at_1_first_attempt",
    "pass_at_1",
    "pass_at_3",
    "tokens_total",
    "tool_calls",
    "environment_status",
    "paths_available",
    "path_count",
    "total_wall_sec",
]

SETUP_LOGGING_DONE = False


def setup_logging(verbose: bool = False) -> None:
    global SETUP_LOGGING_DONE  # pylint: disable=global-statement
    if SETUP_LOGGING_DONE:
        return
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )
    SETUP_LOGGING_DONE = True


def _parse_agents(raw: str) -> List[str]:
    parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    if not parts:
        raise ValueError("No agents specified")
    _BASELINE_AGENTS = {"redteam_agent", "web_pentester_agent", "raw_scanner_agent"}
    _ALL_AGENTS = _BASELINE_AGENTS | {"hybrid_reasoner_agent"}
    for key in parts:
        if key not in _ALL_AGENTS:
            raise ValueError(
                f"Unsupported agent {key!r}; expected one of {sorted(_ALL_AGENTS)}"
            )
    return parts


def _filter_tasks_by_ids(tasks: List[WebTask], ids: Optional[List[str]]) -> List[WebTask]:
    if not ids:
        return tasks
    want = set(ids)
    out = [t for t in tasks if t.task_id in want]
    missing = want - {t.task_id for t in out}
    if missing:
        logging.warning("Unknown task_id filters (skipped): %s", sorted(missing))
    return out


def _collect_answer_strings(obj: Any) -> List[str]:
    """Recursively collect every string value under a key literally named "answer"."""
    found: List[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "answer" and isinstance(value, str) and value:
                found.append(value)
            else:
                found.extend(_collect_answer_strings(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_collect_answer_strings(item))
    return found


def _make_sanitized_source_dir(task_dir: Path, answers: Sequence[str]) -> Path:
    """Copy task_dir for the agent to read, stripping metadata/ (holds the ground-truth
    answer) and redacting that same answer out of any other file (e.g. README.md ships
    the identical flag in plaintext in this dataset) — otherwise agents just read the
    flag off disk instead of exploiting the live target (confirmed via transcripts: a
    large fraction of "solved" attempts cited metadata.json/README.md as their source)."""
    dest = Path(tempfile.mkdtemp(prefix="cai_source_")) / "source"
    shutil.copytree(task_dir, dest, ignore=shutil.ignore_patterns("metadata"))
    if answers:
        for path in dest.rglob("*"):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            redacted = text
            for answer in answers:
                redacted = redacted.replace(answer, "[REDACTED]")
            if redacted != text:
                path.write_text(redacted, encoding="utf-8")
    return dest


# Safety net for hung tool calls (e.g. a model invoking an interactive command that never
# returns) — without this, one stuck attempt blocks the entire remaining run indefinitely.
ATTEMPT_TIMEOUT_SEC = 1200


def _agent_attempt(
    *,
    agent_key: str,
    base_url: str,
    target_hostport: str,
    paths_file: Optional[Path],
    graph_dir: Optional[Path],
    source_dir: Optional[Path],
    model: str,
    max_turns: int,
) -> Any:
    if agent_key == "hybrid_reasoner_agent":
        return run_agent_async(
            run_hybrid_reasoner_attempt(
                base_url=base_url,
                target_hostport=target_hostport,
                paths_file=paths_file,
                source_dir=source_dir,
                model=model,
                max_turns=max_turns,
            ),
            timeout_sec=ATTEMPT_TIMEOUT_SEC,
        )
    if agent_key == "raw_scanner_agent":
        return run_agent_async(
            run_raw_scanner_attempt(
                base_url=base_url,
                graph_dir=graph_dir,
                source_dir=source_dir,
                model=model,
                max_turns=max_turns,
            ),
            timeout_sec=ATTEMPT_TIMEOUT_SEC,
        )
    return run_agent_async(
        run_redteam_attempt(base_url=base_url, model=model, max_turns=max_turns,
                            source_dir=source_dir, agent_key=agent_key),
        timeout_sec=ATTEMPT_TIMEOUT_SEC,
    )


def run_evaluation(
    *,
    cybench_root: Path,
    inventory_csv: Path,
    results_dir: Path,
    agents: Sequence[str],
    attempts: int,
    max_turns: int,
    model: str,
    compose_timeout: int,
    nmap_profile: str,
    reuse_graphs: bool,
    precomputed_graphs_dir: Optional[Path] = None,
    max_tasks: Optional[int],
    task_ids_filter: Optional[List[str]],
    run_requirements: bool,
    verbose: bool,
    ollama_runtime: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    setup_logging(verbose)

    if attempts < 1:
        raise ValueError("attempts must be >= 1")

    if not inventory_csv.exists():
        raise FileNotFoundError(inventory_csv)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"run_{timestamp}"
    run_dir = results_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    all_tasks, issues = discover_web_tasks_from_inventory(cybench_root, inventory_csv)
    tasks = _filter_tasks_by_ids(all_tasks, task_ids_filter)

    # Drop tasks without metadata.json before max_tasks slicing so --max-tasks N
    # always yields N runnable tasks rather than hitting broken ones first.
    valid_tasks = []
    skipped_no_meta = []
    for t in tasks:
        meta_path = t.task_dir / "metadata" / "metadata.json"
        if meta_path.exists():
            valid_tasks.append(t)
        else:
            skipped_no_meta.append(t.task_id)
    if skipped_no_meta:
        logging.info("Skipping %d tasks without metadata.json", len(skipped_no_meta))
        logging.debug("Skipped: %s", skipped_no_meta)
    tasks = valid_tasks

    if max_tasks:
        tasks = tasks[:max_tasks]

    logging.info("Discovered %d tasks (%d issues); evaluating %d", len(all_tasks), len(issues), len(tasks))

    manifest: Dict[str, Any] = {
        "run_id": run_id,
        "evaluation_track": "agent_solve_evaluation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cybench_root": str(cybench_root),
        "inventory_csv": str(inventory_csv),
        "inventory_issue_count": len(issues),
        "agents": list(agents),
        "attempts": attempts,
        "max_turns": max_turns,
        "model": model,
        "compose_up_timeout_sec": compose_timeout,
        "nmap_profile": nmap_profile,
        "reuse_graphs": reuse_graphs,
        "precomputed_graphs_dir": str(precomputed_graphs_dir) if precomputed_graphs_dir else None,
        "task_ids": [t.task_id for t in tasks],
        "task_count": len(tasks),
        "run_task_requirements": run_requirements,
    }
    if ollama_runtime:
        manifest["ollama_runtime"] = dict(ollama_runtime)
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    metrics_records: List[Dict[str, Any]] = []
    infrastructure_failed_tasks = 0

    for idx, task in enumerate(tasks, 1):
        logging.info("[%s/%s] %s", idx, len(tasks), task.task_id)
        task_dir = run_dir / "tasks" / task.task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        graph_dir = task_dir / "graphs"
        paths_file: Optional[Path] = None
        path_count = 0
        paths_meta: Dict[str, Any] = {}

        session_wall_start = time.time()

        meta_path = task_dir / "metadata_snapshot.json"
        expected_answer = ""
        sanitized_source_dir: Optional[Path] = None
        try:
            md = load_metadata(task.task_dir)
            meta_path.write_text(json.dumps(md, indent=2), encoding="utf-8")
            expected_answer = expected_unguided_answer(md)
            # Agents are told source_dir's path directly in their prompt and can read any
            # file under it via unrestricted shell tools — task.task_dir itself is the raw
            # cybench checkout, which ships the ground-truth flag in metadata/metadata.json
            # (and duplicated verbatim in README.md), so agents get a sanitized copy instead.
            sanitized_source_dir = _make_sanitized_source_dir(
                task.task_dir, _collect_answer_strings(md)
            )
        except Exception as exc:  # pylint: disable=broad-except
            logging.error("  Missing/bad metadata: %s", exc)
            for agent_key in agents:
                metrics_records.append({
                    "task_id": task.task_id,
                    "agent": agent_key,
                    "attempts_configured": attempts,
                    "environment_status": "metadata_error",
                    "paths_available": False,
                    "path_count": 0,
                    "attempt_details": [],
                    "correct_attempts": 0,
                    "pass_at_k": 0.0,
                    "k": attempts,
                    "pass_at_1_first_attempt": 0.0,
                    "total_wall_sec": round(time.time() - session_wall_start, 4),
                    "error": str(exc),
                })
            continue

        session = LiveAgentTaskSession(task, compose_timeout=compose_timeout)
        env_ok = session.start()
        if env_ok:
            host, port = session.resolved_endpoint()
            base_url = f"http://{host}:{port}"
            target_hostport = f"{host}:{port}"
        else:
            # No live container (e.g. the challenge's own Dockerfile build fails — a data
            # issue in the source repo, not this pipeline). Agents still run: they get a
            # prompt saying the target is unreachable and, when source_dir exists, can
            # still analyze it. Scanning/attack-graph generation is skipped (nothing to
            # scan), so hybrid_reasoner/raw_scanner fall back to their "no data" prompts.
            infrastructure_failed_tasks += 1
            base_url = "http://unreachable-target:0"
            target_hostport = "unreachable-target:0"
            logging.warning("  Environment failed to start for %s — running agents without a live target", task.task_id)

        try:
            if env_ok and ("hybrid_reasoner_agent" in agents or "raw_scanner_agent" in agents):
                # Prefer precomputed graphs if available.
                precomputed = (
                    precomputed_graphs_dir / task.task_id / "paths.json"
                    if precomputed_graphs_dir
                    else None
                )
                if precomputed and precomputed.exists():
                    paths_file = precomputed
                    paths_meta = {"success": True, "reused": True, "task_mode": "precomputed"}
                    logging.debug("Using precomputed paths for %s", task.task_id)
                else:
                    paths_file, paths_meta = session.ensure_paths_json(
                        graph_dir,
                        nmap_profile=nmap_profile,
                        reuse_existing=reuse_graphs,
                    )
                if paths_file and paths_file.exists():
                    try:
                        pdata = json.loads(paths_file.read_text(encoding="utf-8"))
                        path_count = int(pdata.get("total_paths", 0))
                    except Exception:
                        path_count = 0
            elif reuse_graphs and (graph_dir / "paths.json").exists():
                paths_file = graph_dir / "paths.json"

            if run_requirements:
                req_script = task.task_dir / "metadata" / "requirements.sh"
                if req_script.exists():
                    import subprocess
                    subprocess.run(
                        ["bash", str(req_script)],
                        cwd=str(task.task_dir),
                        timeout=120,
                        check=False,
                    )

            for agent_key in agents:
                hybrid_paths = paths_file if agent_key == "hybrid_reasoner_agent" else None
                attempt_details: List[Dict[str, Any]] = []
                successes: List[bool] = []
                tokens_total = 0
                tool_calls_total = 0

                for attempt_idx in range(attempts):
                    attempt_dir = task_dir / "agents" / agent_key / f"attempt_{attempt_idx + 1}"
                    attempt_dir.mkdir(parents=True, exist_ok=True)

                    t0 = time.time()
                    error_txt: Optional[str] = None
                    result_dict: Dict[str, Any] = {}
                    score_result = {"exact_match": False, "contains_answer": False, "solved_primary": False}

                    # Tools like execute_code write files into CAI_WORKSPACE_DIR (falling back
                    # to the process CWD — this repo's root — if unset). Scope it per attempt
                    # so generated scripts never pollute the repo and attempts stay independent
                    # of each other (an agent shouldn't see files a prior attempt left behind).
                    workspace_dir = tempfile.mkdtemp(prefix="cai_workspace_")
                    prev_workspace_dir = os.environ.get("CAI_WORKSPACE_DIR")
                    os.environ["CAI_WORKSPACE_DIR"] = workspace_dir
                    try:
                        result = _agent_attempt(
                            agent_key=agent_key,
                            base_url=base_url,
                            target_hostport=target_hostport,
                            paths_file=hybrid_paths,
                            graph_dir=graph_dir,
                            source_dir=sanitized_source_dir,
                            model=model,
                            max_turns=max_turns,
                        )
                        tool_blocks = extract_tool_text_blocks(result)
                        transcript = build_transcript(result.final_output, tool_blocks)
                        score_result = score_transcript(expected_answer, transcript)
                        result_dict = run_result_to_record(result)
                        write_full_transcript(result, attempt_dir / "transcript.json")
                    except Exception as exc:  # pylint: disable=broad-except
                        error_txt = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
                    finally:
                        if prev_workspace_dir is None:
                            os.environ.pop("CAI_WORKSPACE_DIR", None)
                        else:
                            os.environ["CAI_WORKSPACE_DIR"] = prev_workspace_dir
                        shutil.rmtree(workspace_dir, ignore_errors=True)

                    elapsed_attempt = round(time.time() - t0, 4)
                    solved = bool(score_result.get("solved_primary"))
                    successes.append(solved)
                    tokens_total += result_dict.get("usage", {}).get("total_tokens", 0)
                    tool_calls_total += result_dict.get("tool_call_count", 0)

                    logging.info(
                        "  [%s/%s] %s attempt %s/%s: solved=%s tool_calls=%s tokens=%s wall=%ss%s",
                        idx, len(tasks), agent_key, attempt_idx + 1, attempts, solved,
                        result_dict.get("tool_call_count", 0),
                        result_dict.get("usage", {}).get("total_tokens", 0),
                        elapsed_attempt,
                        f" error={error_txt.splitlines()[0]}" if error_txt else "",
                    )

                    attempt_payload = {
                        "attempt": attempt_idx + 1,
                        "wall_sec": elapsed_attempt,
                        "exact_match": score_result["exact_match"],
                        "contains_answer": score_result["contains_answer"],
                        "solved_primary": solved,
                        "error": error_txt,
                        "run": result_dict,
                    }
                    attempt_details.append(attempt_payload)
                    (attempt_dir / "run.json").write_text(
                        json.dumps(attempt_payload, indent=2),
                        encoding="utf-8",
                    )

                c = sum(1 for x in successes if x)
                pass_k = pass_at_k_unbiased(attempts, c, attempts)
                pass_1 = pass_at_k_unbiased(attempts, c, 1)
                pass_3 = pass_at_k_unbiased(attempts, c, 3) if attempts >= 3 else None
                first_ok = 1.0 if successes and successes[0] else 0.0

                metrics_records.append({
                    "task_id": task.task_id,
                    "agent": agent_key,
                    "attempts_configured": attempts,
                    "environment_status": "ok" if env_ok else "no_live_target",
                    "paths_available": bool(hybrid_paths and hybrid_paths.exists()),
                    "path_count": path_count if agent_key == "hybrid_reasoner_agent" else 0,
                    "paths_generation": paths_meta if agent_key == "hybrid_reasoner_agent" else {},
                    "attempt_details": attempt_details,
                    "correct_attempts": c,
                    "pass_at_k": pass_k,
                    "pass_at_1": pass_1,
                    "pass_at_3": pass_3,
                    "tokens_total": tokens_total,
                    "tool_calls": tool_calls_total,
                    "k": attempts,
                    "pass_at_1_first_attempt": first_ok,
                    "total_wall_sec": round(time.time() - session_wall_start, 4),
                })

        finally:
            session.stop()
            if sanitized_source_dir is not None:
                shutil.rmtree(sanitized_source_dir.parent, ignore_errors=True)

    summary = _build_summary(metrics_records, attempts, len(tasks), infrastructure_failed_tasks)
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    metrics_json_path = run_dir / "metrics.json"
    metrics_json_path.write_text(json.dumps(metrics_records, indent=2), encoding="utf-8")

    csv_path = run_dir / "metrics.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=METRICS_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in metrics_records:
            writer.writerow({
                "task_id": row["task_id"],
                "agent": row["agent"],
                "attempts_configured": row["attempts_configured"],
                "correct_attempts": row["correct_attempts"],
                "pass_at_k": row["pass_at_k"],
                "k": row["k"],
                "pass_at_1_first_attempt": row["pass_at_1_first_attempt"],
                "pass_at_1": row.get("pass_at_1"),
                "pass_at_3": row.get("pass_at_3"),
                "tokens_total": row.get("tokens_total", 0),
                "tool_calls": row.get("tool_calls", 0),
                "environment_status": row["environment_status"],
                "paths_available": row.get("paths_available", False),
                "path_count": row.get("path_count", 0),
                "total_wall_sec": row.get("total_wall_sec", 0),
            })

    logging.info("Done. Summary: %s", json.dumps(summary, indent=2))
    logging.info("Results: %s", run_dir)

    return {"run_dir": str(run_dir), "manifest": manifest, "summary": summary, "metrics": metrics_records}


def _build_summary(
    records: List[Dict[str, Any]],
    k: int,
    task_count: int,
    infra_failed: int,
) -> Dict[str, Any]:
    by_agent: Dict[str, Dict[str, Any]] = {}
    for row in records:
        agent = row["agent"]
        bucket = by_agent.setdefault(agent, {
            "pass_at_k_sum": 0.0, "rows": 0, "first_sum": 0.0,
            "pass_at_1_sum": 0.0, "pass_at_3_sum": 0.0, "pass_at_3_rows": 0,
            "tokens_sum": 0, "tool_calls_sum": 0,
        })
        bucket["pass_at_k_sum"] += float(row.get("pass_at_k", 0.0))
        bucket["first_sum"] += float(row.get("pass_at_1_first_attempt", 0.0))
        bucket["pass_at_1_sum"] += float(row.get("pass_at_1") or 0.0)
        if row.get("pass_at_3") is not None:
            bucket["pass_at_3_sum"] += float(row["pass_at_3"])
            bucket["pass_at_3_rows"] += 1
        bucket["tokens_sum"] += int(row.get("tokens_total", 0) or 0)
        bucket["tool_calls_sum"] += int(row.get("tool_calls", 0) or 0)
        bucket["rows"] += 1

    agents_summary: Dict[str, Any] = {}
    for agent, bucket in by_agent.items():
        n = bucket["rows"]
        n3 = bucket["pass_at_3_rows"]
        mean_pass = round(bucket["pass_at_k_sum"] / n, 4) if n else 0.0
        mean_first = round(bucket["first_sum"] / n, 4) if n else 0.0
        mean_pass_1 = round(bucket["pass_at_1_sum"] / n, 4) if n else 0.0
        mean_pass_3 = round(bucket["pass_at_3_sum"] / n3, 4) if n3 else None
        agents_summary[agent] = {
            "mean_pass_at_k": mean_pass,
            "k": k,
            "mean_pass_at_1_first_attempt": mean_first,
            "mean_pass_at_1": mean_pass_1,
            "mean_pass_at_3": mean_pass_3,
            "tokens_total": bucket["tokens_sum"],
            "tool_calls_total": bucket["tool_calls_sum"],
            "record_rows": n,
        }

    return {
        "task_count": task_count,
        "metrics_rows": len(records),
        "infrastructure_failed_tasks_estimate": infra_failed,
        "definition": (
            "pass_at_k per task uses unbiased estimator 1 - C(n-c,k)/C(n,k) with n=c attempts; "
            "for n=k this equals 1 if any attempt solves else 0. Mean is across evaluated tasks."
        ),
        "agents": agents_summary,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyBench-style agent solve benchmark (pass@k)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--cybench-root", type=Path, default=DEFAULT_CYBENCH_ROOT)
    parser.add_argument("--inventory-csv", type=Path, default=DEFAULT_INVENTORY_CSV)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--agents", type=str, default="web_pentester_agent,hybrid_reasoner_agent",
                        help="Comma-separated agent keys: redteam_agent, web_pentester_agent, "
                             "raw_scanner_agent, hybrid_reasoner_agent")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--max-turns", type=int, default=50)
    parser.add_argument("--model", type=str, default=None,
                        help="Override CAI model for both agents (recommended for fair comparison)")
    parser.add_argument("--compose-up-timeout-sec", type=int, default=180)
    parser.add_argument("--nmap-profile", choices=["full", "fast"], default="full")
    parser.add_argument("--reuse-graphs", action="store_true",
                        help="Reuse paths.json in graphs/ if present")
    parser.add_argument(
        "--precomputed-graphs-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Directory of precomputed paths.json files, one per task_id subdirectory "
            "(e.g. benchmarking/data/graphs/). When set and a paths.json is present for "
            "a task, it is used directly instead of running live graph generation."
        ),
    )
    parser.add_argument("--max-tasks", type=int, default=None)
    parser.add_argument("--task-id", action="append", default=None,
                        help="Filter by task_id (repeatable)")
    parser.add_argument("--run-task-requirements", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--ollama",
        action="store_true",
        help=(
            "Use Ollama via CAI (sets OLLAMA=true). If OLLAMA_API_BASE is unset, defaults to "
            "http://127.0.0.1:11434/v1 (local ollama serve)."
        ),
    )
    parser.add_argument(
        "--ollama-api-base",
        type=str,
        default=None,
        metavar="URL",
        help=(
            "OpenAI-compatible Ollama base URL ending in /v1 (e.g. local "
            "http://127.0.0.1:11434/v1 or cloud https://host:443/v1). Sets OLLAMA_API_BASE and "
            "enables Ollama mode."
        ),
    )

    args = parser.parse_args()

    if not args.cybench_root.exists():
        print(f"CyBench root not found: {args.cybench_root}", file=sys.stderr)
        sys.exit(1)

    agents = _parse_agents(args.agents)
    model = args.model or __import__("os").environ.get("CAI_MODEL", "alias1")

    ollama_applied: Dict[str, str] = {}
    if args.ollama or args.ollama_api_base:
        ollama_applied = apply_ollama_cli_to_environ(
            enable=args.ollama,
            api_base=args.ollama_api_base,
        )

    setup_logging(args.verbose)

    run_evaluation(
        cybench_root=args.cybench_root.resolve(),
        inventory_csv=args.inventory_csv.resolve(),
        results_dir=args.results_dir.resolve(),
        agents=agents,
        attempts=args.attempts,
        max_turns=args.max_turns,
        model=model,
        compose_timeout=args.compose_up_timeout_sec,
        nmap_profile=args.nmap_profile,
        reuse_graphs=args.reuse_graphs,
        precomputed_graphs_dir=args.precomputed_graphs_dir.resolve() if args.precomputed_graphs_dir else None,
        max_tasks=args.max_tasks,
        task_ids_filter=args.task_id,
        run_requirements=args.run_task_requirements,
        verbose=args.verbose,
        ollama_runtime=ollama_applied or None,
    )


if __name__ == "__main__":
    main()
