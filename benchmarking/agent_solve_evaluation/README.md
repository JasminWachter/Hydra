# Agent solve evaluation

Evaluates **CAI agents** against live CyBench web challenges using the same 54-task inventory as the attack-graph track (`benchmarking/data/web_ctf_inventory.csv`). Compare `redteam_agent` vs `hybrid_reasoner_agent` and aggregate **pass@k** (default pass@3 with `--attempts 3`).

## Prerequisites

- CyBench sibling checkout at `<Hydra>/../cybench` (override with `--cybench-root`).
- Docker available for tasks that use compose (same infra as `../runner`).
- A CAI model backend: cloud APIs via `.env` / keys, or **Ollama** (local or remote).

### Ollama (local or cloud)

CAI reads `OLLAMA` and `OLLAMA_API_BASE` (OpenAI-compatible URL ending in `/v1`). The evaluation entrypoint can set them for you:

- **Local** (`ollama serve` on this machine, default port 11434): pass `--ollama`. If `OLLAMA_API_BASE` is not already set, it defaults to `http://127.0.0.1:11434/v1`.
- **Cloud / remote host**: pass `--ollama-api-base 'https://your-host/v1'` (implies Ollama mode). You can instead export `OLLAMA=true` and `OLLAMA_API_BASE` yourself and omit these flags.

Pin a model name your server provides, e.g. `--model llama3.1`. The resolved Ollama settings are copied into `manifest.json` under `ollama_runtime` when you use the CLI flags.

For local-model evaluation without external trace export, set both tracing
controls. They affect separate tracing paths:

```bash
export CAI_TRACING=false
export OPENAI_AGENTS_DISABLE_TRACING=true
```

`CAI_TRACING=false` alone does not disable the bundled Agents SDK exporter.

### Docker-served Ollama sweep (GPU)

`benchmarking/scripts/run_model_sweep.sh` serves a fixed set of large local models one at a time via a Docker-run `ollama/ollama` container (single-GPU box, so only one model is ever loaded) and runs this evaluation against each in turn. It pulls the model, verifies it via a real tool-calling warm-up request (retrying with a quantized KV cache if the warm-up OOMs), runs the eval, then tears the container down and frees the pulled model's disk space before moving to the next one.

Attack-graph generation (MulVAL/nmap scan of the live target) is model-independent, so the sweep passes `--precomputed-graphs-dir benchmarking/data/graphs` to every eval run and copies any newly-computed `paths.json` back into that shared cache afterward — a task's graph is only ever computed once across the whole sweep (and across re-runs), not once per model.

```bash
./benchmarking/scripts/run_model_sweep.sh              # all models
./benchmarking/scripts/run_model_sweep.sh gpt-oss:120b  # single model (smoke test / retry)
```

Per-model logs land under `benchmarking/results/agent_solve_evaluation/<tag>/`:
- `ollama_serve.log` — container logs
- `eval_progress.log` — live evaluation output
- `warmup_response.json` — the tool-calling warm-up request/response
- `TOOLCALL_WARNING` — **present only if the warm-up response had no structured `tool_calls`**; if you see this file, manually inspect `warmup_response.json` before trusting that model's results — it means the model's chat template may not be emitting tool calls Ollama can parse.

## Run

From Hydra repo root:

```bash
python3 benchmarking/agent_solve_evaluation/run_evaluation.py \
  --cybench-root ../cybench \
  --results-dir benchmarking/results/agent_solve_evaluation \
  --agents redteam_agent,hybrid_reasoner_agent \
  --attempts 3 \
  --max-turns 50 \
  --model openai/gpt-4o \
  --max-tasks 2 \
  --verbose
```

Local Ollama example:

```bash
python3 benchmarking/agent_solve_evaluation/run_evaluation.py \
  --cybench-root ../cybench \
  --ollama \
  --model llama3.1 \
  --max-tasks 1 \
  --verbose
```

Remote Ollama (replace host and model):

```bash
python3 benchmarking/agent_solve_evaluation/run_evaluation.py \
  --cybench-root ../cybench \
  --ollama-api-base 'https://ollama.example.org:443/v1' \
  --model llama3.1 \
  --max-tasks 1 \
  --verbose
```

## Outputs

Under `--results-dir/run_<timestamp>/`:

- `manifest.json`, `summary.json`, `metrics.json`, `metrics.csv`
- `tasks/<task_id>/graphs/paths.json` (when hybrid is evaluated — MulVAL input)
- `tasks/<task_id>/agents/<agent>/attempt_<n>/run.json`

## Scoring

Ground truth is the **final CyBench subtask answer** (unguided flag). Primary solve criterion matches CyBench-style grading: **exact** equality against either the full transcript tail or a single output line (`benchmarking/agent_solve_evaluation/scoring.py`). `contains_answer` is logged for debugging only.

Agents are never given the real `cybench` checkout path as `source_dir` — the harness's own `metadata/metadata.json` read (for scoring) is separate from what agents can reach: each task gets a sanitized copy (`_make_sanitized_source_dir` in `run_evaluation.py`) with `metadata/` stripped and the ground-truth answer string redacted out of any other file (this dataset's `README.md` ships the identical flag in plaintext). Without this, agents can just read the flag off disk instead of exploiting the live target.
