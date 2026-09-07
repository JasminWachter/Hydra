#!/usr/bin/env bash
# Sequentially serves each model via Ollama's official Docker image (single-GPU box: one
# model at a time) and runs the agent_solve_evaluation benchmark against it. Serving runs
# in Docker (not a bare host install) so the pre-built, version-matched CUDA toolchain in
# the image is used instead of relying on host CUDA dev packages. Usage:
#   ./run_model_sweep.sh              # all models
#   ./run_model_sweep.sh gpt-oss:120b # single model (smoke test / retry)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

OLLAMA_IMAGE="ollama/ollama:latest"
OLLAMA_PORT=8001
OLLAMA_BASE_URL="http://127.0.0.1:${OLLAMA_PORT}/v1"
# Single-GPU, sequential sweep: only ever one model loaded, one request in flight at a
# time — same rationale as vLLM's old MAX_NUM_SEQS=64, expressed via Ollama's server env
# vars instead of a CLI flag.
OLLAMA_MAX_LOADED_MODELS=1
OLLAMA_NUM_PARALLEL=1
# Ollama's default keep_alive unloads an idle model after 5 minutes; a 50-turn, 3-attempt,
# 3-agent eval run can easily leave >5min gaps between calls to a given model. Force the
# model to stay resident in VRAM for the whole run (vLLM never unloaded mid-run either).
OLLAMA_KEEP_ALIVE=-1
# OOM fallback lever, analogous to vLLM's old --cpu-offload-gb: shrink the KV cache
# footprint instead of offloading weights. Ollama auto-manages GPU/CPU layer placement —
# there's no direct equivalent to --gpu-memory-utilization to tune directly.
OLLAMA_KV_CACHE_TYPE_FALLBACK="q8_0"
HEALTH_TIMEOUT_SEC=1800
RESULTS_ROOT="benchmarking/results/agent_solve_evaluation"
AGENTS="redteam_agent,raw_scanner_agent,hybrid_reasoner_agent"
# Passthrough for extra run_evaluation.py flags, e.g. `--task-id X --task-id Y` to resume
# only specific tasks after an interrupted run (leave empty for a normal full sweep).
EXTRA_EVAL_ARGS="${EXTRA_EVAL_ARGS:-}"
# Attack-graph generation (MulVAL/nmap scan of the live target) is model-independent, so a
# graph computed once under any model/run is valid for every other model/run. Cache it in
# a stable, non-timestamped dir (unlike RESULTS_ROOT's per-run dirs) and pass it to every
# invocation so already-solved tasks skip live graph generation entirely.
GRAPHS_CACHE_DIR="${REPO_ROOT}/benchmarking/data/graphs"
# Store model data in a Docker-managed named volume to avoid coupling
# execution to a host-specific file system path and to support cleanup.
OLLAMA_VOLUME_PREFIX="hydra-ollama-data"
# Use involcation-specific resource names to prevent concurrent runs from colliding.
RUN_UID="${RUN_UID:-$$}"

MODEL_TAGS=(qwen3.6:35b-a3b gpt-oss:120b gemma4:31b)
# Per-model extra `docker run -e ...` overrides for the *first* launch attempt (empty by
# default — start conservative, let the OOM-fallback tier in run_one_model() add
# OLLAMA_KV_CACHE_TYPE=q8_0 if/when a model doesn't fit).
MODEL_EXTRA_ENV=("" "" "")

ONLY_TAG="${1:-}"
CONTAINER_NAME=""

# Cheap, container-daemon-only check — Ollama's HTTP server answers immediately once
# `ollama serve` is up, independent of any model being pulled/loaded.
wait_for_daemon() {
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if curl -sf "http://127.0.0.1:${OLLAMA_PORT}/api/tags" >/dev/null 2>&1; then
      return 0
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
      return 1  # container exited
    fi
    sleep 2
  done
  return 1  # timed out
}

# Ollama's entrypoint already runs `ollama serve`, so pulling happens against the
# already-serving container rather than being baked into the launch itself.
pull_model() {
  local tag="$1"
  for attempt in 1 2 3; do
    if docker exec "$CONTAINER_NAME" ollama pull "$tag"; then
      return 0
    fi
    echo "=== [$tag] pull attempt ${attempt}/3 failed, retrying in 30s ===" >&2
    sleep 30
  done
  return 1
}

start_ollama() {
  local extra_env="$1"
  # shellcheck disable=SC2086
  docker run -d --name "$CONTAINER_NAME" \
    --gpus all \
    -p "${OLLAMA_PORT}:11434" \
    -v "${OLLAMA_VOLUME}:/root/.ollama" \
    -e OLLAMA_MAX_LOADED_MODELS="$OLLAMA_MAX_LOADED_MODELS" \
    -e OLLAMA_NUM_PARALLEL="$OLLAMA_NUM_PARALLEL" \
    -e OLLAMA_KEEP_ALIVE="$OLLAMA_KEEP_ALIVE" \
    $extra_env \
    "$OLLAMA_IMAGE" \
    > /dev/null
}
#Note that --gpus all assumes NVIDIA Docker support

stop_ollama() {
  docker logs "$CONTAINER_NAME" > "${LOG_DIR}/ollama_serve.log" 2>&1 || true
  docker rm -f "$CONTAINER_NAME" > /dev/null 2>&1 || true
  sleep 3
}

free_ollama_volume() {
  docker volume rm -f "$OLLAMA_VOLUME" > /dev/null 2>&1 || true
}

# Forces the model to actually load into VRAM now (Ollama lazy-loads on first request by
# default) so an OOM-on-load is caught here rather than mid-eval. Also doubles as a
# tool-calling smoke test: Ollama has no --tool-call-parser flag to get wrong, but its
# bundled per-model chat template can still fail to emit structured tool_calls (vLLM only
# discovered Qwen3.6's non-standard tool-call format by inspecting a real transcript —
# this is the same class of risk under a different mechanism).
warm_up_and_verify() {
  local tag="$1"
  local resp_file="${LOG_DIR}/warmup_response.json"
  if ! curl -sf --max-time "$HEALTH_TIMEOUT_SEC" \
      -X POST "http://127.0.0.1:${OLLAMA_PORT}/v1/chat/completions" \
      -H 'Content-Type: application/json' \
      -d "$(jq -n --arg m "$tag" '{
            model: $m,
            messages: [{role:"user", content:"Call get_time to answer: what is the current UTC time?"}],
            tools: [{type:"function", function:{name:"get_time", description:"Get current UTC time", parameters:{type:"object", properties:{}}}}],
            tool_choice: "required",
            keep_alive: -1
          }')" \
      -o "$resp_file"; then
    echo "=== [$tag] warm-up request failed/timed out (likely OOM on load) ===" >&2
    return 1
  fi
  if ! jq -e '.choices[0].message.tool_calls | length > 0' "$resp_file" >/dev/null 2>&1; then
    echo "=== [$tag] WARNING: warm-up succeeded but response has NO structured tool_calls" \
         "— inspect ${resp_file} by hand before trusting this model's eval results" \
         "(this is the exact failure mode that broke Qwen3.6 under vLLM) ===" >&2
    touch "${LOG_DIR}/TOOLCALL_WARNING"
  fi
  return 0
}

# Copies any paths.json this run computed live (i.e. wasn't already in the cache) into
# GRAPHS_CACHE_DIR, keyed by task_id, so later models in the sweep (and future re-runs)
# reuse it instead of re-scanning the live target.
sync_graphs_cache() {
  local run_tasks_dir="$1"
  [[ -d "$run_tasks_dir" ]] || return 0
  local task_dir task_id dest
  for task_dir in "$run_tasks_dir"/*/; do
    task_id="$(basename "$task_dir")"
    if [[ -f "${task_dir}graphs/paths.json" ]]; then
      dest="${GRAPHS_CACHE_DIR}/${task_id}"
      if [[ ! -f "${dest}/paths.json" ]]; then
        mkdir -p "$dest"
        cp "${task_dir}graphs/paths.json" "${dest}/paths.json"
      fi
    fi
  done
}

run_one_model() {
  local tag="$1" extra_env="$2"
  LOG_DIR="${RESULTS_ROOT}/${tag//[:\/]/_}"
  mkdir -p "$LOG_DIR"
  CONTAINER_NAME="ollama-${tag//[:\/]/_}-${RUN_UID}"

  OLLAMA_VOLUME="${OLLAMA_VOLUME_PREFIX}-${tag//[:\/]/_}-${RUN_UID}"
  docker volume create "$OLLAMA_VOLUME" > /dev/null
  trap 'echo "=== [$tag] freeing volume ${OLLAMA_VOLUME} ==="; free_ollama_volume' RETURN

  echo "=== [$tag] starting Ollama container ==="
  start_ollama "$extra_env"
  if ! wait_for_daemon; then
    echo "=== [$tag] ollama daemon never came up — skipping ===" >&2
    stop_ollama
    return 1
  fi

  echo "=== [$tag] pulling ${tag} ==="
  if ! pull_model "$tag"; then
    echo "=== [$tag] pull failed after 3 attempts — skipping ===" >&2
    stop_ollama
    return 1
  fi

  echo "=== [$tag] warming up + tool-call smoke test ==="
  if ! warm_up_and_verify "$tag"; then
    echo "=== [$tag] retrying with OLLAMA_KV_CACHE_TYPE=${OLLAMA_KV_CACHE_TYPE_FALLBACK} ==="
    stop_ollama
    start_ollama "${extra_env} -e OLLAMA_KV_CACHE_TYPE=${OLLAMA_KV_CACHE_TYPE_FALLBACK}"
    if ! wait_for_daemon || ! warm_up_and_verify "$tag"; then
      echo "=== [$tag] warm-up failed again even with quantized KV cache — skipping ===" >&2
      stop_ollama
      return 1
    fi
  fi

  echo "=== [$tag] ollama healthy, running evaluation — progress: tail -f ${LOG_DIR}/eval_progress.log ==="
  PYTHON_BIN="${PYTHON_BIN:-python3}"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-sk-1234}"
  # shellcheck disable=SC2086
  CYBENCH_ROOT="${CYBENCH_ROOT:-../cybench}"
  "$PYTHON_BIN" -u benchmarking/agent_solve_evaluation/run_evaluation.py \
    --cybench-root "$CYBENCH_ROOT" \
    --ollama-api-base "$OLLAMA_BASE_URL" \
    --model "$tag" \
    --agents "$AGENTS" \
    --attempts 3 \
    --max-turns 50 \
    --results-dir "${RESULTS_ROOT}/${tag//[:\/]/_}" \
    --precomputed-graphs-dir "$GRAPHS_CACHE_DIR" \
    $EXTRA_EVAL_ARGS \
    2>&1 | tee -a "${LOG_DIR}/eval_progress.log"
  local eval_status=${PIPESTATUS[0]}

  local run_dir
  run_dir="$(ls -td "${RESULTS_ROOT}/${tag//[:\/]/_}"/run_*/ 2>/dev/null | head -1)"
  sync_graphs_cache "${run_dir}tasks"

  echo "=== [$tag] stopping Ollama container ==="
  stop_ollama

  return $eval_status
}

mkdir -p "$GRAPHS_CACHE_DIR"

overall_status=0
for i in "${!MODEL_TAGS[@]}"; do
  tag="${MODEL_TAGS[$i]}"
  extra_env="${MODEL_EXTRA_ENV[$i]}"
  if [[ -n "$ONLY_TAG" && "$tag" != "$ONLY_TAG" ]]; then
    continue
  fi
  if ! run_one_model "$tag" "$extra_env"; then
    echo "=== [$tag] FAILED — continuing with next model ===" >&2
    overall_status=1
  fi
done

exit $overall_status
