#!/usr/bin/env bash
set -euo pipefail

# Canonical benchmark entrypoint: always run full web benchmark with all scanners.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

if [[ ! -f ".venv/bin/activate" ]]; then
  echo "[!] Missing virtual environment at .venv. Create it before running benchmark." >&2
  exit 1
fi

# Prune dangling images, stopped containers, and unused networks on exit,
# whether the run completes normally or is interrupted (Ctrl-C, error, kill).
_docker_cleanup() {
  echo "[benchmark] Running post-run Docker cleanup..."
  docker system prune -f --filter "label=com.docker.compose.project" 2>/dev/null || true
  docker image prune -f 2>/dev/null || true
  docker network prune -f 2>/dev/null || true
  echo "[benchmark] Docker cleanup complete."
}
trap _docker_cleanup EXIT

source .venv/bin/activate

python3 benchmarking/run_benchmark.py \
  --cybench-root ../cybench \
  --scanners trivy,semgrep,nmap \
  --nmap-profile full \
  --with-task-environment \
  --run-task-requirements \
  --compose-up-timeout-sec 180 \
  --results-dir benchmarking/results/attack_graph_quality \
  --verbose
