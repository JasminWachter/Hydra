# Benchmarking

Benchmarking uses **two separate tracks** under `benchmarking/`:

| Track | Path | Measures |
|--------|------|-----------|
| Attack-graph quality | [`benchmarking/run_benchmark.py`](run_benchmark.py) + [`attack_graph_quality/metrics.py`](attack_graph_quality/metrics.py) | MulVAL graph usefulness vs inventory ground-truth (`paths.json`, vuln coverage, goal reachability) |
| Agent solve evaluation | [`agent_solve_evaluation/`](agent_solve_evaluation/README.md) | CAI agents solving live CyBench web tasks with CyBench-aligned scoring (pass@k) |

Shared inputs:

- [`data/web_ctf_inventory.csv`](data/web_ctf_inventory.csv) — 54 web tasks (`task_path` column points into CyBench)
- [`runner/`](runner/) and [`containers/`](containers/) — Docker compose + MulVAL pipeline infrastructure used by both tracks where relevant

## Run Full Attack-Graph Benchmark

From repository root:

```bash
./benchmarking/run_full_benchmark.sh
```

## Attack-graph configurable run

```bash
source .venv/bin/activate
python3 benchmarking/run_benchmark.py \
  --cybench-root ../cybench \
  --scanners trivy,semgrep,nmap \
  --nmap-profile full \
  --run-task-requirements \
  --compose-up-timeout-sec 180 \
  --results-dir benchmarking/results/attack_graph_quality \
  --max-tasks 10 \
  --verbose
```

Graph metric definitions live in [`attack_graph_quality/metrics.py`](attack_graph_quality/metrics.py).

## Agent solve evaluation (quick sample)

```bash
python3 benchmarking/agent_solve_evaluation/run_evaluation.py \
  --cybench-root ../cybench \
  --results-dir benchmarking/results/agent_solve_evaluation \
  --attempts 3 \
  --max-tasks 2 \
  --model <your_model_id>
```

## Tests

```bash
python3 -m unittest discover -s benchmarking/tests -p "test_*.py"
```
