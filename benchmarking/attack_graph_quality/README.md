# Attack graph quality benchmark

Evaluates **MulVAL attack-graph generation quality** on the CyBench web challenges listed in
[`../data/web_ctf_inventory.csv`](../data/web_ctf_inventory.csv).

Metric implementations live here (`metrics.py`). The **runner CLI** is the repository script
[`benchmarking/run_benchmark.py`](../run_benchmark.py) at the parent directory.

## Run

From the Hydra repository root (with `.venv` activated if you use it):

```bash
python3 benchmarking/run_benchmark.py \
  --cybench-root ../cybench \
  --results-dir benchmarking/results/attack_graph_quality \
  --verbose
```

Or use `./benchmarking/run_full_benchmark.sh`.

## Outputs

Under `--results-dir/run_<timestamp>/`:

- `manifest.json`, `summary.json`, `metrics.json`, `metrics.csv`
- `tasks/<task_id>/` — `paths.json`, scans, predicates

See [`metrics.py`](metrics.py) for metric definitions (`goal_reachability`, vulnerability coverage vs `required_vulns`, noise paths).
