# MulVAL Execution Pipeline

Scanner → predicate → MulVAL attack graph pipeline used by the benchmark and hybrid reasoning flow.

## Entry Point

```bash
python3 generate_predicates.py --target /path/to/target --output ./graphs
```

`UnifiedPipeline` in `generate_predicates.py` orchestrates the four stages:

1. **Scanner execution** — runs trivy, semgrep, nmap via `ScannerExecutor`
2. **Predicate generation** — parsers convert scanner outputs to Prolog facts; `AppFeatureExtractor` adds static source-derived predicates; `PredicateAggregator` writes `input_predicates.P`
3. **MulVAL execution** — local XSB/MulVAL, with a Docker fallback, evaluates predicates against interaction rules
4. **Trace processing** — `TraceProcessor` converts `trace_output.P` → `paths.json`

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | *(required)* | Target directory to scan |
| `--output` | `./graphs` | Output directory |
| `--host` | `localhost` | Host identifier for predicates |
| `--scanners` | `trivy,semgrep` | Comma-separated scanner list |
| `--nmap-profile` | `full` | `full` or `fast` |
| `--nmap-ports` | — | Explicit port list (e.g. `80,443,8080`) |
| `--skip-scanning` | — | Use existing scan results |
| `--force-rescan` | — | Re-run scanners even if results exist |
| `--trivy-json` / `--nmap-xml` / `--semgrep-json` | — | Paths to existing scan outputs |
| `--skip-mulval` | — | Stop after predicate generation |
| `--rules` | `kb/web_security_rules.P` | Override interaction rules file |
| `--no-report` | — | Skip `scan_summary.txt` generation |

## Architecture

```
generate_predicates.py (UnifiedPipeline)
├── scanner_executor.py        runs trivy / semgrep / nmap
├── parsers/
│   ├── base_parser.py         Predicate, ScannerStrategy (ABC), PredicateAggregator
│   ├── scanner_strategy_factory.py  creates strategy instances by name
│   ├── trivy_parser_strategy.py     CVEs, misconfigurations → vuln_exists(...)
│   ├── nmap_parser_strategy.py      open ports/services → connects(...), service(...)
│   ├── semgrep_parser_strategy.py   code patterns → detected_vuln(...)
│   └── app_feature_extractor.py     config-driven static source feature extraction
├── mulval_executor.py         local XSB/MulVAL execution with Docker fallback
├── trace_processor.py         trace_output.P → paths.json
└── report_generator.py        scan_summary.txt
```

## Rules

| File | Use |
|------|-----|
| `kb/web_security_rules.P` | **Default KB** — 124 web-focused rules across the kill chain |
| `kb/full_post_exploit_rules.P` | Curated MITRE post-exploitation subset (future work — not loaded; see below) |
| `kb/full_interaction_rules.P` | 533 MITRE ATT&CK techniques (auto-generated, do not edit) |

`web_security_rules.P` is used **on its own** by default; `full_post_exploit_rules.P` is intentionally
not combined (appending it breaks MulVAL derivation). Pass `--rules kb/full_interaction_rules.P` to
override with the full MITRE rule set instead.

See **[`kb/README.md`](kb/README.md)** for the full rule inventory: the Semgrep evidence tiers, the
input-predicate vocabulary, the 12-stage kill chain, and the per-class coverage matrix.

## Output

```
graphs/
├── input_predicates.P          MulVAL input (Prolog facts)
├── trace_output.P              raw MulVAL trace
├── trace_output_attackgraph.P  attack-graph-compatible trace
├── AttackGraph.pdf             visual attack graph
├── paths.json                  structured attack paths for downstream use
├── scan_summary.txt            human-readable scan report
└── scan_results/
    ├── trivy_results.json
    ├── semgrep_results.json
    └── nmap_results.xml
```
