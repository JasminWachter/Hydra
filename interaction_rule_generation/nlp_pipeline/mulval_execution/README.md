# MulVAL Attack Graph Generation Pipeline

This pipeline generates attack graphs from MITRE ATT&CK-based Prolog rules and OSINT data using the prebuilt MulVAL Docker image.

Note: this directory documents the rule-generation validation workflow.
For benchmark/runtime execution defaults, see `MulVAL/README.md` (default: `kb/web_security_rules.P`).

## Scripts Overview

### run.sh

Single execution script for generating attack graphs from one input file.

**Usage:**

```bash
bash run.sh [INPUT_FILE] [OPTIONS]
```

**Behavior:**

- Uses cached MulVAL Docker image by default (wilbercui/mulval)
- Creates timestamped output directory: `graphs/run_<basename>_YYYYMMDD_HHMMSS/`
- Runs MulVAL graph generation inside Docker container
- Measures execution time
- Validates and analyzes attack paths using extract_attack_graph.py
- Generates JSON and summary outputs with timing information

**Default values:**

- Input: `../osint_output/mock_osint.P`
- Rules: `../kb/full_interaction_rules.P`

**Options:**

- `--pull`: Force pull latest MulVAL Docker image (or set `MULVAL_PULL=true`)
- `--rules <file>`: Use custom interaction rules file

### test.sh

Automated test suite runner for validating MulVAL against multiple test cases.

**Usage:**

```bash
bash test.sh [PATTERN]
```

**Behavior:**

- Uses cached MulVAL Docker image by default
- Finds all test files matching pattern in `osint_output/` directory
- Runs each test through MulVAL with full interaction rules
- Creates timestamped output: `graphs/test_<name>_YYYYMMDD_HHMMSS/`
- Validates attack paths and generates reports for each test
- Reports pass/fail statistics

**Default pattern:** `test_*.P` (runs all 8 test files)

**Options:**

- Set `MULVAL_PULL=true` to force pull latest Docker image before testing

### extract_attack_graph.py

Python script that validates and converts MulVAL trace output to human-readable and JSON formats.

**Usage:**

```bash
python3 extract_attack_graph.py <trace_output.P> [--json output.json] [--time DURATION]
```

**Behavior:**

- Parses trace_output.P for attack derivation steps
- Validates that attack paths were found (exits with code 1 if none found)
- Generates simplified summary focusing on the shortest attack path
- Displays attack chain step-by-step with prerequisite conditions
- Shows technique usage statistics
- Includes generation time in summary if provided
- Optionally generates structured JSON graph

**Exit codes:**

- `0`: Success (attack paths found)
- `1`: No attack paths found
- `2`: Error parsing trace file

**Output formats:**

- Text: Simplified attack chain analysis with shortest path highlighted
- JSON: Structured graph with nodes, edges, paths, shortest paths (BFS), and technique summaries

### clean_graphs.sh

Utility script to remove generated graph directories.

**Usage:**

```bash
bash clean_graphs.sh
```

**Behavior:**

- Removes all `graphs/test_*/` directories (test runs)
- Removes all `graphs/run_*/` directories (single runs)
- Preserves other files in graphs/ directory

## Full Pipeline

### 1. Generate Knowledge Base

First, generate the complete knowledge base from MITRE ATT&CK techniques:

```bash
cd MulVaL/AttackAutomatedRuleBase
python generate_full_kb.py
```

### 2. Run MulVAL Attack Graph Generation

#### Quick Start (Default Input)

Execute the automated pipeline with the default mock OSINT data:

```bash
cd mulval_execution
bash run.sh
```

**What happens:**

1. Uses cached `wilbercui/mulval:latest` Docker image (contains MulVAL v1.0 + XSB 3.6)
2. Creates timestamped output directory: `graphs/run_mock_osint_YYYYMMDD_HHMMSS/`
3. Measures execution time
4. Runs MulVAL's `graph_gen.sh` with:
    - Input facts: `osint_output/mock_osint.P` (default)
    - Rules: `kb/full_interaction_rules.P` (533 MITRE ATT&CK techniques)
    - Output: `trace_output.P`, `xsb_log.txt`
5. Validates and analyzes attack paths with `extract_attack_graph.py`
6. Generates JSON graph and human-readable summary with timing information

**Outputs:**

- `AttackGraph.json` - Complete graph structure (nodes, edges, paths, techniques)
- `AttackGraph_Summary.txt` - Simplified attack path analysis with execution time
- `trace_output.P` - Raw MulVAL trace output
- `xsb_log.txt` - XSB Prolog execution log

#### Custom Input Predicates File

Simply pass your input file as an argument:

```bash
# Run with a custom OSINT file
bash run.sh ../osint_output/corporate_network.P

# Run with custom rules file
bash run.sh ../osint_output/simple_webapp.P --rules ../kb/custom_rules.P

# Force pull latest Docker image
bash run.sh ../osint_output/corporate_network.P --pull

# Or use environment variable
MULVAL_PULL=true bash run.sh ../osint_output/corporate_network.P

# List available input files
ls ../osint_output/*.P
```

#### Run Test Suite

To validate MulVAL setup and test all scenarios:

```bash
# Run all tests
bash test.sh

# Run specific test pattern
bash test.sh "test_01*"

# Run tests 1-3
bash test.sh "test_0[1-3]*"
```

#### Manual Docker Command

For full control, use Docker directly from the AttackAutomatedRuleBase directory:

```bash
docker run --rm -it \
  -v "$(pwd)":/data \
  -w /data \
  wilbercui/mulval \
  graph_gen.sh osint_output/my_scan.P -r kb/full_interaction_rules.P -v
```
