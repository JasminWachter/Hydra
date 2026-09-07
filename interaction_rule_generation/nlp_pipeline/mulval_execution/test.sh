#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OSINT_DIR="$DATA_DIR/osint_output/test"
GRAPHS_DIR="$DATA_DIR/graphs"
GENERATE_SCRIPT="$SCRIPT_DIR/generate_attack_paths.py"

TEST_PATTERN="${1:-test_*.P}"
RULES_FILE="kb/full_interaction_rules.P"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
ERROR_TESTS=0

declare -a PASSED_LIST
declare -a FAILED_LIST
declare -a ERROR_LIST

echo "==========================================================================="
echo "MulVAL OSINT Test Suite Runner"
echo "==========================================================================="
echo ""
echo "Test directory: $OSINT_DIR"
echo "Test pattern:   $TEST_PATTERN"
echo "Rules file:     $DATA_DIR/$RULES_FILE"
echo ""

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker CLI not found. Please install Docker and ensure 'docker' is on PATH."
    exit 1
fi

# Ensure Docker daemon is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon does not appear to be running. Start the docker daemon (e.g. 'systemctl start docker') and retry."
    exit 1
fi

if [ ! -f "$GENERATE_SCRIPT" ]; then
    echo "ERROR: Generate script not found: $GENERATE_SCRIPT"
    exit 1
fi

if [ ! -d "$OSINT_DIR" ]; then
    echo "ERROR: OSINT directory not found: $OSINT_DIR"
    exit 1
fi

mkdir -p "$GRAPHS_DIR"

# Ensure Docker daemon is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon does not appear to be running. Start the docker daemon (e.g. 'systemctl start docker') and retry."
    exit 1
fi

# Pull only if requested via env MULVAL_PULL=true; otherwise use cached image
if [[ "${MULVAL_PULL:-false}" = "true" ]]; then
    echo "[INFO] Pulling MulVAL Docker image..."
    docker pull wilbercui/mulval:latest > /dev/null 2>&1 || echo "[WARN] Could not pull image"
else
    echo "[INFO] Using cached MulVAL image (not pulling). Set MULVAL_PULL=true to force pull."
fi
echo ""

mapfile -t TEST_FILES < <(find "$OSINT_DIR" -name "$TEST_PATTERN" -type f | sort)

if [ ${#TEST_FILES[@]} -eq 0 ]; then
    echo "ERROR: No test files found matching pattern: $TEST_PATTERN"
    exit 1
fi

echo "Found ${#TEST_FILES[@]} test file(s) to run"
echo "==========================================================================="
echo ""

for test_file in "${TEST_FILES[@]}"; do
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    TEST_NAME=$(basename "$test_file" .P)
    
    echo "-----------------------------------------------------------------------"
    echo "Test $TOTAL_TESTS/${#TEST_FILES[@]}: $TEST_NAME"
    echo "-----------------------------------------------------------------------"
    
    TS="test_${TEST_NAME}_$(date +%Y%m%d_%H%M%S)"
    RUN_DIR="/data/graphs/$TS"
    OUTPUT_DIR="$GRAPHS_DIR/$TS"
    
    mkdir -p "$OUTPUT_DIR"
    
    REL_TEST_FILE="${test_file#$DATA_DIR/}"
    
    echo "[1/3] Running MulVAL..."
    
    docker run --rm \
      -v "$DATA_DIR":/data \
      -w "$RUN_DIR" \
      wilbercui/mulval \
      bash -lc "graph_gen.sh ../../$REL_TEST_FILE -r ../../$RULES_FILE -v" \
      > "$OUTPUT_DIR/mulval.log" 2>&1 || true
    
    if [ ! -f "$OUTPUT_DIR/trace_output.P" ]; then
        echo "[FAILED] No trace output"
        ERROR_TESTS=$((ERROR_TESTS + 1))
        ERROR_LIST+=("$TEST_NAME")
        echo ""
        continue
    fi
    
    # Extract MulVAL internal timing from xsb_log.txt
    MULVAL_TIME=""
    if [ -f "$OUTPUT_DIR/xsb_log.txt" ]; then
        TIMING_LINE=$(grep -o "cputime [0-9.]\+ secs, elapsetime [0-9.]\+ secs" "$OUTPUT_DIR/xsb_log.txt" | tail -1)
        if [ -n "$TIMING_LINE" ]; then
            CPU_TIME=$(echo "$TIMING_LINE" | grep -o "cputime [0-9.]\+" | awk '{print $2}')
            ELAPSED_TIME=$(echo "$TIMING_LINE" | grep -o "elapsetime [0-9.]\+" | awk '{print $2}')
            MULVAL_TIME="${ELAPSED_TIME}s (${CPU_TIME}s CPU)"
        fi
    fi
    
    echo "[2/2] Generating attack paths JSON..."
    
    if python3 "$GENERATE_SCRIPT" "$OUTPUT_DIR/trace_output.P" "$OUTPUT_DIR/AttackGraph.json" 2>&1; then
        echo "[PASSED] $TEST_NAME"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        PASSED_LIST+=("$TEST_NAME")
    else
        echo "[ERROR] JSON generation failed"
        ERROR_TESTS=$((ERROR_TESTS + 1))
        ERROR_LIST+=("$TEST_NAME")
    fi
    
    echo ""
done

echo "==========================================================================="
echo "Test Results"
echo "==========================================================================="
echo "Total: $TOTAL_TESTS | Passed: $PASSED_TESTS | Failed: $FAILED_TESTS | Errors: $ERROR_TESTS"
echo ""

if [ $PASSED_TESTS -gt 0 ]; then
    echo "PASSED:"
    for test in "${PASSED_LIST[@]}"; do
        echo "  + $test"
    done
fi

if [ $FAILED_TESTS -gt 0 ]; then
    echo "FAILED:"
    for test in "${FAILED_LIST[@]}"; do
        echo "  - $test"
    done
fi

if [ $ERROR_TESTS -gt 0 ]; then
    echo "ERRORS:"
    for test in "${ERROR_LIST[@]}"; do
        echo "  ! $test"
    done
fi

echo "==========================================================================="

if [ $FAILED_TESTS -gt 0 ] || [ $ERROR_TESTS -gt 0 ]; then
    exit 1
fi
