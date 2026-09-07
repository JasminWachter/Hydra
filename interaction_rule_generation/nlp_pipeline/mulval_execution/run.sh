#!/usr/bin/env bash
set -euo pipefail

# Usage: run.sh [INPUT_FILE] [OPTIONS]
# Options:
#   --rules RULES_FILE    Use custom interaction rules file (default: ../kb/full_interaction_rules.P)
#
# Examples:
#   run.sh ../osint_output/corporate_network.P
#   run.sh ../osint_output/test_02.P --rules ../kb/custom_rules.P

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

INPUT_FILE="${1:-../osint_output/mock_osint.P}"
RULES_FILE="kb/full_interaction_rules.P"
GRAPH_GEN_OPTS=""
# By default don't pull the docker image; allow forcing with --pull or env MULVAL_PULL=true
DO_PULL="false"

# Parse arguments
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --pull)
            DO_PULL="true"
            shift
            ;;
        --rules)
            RULES_FILE="$2"
            shift 2
            ;;
        *)
            GRAPH_GEN_OPTS="$GRAPH_GEN_OPTS $1"
            shift
            ;;
    esac
done

# Convert to absolute path if relative
if [[ "$INPUT_FILE" != /* ]]; then
    INPUT_FILE="$(cd "$(dirname "$INPUT_FILE")" && pwd)/$(basename "$INPUT_FILE")"
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo "[ERROR] Input file not found: $INPUT_FILE"
    echo "[INFO] Available files in osint_output/:"
    ls -1 "$DATA_DIR/osint_output/"*.P 2>/dev/null || echo "  (none found)"
    exit 1
fi

# Convert absolute path to relative path from DATA_DIR for Docker
INPUT_FILE_REL="${INPUT_FILE#$DATA_DIR/}"

# Convert RULES_FILE to absolute path if relative
if [[ "$RULES_FILE" != /* ]]; then
    # Make relative path relative to DATA_DIR (parent of mulval_execution)
    RULES_FILE="$DATA_DIR/$RULES_FILE"
fi

if [ ! -f "$RULES_FILE" ]; then
    echo "[ERROR] Rules file not found: $RULES_FILE"
    echo "[INFO] Available rules files:"
    ls -1 "$DATA_DIR/kb/"*.P 2>/dev/null || echo "  (none found)"
    exit 1
fi

# Convert absolute path to relative path from DATA_DIR for Docker
RULES_FILE_REL="${RULES_FILE#$DATA_DIR/}"

# Extract basename for run folder naming
INPUT_BASENAME=$(basename "$INPUT_FILE" .P)
RULES_BASENAME=$(basename "$RULES_FILE" .P)

mkdir -p "$DATA_DIR/graphs"

TS="run_${INPUT_BASENAME}_$(date +%Y%m%d_%H%M%S)"
RUN_DIR="/data/graphs/$TS"

echo "==========================================================================="
echo "MulVAL Attack Graph Generator"
echo "==========================================================================="
echo ""
echo "Configuration:"
echo "  Input file:  $INPUT_FILE"
echo "  Rules file:  $RULES_FILE"
echo "  Output dir:  graphs/$TS/"
if [ -n "$GRAPH_GEN_OPTS" ]; then
    echo "  Extra opts: $GRAPH_GEN_OPTS"
fi
echo ""

if grep -q "^%" "$INPUT_FILE"; then
    echo "Input file description:"
    grep "^%" "$INPUT_FILE" | sed 's/^%/  /' || true
    echo ""
fi

# Ensure Docker CLI exists and daemon is running
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker CLI not found. Please install Docker and ensure 'docker' is on PATH."
    exit 1
fi

if ! docker info > /dev/null 2>&1; then
    echo "[ERROR] Docker daemon does not appear to be running. Start the docker daemon (e.g. 'systemctl start docker') and retry."
    exit 1
fi

# Pull image only if requested via --pull or MULVAL_PULL=true; otherwise use cached image
if [[ "${MULVAL_PULL:-false}" = "true" ]] || [[ "$DO_PULL" = "true" ]]; then
    echo "[INFO] Pulling MulVAL image..."
    docker pull wilbercui/mulval:latest > /dev/null 2>&1 || {
        echo "[WARN] Could not pull latest image, using cached version"
    }
else
    echo "[INFO] Using cached MulVAL image (not pulling). To force pull set MULVAL_PULL=true or pass --pull."
fi

echo "[INFO] Creating output folder: $DATA_DIR/graphs/$TS"
mkdir -p "$DATA_DIR/graphs/$TS"

echo ""
echo "[1/3] Running MulVAL graph generation..."
MULVAL_EXIT_CODE=0
START_TIME=$(date +%s)
docker run --rm \
  -v "$DATA_DIR":/data \
  -w "$RUN_DIR" \
  wilbercui/mulval \
  bash -lc "graph_gen.sh ../../$INPUT_FILE_REL -r ../../$RULES_FILE_REL -v $GRAPH_GEN_OPTS" \
  > "$DATA_DIR/graphs/$TS/mulval.log" 2>&1 || MULVAL_EXIT_CODE=$?
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Format duration as human-readable
if [ $DURATION -ge 60 ]; then
    MINUTES=$((DURATION / 60))
    SECONDS=$((DURATION % 60))
    DURATION_STR="${MINUTES}m ${SECONDS}s"
else
    DURATION_STR="${DURATION}s"
fi

# Check if attack graph was generated successfully
if [ ! -f "$DATA_DIR/graphs/$TS/trace_output.P" ]; then
    echo "      - FAILED: No trace_output.P generated"
    echo "      See: graphs/$TS/mulval.log"
    echo "      See: graphs/$TS/xsb_log.txt"
    echo ""
    echo "[ERROR] MulVAL execution failed"
    echo "==========================================================================="
    exit 1
fi

# Extract MulVAL internal timing from xsb_log.txt
MULVAL_TIME=""
if [ -f "$DATA_DIR/graphs/$TS/xsb_log.txt" ]; then
    # Extract the last line with timing info: "End XSB (cputime X.XX secs, elapsetime Y.YY secs)"
    TIMING_LINE=$(grep -o "cputime [0-9.]\+ secs, elapsetime [0-9.]\+ secs" "$DATA_DIR/graphs/$TS/xsb_log.txt" | tail -1)
    if [ -n "$TIMING_LINE" ]; then
        CPU_TIME=$(echo "$TIMING_LINE" | grep -o "cputime [0-9.]\+" | awk '{print $2}')
        ELAPSED_TIME=$(echo "$TIMING_LINE" | grep -o "elapsetime [0-9.]\+" | awk '{print $2}')
        MULVAL_TIME="${ELAPSED_TIME}s (${CPU_TIME}s CPU)"
    fi
fi

echo "[2/2] Generating attack paths JSON..."

if [ -f "$SCRIPT_DIR/generate_attack_paths.py" ]; then
    python3 "$SCRIPT_DIR/generate_attack_paths.py" "$DATA_DIR/graphs/$TS/trace_output.P" "$DATA_DIR/graphs/$TS/AttackGraph.json" || {
        echo ""
        echo "- ERROR: Failed to generate attack paths JSON"
        echo "==========================================================================="
        exit 2
    }
    
    echo ""
    echo "+ SUCCESS: Attack graph generated successfully"
    echo ""
    echo "Results available in:"
    echo "  - PDF:     graphs/$TS/AttackGraph.pdf"
    echo "  - DOT:     graphs/$TS/AttackGraph.dot"
    echo "  - JSON:    graphs/$TS/AttackGraph.json"
    echo "  - Trace:   graphs/$TS/trace_output.P"
    echo "  - Logs:    graphs/$TS/xsb_log.txt"
else
    echo "      ! generate_attack_paths.py not found, skipping JSON generation"
    echo ""
    echo "Results available in:"
    echo "  - PDF:     graphs/$TS/AttackGraph.pdf"
    echo "  - DOT:     graphs/$TS/AttackGraph.dot"
    echo "  - Trace:   graphs/$TS/trace_output.P"
    echo "  - Logs:    graphs/$TS/xsb_log.txt"
fi

echo "==========================================================================="
exit 0
