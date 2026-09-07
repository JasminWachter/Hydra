#!/usr/bin/env bash
set -euo pipefail

# Clean all test and run execution folders from graphs directory
# Usage: bash clean_graphs.sh [-y]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GRAPHS_DIR="$SCRIPT_DIR/../graphs"

if [ ! -d "$GRAPHS_DIR" ]; then
    echo "Graphs directory not found: $GRAPHS_DIR"
    exit 1
fi

# Count folders to be deleted
COUNT=$(find "$GRAPHS_DIR" -maxdepth 1 -type d \( -name "test/test_*" -o -name "run_*" \) | wc -l)

if [ "$COUNT" -eq 0 ]; then
    echo "No test or run folders found in graphs/"
    exit 0
fi

echo "Found $COUNT folder(s) to delete:"
find "$GRAPHS_DIR" -maxdepth 1 -type d \( -name "test_*" -o -name "run_*" \) -exec basename {} \; | sort

# Check for -y flag
if [ "${1:-}" = "-y" ]; then
    REPLY="y"
else
    read -p "Delete all? (y/N): " -n 1 -r
    echo
fi

if [[ $REPLY =~ ^[Yy]$ ]]; then
    find "$GRAPHS_DIR" -maxdepth 1 -type d \( -name "test_*" -o -name "run_*" \) -exec rm -rf {} +
    echo "+ Deleted $COUNT folder(s)"
else
    echo "Cancelled"
fi
