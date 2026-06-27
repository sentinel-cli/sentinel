#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test.sh — Run the full Sentinel test suite with coverage and benchmarks
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   ./scripts/test.sh              # run all tests
#   ./scripts/test.sh bench        # run all benchmarks
#   ./scripts/test.sh cover        # generate HTML coverage report
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

COVER_OUT="coverage.out"
COVER_HTML="coverage.html"

echo "┌────────────────────────────────────────────────────┐"
echo "│  SENTINEL TEST SUITE                                │"
echo "└────────────────────────────────────────────────────┘"
echo

case "${1:-test}" in
  test)
    echo "Running all unit and integration tests..."
    go test ./... -v -count=1 -timeout 60s -race
    echo
    echo "✔ All tests passed."
    ;;

  bench)
    echo "Running all benchmarks (3 iterations each)..."
    go test ./... -bench=. -benchmem -benchtime=3x -count=1 -run='^$'
    ;;

  cover)
    echo "Generating coverage report..."
    go test ./... -coverprofile="${COVER_OUT}" -covermode=atomic -count=1 -timeout 60s
    go tool cover -html="${COVER_OUT}" -o "${COVER_HTML}"
    echo "✔ Coverage report: ${COVER_HTML}"
    go tool cover -func="${COVER_OUT}" | tail -1
    ;;

  *)
    echo "Usage: $0 [test|bench|cover]"
    exit 1
    ;;
esac
