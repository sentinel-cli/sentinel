#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build.sh — Sentinel production build script
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   ./scripts/build.sh              # build for current platform
#   ./scripts/build.sh cross        # build all release targets
#   ./scripts/build.sh clean        # remove build artifacts
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

MODULE="github.com/sentinel-cli/sentinel"
CMD_PATH="${MODULE}/cmd/sentinel"
BINARY="sentinel"
DIST_DIR="dist"

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS=(
  "-s" "-w"
  "-X ${MODULE}/pkg/version.Version=${VERSION}"
  "-X ${MODULE}/pkg/version.Commit=${COMMIT}"
  "-X ${MODULE}/pkg/version.Date=${DATE}"
)

LDFLAGS_STR="${LDFLAGS[*]}"

echo "┌────────────────────────────────────────────────────┐"
echo "│  SENTINEL BUILD                                     │"
echo "│  Version : ${VERSION}"
echo "│  Commit  : ${COMMIT}"
echo "│  Date    : ${DATE}"
echo "└────────────────────────────────────────────────────┘"
echo

build_for() {
  local GOOS=$1
  local GOARCH=$2
  local suffix="${3:-}"
  local out="${DIST_DIR}/${BINARY}-${VERSION}-${GOOS}-${GOARCH}${suffix}"

  echo "  → Building ${out}..."
  GOOS="${GOOS}" GOARCH="${GOARCH}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${LDFLAGS_STR}" -o "${out}" "${CMD_PATH}"
  echo "    ✔ done ($(du -sh "${out}" | cut -f1))"
}

case "${1:-local}" in
  local)
    mkdir -p "${DIST_DIR}"
    CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS_STR}" -o "${DIST_DIR}/${BINARY}" "${CMD_PATH}"
    echo "✔ Built: ${DIST_DIR}/${BINARY}"
    ;;

  cross)
    mkdir -p "${DIST_DIR}"
    build_for linux   amd64
    build_for linux   arm64
    build_for linux   arm    ""   # ARM v6/v7 for Raspberry Pi / Termux
    build_for darwin  amd64
    build_for darwin  arm64
    build_for windows amd64  ".exe"
    build_for windows arm64  ".exe"
    echo
    echo "✔ All targets built in ${DIST_DIR}/"
    ls -lh "${DIST_DIR}/"
    ;;

  clean)
    rm -rf "${DIST_DIR}"
    echo "✔ Cleaned ${DIST_DIR}/"
    ;;

  *)
    echo "Usage: $0 [local|cross|clean]"
    exit 1
    ;;
esac
