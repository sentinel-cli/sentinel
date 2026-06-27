# Sentinel — Git Pre-Commit Secret Detector
# Makefile for development convenience
# ─────────────────────────────────────────────────────────────────────────────

BINARY      := sentinel
DIST_DIR    := dist
CMD_PATH    := ./cmd/sentinel
MODULE      := github.com/sentinel-cli/sentinel

VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE        := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X $(MODULE)/pkg/version.Version=$(VERSION) \
	-X $(MODULE)/pkg/version.Commit=$(COMMIT) \
	-X $(MODULE)/pkg/version.Date=$(DATE)

.PHONY: all build cross test bench cover lint install clean help

all: build

## build: Build sentinel for the current platform
build:
	@echo "Building $(BINARY) $(VERSION)..."
	@mkdir -p $(DIST_DIR)
	@CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY) $(CMD_PATH)
	@echo "✔ $(DIST_DIR)/$(BINARY)"

## cross: Cross-compile for all release targets
cross:
	@bash scripts/build.sh cross

## test: Run all tests with race detector
test:
	@go test ./... -v -race -count=1 -timeout 60s

## bench: Run all benchmarks
bench:
	@go test ./... -bench=. -benchmem -benchtime=3x -run='^$$'

## cover: Generate HTML coverage report
cover:
	@bash scripts/test.sh cover

## lint: Run staticcheck
lint:
	@command -v staticcheck >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	@staticcheck ./...

## install: Install sentinel binary to GOPATH/bin
install:
	@CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" $(CMD_PATH)
	@echo "✔ sentinel installed to $$(go env GOPATH)/bin/sentinel"

## hook: Install the pre-commit hook into the current repository
hook: build
	@$(DIST_DIR)/$(BINARY) install --force

## hook-global: Install the hook globally for all repositories
hook-global: build
	@$(DIST_DIR)/$(BINARY) install --global --force

## clean: Remove build artifacts
clean:
	@rm -rf $(DIST_DIR) coverage.out coverage.html
	@echo "✔ Cleaned"

## help: Show this help message
help:
	@grep -E '^## ' Makefile | sed 's/## /  /' | column -t -s ':'
