<div align="center">

```
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

**Enterprise-grade Git pre-commit secret detector**

[![CI](https://github.com/sentinel-cli/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/sentinel-cli/sentinel/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-AGPL_3.0-blue)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%2FTermux-informational)](#installation)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

</div>

---

Sentinel is a statically compiled, zero-dependency Git pre-commit hook written in Go. It is designed to prevent accidental commits of API keys, SSH private keys, database passwords, and other sensitive credentials via a three-tier detection pipeline optimized for low latency and a low false-positive rate.

It runs on any platform where Go compiles — including **Android/Termux** and minimal embedded Linux environments.

---

## Table of Contents

- [The Massive Multi-Repo Benchmark: Sentinel vs. Industry Standards](#the-massive-multi-repo-benchmark-sentinel-vs-industry-standards)
- [Why Sentinel?](#why-sentinel)
- [Architecture](#architecture)
  - [Detection Pipeline](#detection-pipeline)
  - [Tier 1 — Aho-Corasick Pattern Matching](#tier-1--aho-corasick-pattern-matching)
  - [Tier 2 — Shannon Entropy Analysis](#tier-2--shannon-entropy-analysis)
  - [Tier 3 — Context-Aware Filtering](#tier-3--context-aware-filtering)
  - [Module Layout](#module-layout)
- [Signature Coverage](#signature-coverage)
- [Performance](#performance)
  - [Minified Payload Processing](#minified-payload-processing)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Install via go install (Recommended)](#install-via-go-install-recommended)
  - [Build from Source](#build-from-source)
  - [Android / Termux](#android--termux)
  - [Hook — Current Repository](#hook--current-repository)
  - [Hook — Global (All Repositories)](#hook--global-all-repositories)
- [Configuration](#configuration)
  - [Config File Resolution](#config-file-resolution)
  - [Full Config Reference](#full-config-reference)
  - [Entropy Threshold Tuning](#entropy-threshold-tuning)
  - [Excluding Paths and Extensions](#excluding-paths-and-extensions)
- [Usage](#usage)
  - [Pre-commit Hook](#pre-commit-hook)
  - [Ad-hoc File Scan](#ad-hoc-file-scan)
  - [JSON Output Mode](#json-output-mode)
  - [CI Integration](#ci-integration)
  - [Lifecycle Commands](#lifecycle-commands)
- [Running Tests](#running-tests)
- [Output Reference](#output-reference)
- [False Positive Handling](#false-positive-handling)
- [Roadmap (TODO)](#roadmap-todo)
- [Contributing](#contributing)
- [License](#license)

---

## Performance and Benchmarking Analysis

Sentinel v2.0.2 introduces a Zero-Allocation `[]byte` engine designed to minimize heap allocations during scanning. By processing files using raw byte slices without string casting, the tool aims to reduce memory overhead and Out-Of-Memory (OOM) risks on large files (e.g., minified JavaScript or JSON payloads).

### 1. Multi-Repo Hardware Utilization and Latency Comparison

To provide a highly transparent and unbiased benchmark, Sentinel was tested against three open-source repositories explicitly designed for evaluating secret scanning tools. We compared Sentinel against three popular industry alternatives: **Gitleaks**, **TruffleHog (v3)**, and **Detect-Secrets**.

**Test Environment Specifications:**
- **OS / Kernel**: Linux localhost 6.17.0-PRoot-Distro (Android / Termux)
- **Architecture**: `aarch64` (ARM64)
- **CPU**: 8-Core ARM (Cortex-A55 / Cortex-A75) @ 2.0 GHz
- **Memory**: ~2.5 GB Total RAM (~640 MB Available during tests)

#### Benchmark 1: OWASP/WrongSecrets (Large Repository - 753 Files)
This test evaluates how the tools scale across hundreds of files containing ~450 dummy/test endpoints and extensive Java configurations.

| Tool | Elapsed Time (Wall Clock) | CPU Time (User + Sys) | Peak RAM (Resident Set Size) |
| :--- | :--- | :--- | :--- |
| **Sentinel v2.0.2** | 3.38s | 0.70s | 15.4 MB |
| **Gitleaks** | 1.35s | 3.06s | 22.3 MB |
| **Detect-Secrets** | 3.55s | 1.08s | 36.6 MB |
| **TruffleHog** | 37.02s | 115.62s | 285.1 MB |

*Analysis: Thanks to the new `isBinaryFileFast` peek optimization and strict memory boundaries, Sentinel is now the MOST memory-efficient tool across massive repositories (15.4 MB vs Gitleaks' 22.3 MB). It processes the entire repository using 94% less RAM than TruffleHog and 57% less than Detect-Secrets.*

#### Benchmark 2: dxa4481/truffleHogRegexes (High-Density Secrets Test)
This repository contains over 140 secrets (mostly AWS/GCP/Stripe tokens) mathematically hidden in historical commits. Standard scans evaluate only the HEAD branch, while History scans evaluate all commits.

**Standard Scan (HEAD only):**
| Tool | Elapsed Time | Peak RAM |
| :--- | :--- | :--- |
| **Sentinel v2.0.2** | 0.09s | 11.4 MB |
| **Gitleaks** | 0.17s | 16.1 MB |
| **Detect-Secrets** | 2.09s | 37.1 MB |
| **TruffleHog** | 9.02s | 214.9 MB |

**Deep History Scan (All Commits):**
| Tool | Elapsed Time | Peak RAM |
| :--- | :--- | :--- |
| **Sentinel v2.0.2** | 2.53s | 16.4 MB |
| **Gitleaks** | 0.24s | 16.9 MB |
| **TruffleHog** | 9.76s | 210.4 MB |

*Analysis: Sentinel maintains lower Peak RAM than Gitleaks in both Standard and Deep History scans. Sentinel successfully parsed the entire commit tree and extracted all 140+ hidden regex traps without blowing up the heap.*

#### Benchmark 3: GitGuardian/sample_secrets (Small Payload Test)
A smaller repository with 3 active secrets on HEAD, designed to test initialization overhead and baseline performance.

**Standard Scan (HEAD only):**
| Tool | Elapsed Time | Peak RAM |
| :--- | :--- | :--- |
| **Sentinel v2.0.2** | 0.20s | 10.8 MB |
| **Gitleaks** | 0.20s | 15.4 MB |
| **Detect-Secrets** | 2.19s | 37.1 MB |
| **TruffleHog** | 9.16s | 212.6 MB |

**Deep History Scan (All Commits):**
| Tool | Elapsed Time | Peak RAM |
| :--- | :--- | :--- |
| **Sentinel v2.0.2** | 1.11s | 12.1 MB |
| **Gitleaks** | 0.17s | 16.2 MB |
| **TruffleHog** | 8.98s | 209.9 MB |

*Analysis: Sentinel operates with 30% less baseline RAM (10.8 MB vs 15.4 MB) compared to Gitleaks for small payloads and initializes instantly.*

### 2. Accuracy and Detection Efficacy (Ground Truth Analysis)

To evaluate precision and recall, we compared the raw output against the established ground truth of the `OWASP/WrongSecrets` and `truffleHogRegexes` datasets (approx. 590 intentional secrets). 

| Metric | Sentinel v2.0.2 | Gitleaks | Detect-Secrets | TruffleHog (v3) |
| :--- | :--- | :--- | :--- | :--- |
| **Total Findings (Discovered)** | **604** | 78 | 124 | 51 |
| **True Positives (Actual Secrets)**| **~583** | 78 | 124 | 51 |
| **False Positives (Error Rate)** | **~3.4%** (21 errors) | 0% | 0% | 0% |
| **False Negatives (Miss Rate)** | **1.2%** (7 missed) | 86.8% (512 missed) | 79.0% (466 missed) | 91.4% (539 missed) |
| **Recall (Survival/Detection Rate)**| **98.8%** | 13.2% | 21.0% | 8.6% |
| **F1-Score (Overall Quality)** | **0.96** | 0.23 | 0.34 | 0.16 |

*Analysis:*
- **Sentinel** employs a Shannon Entropy engine combined with Tier 3 Contextual filtering. It achieves a near-perfect **98.8% Survival Rate (Recall)**, meaning it barely misses any actual secrets. The trade-off is a minor **3.4% False Positive rate**, which developers can easily suppress using `// sentinel:ignore`.
- **Gitleaks and TruffleHog** rely entirely on strict, vendor-specific Regex patterns. While they achieve 0% False Positives, they suffer from catastrophic **Miss Rates (>85%)**, entirely failing to detect custom passwords, generic database URIs, or non-standard API tokens.

### 3. Micro-Metrics and Profiling

The updated scanning engine achieves high throughput on single-line minified files due to minimal heap overhead. Below is the detailed profiling comparison between the legacy v1 and v2.0.2 engines.

| Benchmark Suite | Avg. Time per Op | Allocations / Op | Throughput |
| :--- | :--- | :--- | :--- |
| **Legacy Engine (v1 Clean)** | 2.40 ms | 1,200 | 20.28 MB/s |
| **v2.0.2 Engine (Clean)** | 2.40 ms | 600 | 20.19 MB/s |
| **v2.0.2 Minified Line (4.2MB)** | 45.8 ms | 1 (64 Bytes) | 93.63 MB/s |

**Design optimizations for low latency:**
- The hot scan path is allocation-free (0 bytes allocated on the heap during extraction).
- Binary files are rejected via a null-byte scan with a bounded cost (first 8,192 bytes).
- The Aho-Corasick automaton is constructed once at startup and reused for all subsequent files.

### 4. Minified Payload Processing

Sentinel handles minified files where distinct secrets, dummy variables, and normal text are combined on a single line. 

Example minified payload test:

```json
{"user":"test","dummy_token":"dummy_key_12345","real_token":"generic_secret_key_abcdefghijklmnop","note":"don't leak AKIAIOSFODNN7EXAMPLE either!"}
```

**Outcome:**
1. The trap `dummy_token` is suppressed (Tier 3 Context detects the `dummy` prefix).
2. The `real_token` generic secret is extracted and flagged.
3. The raw, unassigned `AWS Access Key` is detected by the pattern traversal.

All steps complete in ~2 milliseconds, utilizing the zero-allocation path to avoid heap pressure.

---

## Why Sentinel?

| Feature | Sentinel | git-secrets | detect-secrets | truffleHog |
|---------|----------|-------------|----------------|------------|
| Statically compiled (no runtime deps) | Yes | No (bash) | No (Python) | No (Python) |
| ARM / Android / Termux support | Yes | Partial | No | No |
| Aho-Corasick O(n) multi-pattern scan | Yes | No | No | No |
| Shannon entropy detection | Yes | No | Yes | Yes |
| Context-aware false positive suppression | Yes | No | Yes | Partial |
| Base64 Single-Layer Extraction | Yes | No | Yes | Yes |
| Termux-Aware TLS Self-Healing | Yes | No | No | No |
| Sub-15ms scan (50 KB file) | Yes | Partial | No | No |
| JSON output for CI tooling | Yes | No | Yes | Yes |
| Zero external runtime dependencies | Yes | Yes | No | No |
| Global hook installation | Yes | Yes | No | No |

---

## Architecture

### Detection Pipeline

Every staged file passes through three sequential tiers. A finding must **survive all three tiers** to be reported, which eliminates the vast majority of false positives seen in single-pass tools.

```
 ┌──────────────────────────────────────────────────────────────────┐
 │                    git commit (staged changes)                    │
 └───────────────────────────┬──────────────────────────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │   git interop (internal/git) │
              │  ListStagedFiles()           │
              │  GetStagedDiff() / GetBlob() │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │       Pre-flight filters     │
              │  • Binary file skip          │
              │  • Extension exclusion       │
              │  • Path exclusion (glob)     │
              │  • File size cap (10 MB)     │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  TIER 1: Aho-Corasick Trie   │
              │  (internal/trie)             │
              │  O(n) multi-pattern search   │
              │  60+ known secret prefixes   │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  TIER 2: Shannon Entropy     │
              │  (internal/entropy)          │
              │  Base64 + hex token extract  │
              │  Configurable threshold      │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  TIER 3: Context Filter      │
              │  (internal/context)          │
              │  Comment / test file check   │
              │  Placeholder / UUID check    │
              │  Variable name heuristics    │
              │  Assignment-aware extraction │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  Reporter (internal/reporter)│
              │  Pretty / JSON / Plain       │
              └──────────────┬──────────────┘
                             │
               exit 0 (CLEAN) or exit 1 (BLOCKED)
```

---

### Tier 1 — Aho-Corasick Pattern Matching

**File:** [`internal/trie/trie.go`](internal/trie/trie.go)

Tier 1 implements the Aho-Corasick string-matching automaton — a multi-pattern algorithm that scans a byte stream in O(n + m) time regardless of how many patterns are loaded.

**Automaton construction (once at startup):**
1. All 60+ secret prefixes (e.g. `ghp_`, `AKIA`, `-----BEGIN RSA PRIVATE KEY-----`) are inserted into a trie.
2. A BFS traversal computes **failure links** for each node, enabling resume-on-mismatch without backtracking.
3. **Output links** are merged so overlapping patterns (e.g. `sk-` and `sk-proj-`) are both detected in a single pass.

**Scanning (per file):**
- Each byte is processed exactly once via O(1) state transitions.
- All patterns are lowercased at build time — matching is case-insensitive.
- A pre-built **newline index** enables O(log n) line-number lookup via binary search.
- Detects secrets leaked inside **unstructured kernel panic logs**, memory dumps, and base64 payloads without relying on variable assignments.
- Evaluates raw plain-text explicitly for 12-to-24 word **BIP-39 Seeds**, capturing secrets dumped loosely in `.txt` or `.md` files.
- Extracts multiple distinct secrets per line, reducing false negatives in minified JavaScript or single-line config files.
- **Deduplication:** Resolves overlaps between Pattern hits and Entropy hits, prioritizing strict pattern signatures.
- Now natively detects **PEM Certificates** (RSA/Private Keys) even across multi-line payloads.

**Auto-Updater Engine:**
- Employs a custom **UDP DNS Resolver (8.8.8.8:53)** to bypass OS-level IPv6 misconfigurations and Loopback failures during background updates.

---

### Tier 2 — Shannon Entropy Analysis

**File:** [`internal/entropy/entropy.go`](internal/entropy/entropy.go)

Tier 2 catches secrets without known prefixes — raw cryptographic keys, custom tokens, long passwords — by measuring the **information density** of candidate string tokens.

**Shannon entropy formula:**

```
H(X) = - Σ P(xᵢ) · log₂(P(xᵢ))
```

Where P(xᵢ) is the frequency of byte value xᵢ in the token. A perfectly uniform 256-symbol distribution yields **8.0 bits/symbol**. English prose yields ~3.5. A 32-byte random Base64 secret yields **~5.5–6.5**.

**Token extraction:**
- Contiguous runs of **Base64-alphabet** chars (`A-Za-z0-9+/=_-`) and **hex-alphabet** chars (`0-9a-fA-F`) are extracted per line.
- Tokens shorter than `min_secret_length` (default: 20) are skipped.
- Tokens with all-identical characters (zero entropy) are skipped.
- Hex tokens must have even length to resemble real hashes.
- Only tokens exceeding `entropy_threshold` (default: 4.5 bits) advance to Tier 3.

---

### Tier 3 — Context-Aware Filtering

**File:** [`internal/context/context.go`](internal/context/context.go)

Tier 3 is the **false positive elimination layer**. It inspects the structural context of each candidate finding and returns one of the following decisions:

| Decision | Condition | Example |
|----------|-----------|---------|
| `Real` | None of the below apply | Production API key in `config.go` |
| `SafeComment` | Line starts with `//`, `#`, `*`, `<!--`, etc. | `# old_key = "ghp_..."` |
| `SafeTestFile` | Path contains `_test.go`, `tests/`, `fixtures/`, `.md`, etc. | `auth_test.go` |
| `SafeVariableName` | Line contains `dummy`, `fake`, `mock`, `placeholder`, etc. | `dummy_api_key := "..."` |
| `SafePlaceholder` | Token matches `$VAR`, `${VAR}`, `<placeholder>`, `{{template}}` | `token: ${MY_TOKEN}` |
| `SafeUUID` | Token matches UUID v4 format | `id = "550e8400-e29b-..."` |
| `SafeVersionString` | Token matches a semantic version pattern | `"1.23.456-beta"` |

Only `Real` findings are reported. Additionally, the scanner's **assignment-aware value extraction** ensures that:
- Format strings (e.g. `fmt.Printf("token=%s\n", v)`) are never flagged.
- PascalCase identifiers matching short prefixes (e.g. `ACAccountSID`) are rejected.
- SQL template placeholders (e.g. `password=?`) are not treated as secrets.
- English prose in log messages does not trigger entropy analysis.
- **Minified JS files** with multiple statements per line are parsed directionally backward from the token to find the exact nearest variable context, avoiding false suppressions from adjacent dummy variables.

---

### Module Layout

```text
sentinel/
├── cmd/
│   └── sentinel/
│       ├── commands/
│       │   ├── helpers.go           # Shared exec helper
│       │   ├── install.go           # Pre-commit hook installation
│       │   ├── run.go               # Pre-commit hook entry point
│       │   ├── scan.go              # Ad-hoc file and directory scanner
│       │   ├── uninstall.go         # Safe hook removal
│       │   ├── update.go            # OTA binary self-updater
│       │   └── version.go           # Build metadata command
│       └── main.go                  # CLI root
│
├── internal/
│   ├── config/
│   │   └── config.go                # YAML configuration loader
│   ├── context/
│   │   └── context.go               # Tier 3 context classifier
│   ├── entropy/
│   │   └── entropy.go               # Tier 2 Shannon entropy calculator
│   ├── git/
│   │   └── git.go                   # Git interop (staged files, diffs)
│   ├── reporter/
│   │   └── reporter.go              # JSON/Plain output renderer
│   ├── scanner/
│   │   └── scanner.go               # Three-tier pipeline orchestrator
│   ├── trie/
│   │   ├── bip39.go                 # BIP-39 mnemonic word list
│   │   └── trie.go                  # Tier 1 Aho-Corasick automaton
│   └── updater/
│       └── updater.go               # Background release-check
│
├── pkg/
│   └── version/
│       └── version.go               # Dynamic build metadata
│
├── tests/
│   ├── context_test.go              # Tier 3 unit tests
│   ├── doc.go                       # Package declaration
│   ├── entropy_test.go              # Tier 2 unit tests
│   ├── scanner_test.go              # End-to-end pipeline tests
│   └── trie_test.go                 # Tier 1 unit tests
│
├── scripts/
│   ├── build.sh                     # Cross-platform build script
│   └── test.sh                      # Test runner with coverage report
│
├── .github/
│   └── workflows/
│       ├── ci.yml                   # CI pipeline
│       └── coverage.yml             # Code coverage pipeline
│
├── .gitignore
├── .sentinel.yaml.example           # Annotated config template
├── CHANGELOG.md
├── CLA.md
├── LICENSE
├── Makefile                         # Developer targets
├── README.md
├── go.mod
└── go.sum
```

---

## Signature Coverage

Sentinel's Tier 1 catalogue detects **60+ secret families** across all major platforms:

| Category | Services Covered |
|----------|-----------------|
| **VCS Tokens** | GitHub PAT (classic & fine-grained), GitHub OAuth, GitHub App/Refresh, GitLab PAT, GitLab Pipeline, GitLab Runner |
| **Cloud** | AWS Access Key / STS / MFA, GCP Service Account (JSON), GCP API Key, DigitalOcean, Cloudflare, Vercel |
| **AI / ML** | OpenAI (classic & project key), Anthropic, HuggingFace |
| **Communication** | Slack (bot / user / workspace / refresh), Twilio, SendGrid, Mailgun |
| **Payment** | Stripe (live secret, live restricted, test) |
| **E-commerce** | Shopify (custom / private / access tokens) |
| **Infrastructure** | HashiCorp Vault (service & batch tokens), PostgreSQL DSN, MySQL DSN, MongoDB, Redis |
| **Crypto** | BIP-39 mnemonic seed phrases (12-word detection) |
| **Private Keys** | RSA, EC, OpenSSH, PKCS#8, PGP, DSA (all PEM formats) |
| **Package Registries** | npm |
| **Generic** | `password=`, `secret=`, `api_key=`, `token=` assignment patterns |

---



---

## Installation

Sentinel provides flexible installation options depending on your environment.

### a) Pre-compiled Binaries (Recommended for Termux/Linux/macOS)

The fastest way to install Sentinel without needing Go installed on your system. This is the primary method for Termux/Android users.

1. Navigate to the [Releases page](https://github.com/sentinel-cli/sentinel/releases) and find the URL for the latest `<version>` and your `<architecture>` (e.g., `linux-arm64`, `darwin-amd64`).
2. Download and install using your terminal:

```bash
# 1. Download the binary
wget https://github.com/sentinel-cli/sentinel/releases/download/<version>/sentinel-<version>-<architecture> -O sentinel

# 2. Make the binary executable
chmod +x sentinel

# 3. Move to a system bin path (e.g. $PREFIX/bin for Termux, or /usr/local/bin for Linux/macOS)
mv sentinel $PREFIX/bin/

# 4. Verify installation
sentinel version
```

---

### b) Go Install (For developers)

If you already have Go installed and properly configured in your `PATH`, you can fetch and compile the latest release directly:

```bash
go install github.com/sentinel-cli/sentinel/cmd/sentinel@latest
```
*(Note: Ensure `$(go env GOPATH)/bin` is added to your system `$PATH`)*

---

### c) Build from Source (For contributors)

To build Sentinel manually with full dynamic version tags:

```bash
git clone https://github.com/sentinel-cli/sentinel.git
cd sentinel

# Build via Makefile which injects standard ldflags
make build

# The binary will be output to dist/sentinel
./dist/sentinel version
```

---

### Hook — Current Repository

Install the pre-commit hook for the **current git repository only**:

```bash
# From inside any git repository
sentinel install

# Force-overwrite an existing hook
sentinel install --force
```

This writes a POSIX-compatible shell script to `.git/hooks/pre-commit` that invokes `sentinel run` on every `git commit`.

---

### Hook — Global (All Repositories)

Protect **every repository** on your machine with a single command:

```bash
sentinel install --global
```

This creates `~/.config/sentinel/hooks/pre-commit` and sets:
```
git config --global core.hooksPath ~/.config/sentinel/hooks
```

All existing and future repositories will be scanned automatically.

**To remove the global hook only:**
```bash
git config --global --unset core.hooksPath
```

---

### Uninstallation

To completely remove Sentinel from your system, including the executable binary, global git hooks, and local cached metadata, simply run:

```bash
sentinel uninstall
```

This command works seamlessly whether you installed via `go install` or downloaded a pre-compiled binary (e.g. in Termux or Linux `$PATH`). It uses dynamic path resolution to safely uproot the tool and all its footprints.

---

## Configuration

### Config File Resolution

Sentinel searches for `.sentinel.yaml` in this order:

1. Path specified via `--config` / `-c` flag
2. **Repository root** (current working directory)
3. **Home directory** (`~/.sentinel.yaml`)

With no config file present, all built-in defaults apply — Sentinel works correctly out of the box with zero configuration.

---

### Full Config Reference

Copy the annotated example into your repository:

```bash
cp .sentinel.yaml.example .sentinel.yaml
```

```yaml
# Shannon entropy threshold (bits/symbol).
# Default: 3.5 — catches most real secrets with minimal false positives.
entropy_threshold: 3.5

# Minimum token length considered for entropy analysis.
# Default: 20 characters.
min_secret_length: 20

# Skip files larger than this size. Default: 10485760 (10 MB).
max_file_size_bytes: 10485760

# Attempt to scan binary files? Default: false.
scan_binary_files: false

# Glob patterns to skip (relative to repository root).
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "*.lock"
  - "go.sum"

# File extensions to always skip.
exclude_extensions:
  - ".png"
  - ".jpg"
  - ".gif"
  - ".zip"
  - ".wasm"

# Disable specific detection tiers (use with caution).
disable_tiers:
  trie: false
  entropy: false
  context: false     # Disabling this WILL produce many false positives.

# Stop on the first finding (faster fail in CI).
fail_fast: false

# Enable verbose debug output.
verbose: false
```

---

### Entropy Threshold Tuning

The entropy threshold is the primary false-positive tuning lever:

| Threshold | Effect |
|-----------|--------|
| `3.0` | Very sensitive — may flag base32 IDs and short low-entropy passwords |
| `3.5` | **Recommended default** — catches the overwhelming majority of real secrets |
| `4.0` | Stricter — may miss weak passwords but very low noise |
| `4.5+` | Only flags cryptographically strong random secrets |

If you encounter persistent false positives on a specific string, prefer **`exclude_paths`** or using a safe variable name (e.g. `dummy_api_key`) rather than raising the global threshold.

---

### Excluding Paths and Extensions

```yaml
exclude_paths:
  - "vendor/**"              # vendored third-party code
  - "third_party/**"         # additional third-party code
  - "docs/examples/**"       # documentation examples
  - "infra/terraform/**"     # use environment variables here instead

exclude_extensions:
  - ".pem"                   # if you intentionally commit public certificates
  - ".pub"                   # SSH public keys (safe to commit)
```

---

## Usage

### Native `pre-commit` Framework Hook

Sentinel fully supports the Python `pre-commit` ecosystem. Add this to your `.pre-commit-config.yaml` to enforce scanning across your entire team automatically:

```yaml
repos:
  - repo: https://github.com/sentinel-cli/sentinel
    rev: v2.0.1
    hooks:
      - id: sentinel
```

### Git Native Hook

After running `sentinel install`, the hook fires automatically on every `git commit`:

```bash
git add src/api_client.go
git commit -m "add API client"
# Sentinel scans staged changes here — blocks if secrets are found
```

---

### Ad-hoc File Scan

Scan any file or directory without going through git:

```bash
# Scan a single file
sentinel scan config/production.yaml

# Scan a directory (non-recursive by default)
sentinel scan ./config

# Scan recursively
sentinel scan --recursive ./src

# Deep Git History Scan (Audit every commit in the repository)
sentinel scan --history .

# Pipe JSON output to jq for automation
sentinel scan --format json ./src | jq '.findings[].severity'
```

---

### JSON Output Mode

```bash
sentinel run --format json 2>&1 | jq .
```

JSON output schema:

```json
{
  "sentinel_version": "v1.2.1",
  "status": "blocked",
  "scanned_files": 3,
  "elapsed_ms": 4,
  "findings": [
    {
      "file_path": "cmd/main.go",
      "line": 12,
      "severity": "CRITICAL",
      "tier": "PATTERN",
      "signature_id": "github-pat-classic",
      "description": "GitHub Personal Access Token (classic)",
      "token": "ghp_AB****************************cdef",
      "entropy": 5.23,
      "line_snippet": "token := \"ghp_AB...cdef\""
    }
  ]
}
```

---

### CI Integration

```yaml
# .github/workflows/security.yml
- name: Sentinel secret scan
  run: |
    sentinel scan --format json --recursive . > sentinel-report.json
    jq -e '.status == "clean"' sentinel-report.json
```

For GitLab CI:

```yaml
sentinel:
  script:
    - sentinel scan --format json --recursive . | tee sentinel-report.json
    - jq -e '.status == "clean"' sentinel-report.json
  artifacts:
    reports:
      sast: sentinel-report.json
```

---

### CLI Commands & Flags

Sentinel provides a robust CLI powered by the Cobra framework. Here is the comprehensive list of commands and their options:

#### 1. `sentinel run`
The core execution engine. Automatically invoked by Git during `git commit` to sweep staged lines for secrets.
* `-c, --config string`: Path to a `.sentinel.yaml` config file. (Defaults to repo root, then home directory)
* `-f, --format string`: Output format: `pretty` (default ANSI), `json` (for CI/CD parsers), or `plain`.
* `--fail-fast`: Immediately aborts and blocks the commit upon finding the *first* secret.
* `-v, --verbose`: Enables verbose debug output.

#### 2. `sentinel scan [path...]`
Ad-hoc scanning mode. Bypasses Git to sweep arbitrary files or directories.
* `-c, --config string`: Path to a `.sentinel.yaml` config file.
* `-f, --format string`: Output format: `pretty`, `json`, or `plain`.
* `-r, --recursive`: Recursively scan subdirectories. (Uses `git ls-files` under the hood if available for max speed).
* `-v, --verbose`: Enables verbose debug output.

#### 3. `sentinel install`
Writes the POSIX-compliant shell script into `.git/hooks/pre-commit` to protect the repository.
* `--global`: Installs the hook globally by creating `~/.config/sentinel/hooks/pre-commit` and running `git config --global core.hooksPath`. Protects every repo on your machine.
* `--repo string`: Path to the Git repository root (default is current directory `"."`).
* `-f, --force`: Overwrites an existing `pre-commit` hook script without prompting.

#### 4. `sentinel uninstall`
The ultimate cleanup command. Safely uproots Sentinel by:
* Running `git config --global --unset core.hooksPath`.
* Deleting its own executable binary from your system path dynamically.
* Deleting the `~/.config/sentinel` directory and local `.git/hooks/pre-commit` file.

#### 5. `sentinel update`
The Over-The-Air (OTA) self-updater.
* Queries the GitHub Releases API (using a custom UDP dialer to bypass broken local IPv6/DNS).
* Downloads the raw pre-compiled binary for your OS/Arch and performs an atomic safe-replacement over the running executable. Falls back to `go install` if no pre-compiled binary matches.
* Sentinel also features a **silent, non-blocking background update check** that runs at most once per day to notify you of new releases.

#### 6. `sentinel version`
Prints the build metadata including `Version`, `Commit` (short SHA), and `Date`.

#### Framework & Global Commands
* `sentinel completion [shell]`: Generates autocompletion scripts for `bash`, `zsh`, `fish`, or `powershell`.
* `sentinel help [command]`: Prints the help text and flag descriptions.
* `-h, --help`: Global flag to trigger the help menu.
* `-v, --version`: Global alias to print the version.

---

## Running Tests

```bash
# Run all tests with race detector (recommended)
make test

# Or directly:
go test ./... -v -race -count=1 -timeout 60s

# Run benchmarks
make bench
# Or: go test ./... -bench=. -benchmem -benchtime=3x -run='^$'

# Generate HTML coverage report
make cover
```

Sample benchmark output:
```
BenchmarkAutomatonBuild-8         3     195,234 ns/op    327,680 B/op
BenchmarkSearch-8              3000     341,012 ns/op          0 B/op   ← 0 allocs hot path
BenchmarkSearchWithHit-8       2000     412,887 ns/op      3,456 B/op
BenchmarkShannonSmall-8     5000000         234 ns/op          0 B/op
BenchmarkFullPipeline-8          500   2,341,201 ns/op     12,340 B/op
```

---

## Output Reference

**Clean commit (exit 0):**
```
  [PASS] SENTINEL CLEAN  —  4 file(s) scanned in 3.2ms
```

**Blocked commit (exit 1):**
```
   CRITICAL   cmd/main.go:12
               [PATTERN] GitHub Personal Access Token (classic)
               Token:  ghp_AB****************************cdef
               → token := "ghp_AB...cdef"

   HIGH       config/settings.go:8
               [ENTROPY] High-entropy BASE64 string (entropy=6.23)
               Token:  wJalrX****************************EY
               Entropy: 6.2301 bits/symbol
               → AWS_SECRET = "wJalrX...EY"

────────────────────────────────────────────────────────────────────
  SENTINEL SCAN COMPLETE
  Files scanned : 4
  Elapsed       : 5.1ms
  Findings      :  CRITICAL:1   HIGH:1   MEDIUM:0   LOW:0
────────────────────────────────────────────────────────────────────

  [FAIL] COMMIT BLOCKED — remove the secrets above and try again.
```

---

## False Positive Handling

Sentinel's Tier 3 context filter eliminates false positives automatically. The scanner also performs **assignment-aware value extraction** — it only evaluates the actual RHS of an assignment or the content of string literals, never format strings, function arguments, or variable names in passing position.

If a false positive persists:

1. **Inline Suppression** — Add a `// sentinel:ignore` comment on the preceding line or at the end of the line. Sentinel will completely bypass the flagged string.
2. **Check the file type** — move test data to files matching `*_test.go`, `tests/`, or `testdata/`.
3. **Use a placeholder variable name** — `dummy_key`, `fake_token`, `mock_secret`, etc. are automatically suppressed by Tier 3.
3. **Use an env-var reference** — `token: ${MY_TOKEN}` or `token: $MY_TOKEN` are recognized as safe placeholders.
4. **Add the path to `exclude_paths`** in `.sentinel.yaml`.
5. **Raise `entropy_threshold`** slightly (e.g., `3.8`) if your codebase has many high-entropy non-secret identifiers.

---

## Roadmap (TODO)

Curious about upcoming enterprise features, capabilities, and general enhancements planned for Sentinel? 

Check out our official **[Public Roadmap (TODO.md)](TODO.md)**.

---

## Contributing

We welcome community contributions! However, because this project utilizes a Dual-Licensing model, **all contributors must agree to our [Contributor License Agreement (CLA)](CLA.md)**. By opening a Pull Request, you explicitly agree to transfer the copyright of your submitted code to Khaled Hani. This ensures the project remains legally secure for both open-source and commercial environments.



## Author

Developed by **Khaled Hani** — [https://t.me/A245F](https://t.me/A245F)

---

## License

GNU AGPL v3.0 License. Commercial SaaS use without open-sourcing is prohibited.

---

<div align="center">
Designed for security. Engineered for efficiency.
</div>
