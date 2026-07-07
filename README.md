# Sentinel — Ultra-Fast Git Secret Scanner & Pre-Commit Hook

<!-- SEO: git secret scanner, pre-commit hook, gitleaks alternative, credentials detector, api key detection, go security tool, git-secrets alternative -->

<div align="center">

```text
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

**Enterprise-grade Git pre-commit secret detector, Gitleaks alternative, and high-performance credentials scanner written in Go.**

[![CI](https://github.com/sentinel-cli/sentinel/actions/workflows/ci.yml/badge.svg?branch=main&v=4)](https://github.com/sentinel-cli/sentinel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sentinel-cli/sentinel?color=3c6382&logo=github&label=latest&v=4)](https://github.com/sentinel-cli/sentinel/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22+-2f3542?logo=go&v=4)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/sentinel-cli/sentinel/v2.svg?v=4)](https://pkg.go.dev/github.com/sentinel-cli/sentinel/v2)
[![Stars](https://img.shields.io/github/stars/sentinel-cli/sentinel?style=flat&logo=github&color=3c6382&v=4)](https://github.com/sentinel-cli/sentinel/stargazers)
[![Downloads](https://img.shields.io/github/downloads/sentinel-cli/sentinel/total?color=4b6584&logo=github&v=4)](https://github.com/sentinel-cli/sentinel/releases)
[![License](https://img.shields.io/badge/license-AGPL_3.0-4b6584?v=4)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%2FTermux-2f3542?v=4)](#installation)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg?v=4)](https://github.com/avelino/awesome-go)

</div>

---

## Quick Start

**Install and protect your repository in under 60 seconds:**

```bash
# 1. Install
go install github.com/sentinel-cli/sentinel/v2/cmd/sentinel@latest

# 2. Protect the current repository
sentinel install

# 3. Verify — Sentinel will now scan every commit automatically
git add . && git commit -m "test"
```

**Or scan any directory right now, without a hook:**

```bash
sentinel scan --recursive ./src
```

That is all. No configuration file required. No runtime dependencies. Works on Linux, macOS, Windows, and Android/Termux.

---

## What is Sentinel?

**Sentinel** is a statically compiled, zero-dependency Git pre-commit hook and credentials scanner written in Go. It automatically blocks accidental commits of API keys, SSH private keys, cloud credentials, database connection strings, and other sensitive material before they enter version control.

It is a lightweight, developer-friendly alternative to **Gitleaks** and **git-secrets**, with broader detection coverage and significantly lower resource usage.

Sentinel uses a **three-tier detection pipeline** built for speed and near-zero false positives:

| Tier | Engine | Purpose |
|------|--------|---------|
| 1 — PATTERN | Aho-Corasick automaton | Matches 68 known secret signatures in O(n) time, zero allocations |
| 2 — ENTROPY | Shannon entropy analysis | Catches unknown secrets by measuring information density |
| 3 — CONTEXT | Context classifier | Suppresses false positives from comments, test files, and placeholders |

A finding must survive all three tiers before it is reported.

---

## Terminal Demo

```bash
asciinema play https://sentinel-cli.github.io/sentinel/demo.cast
```

![Sentinel Demo](docs/demo.gif)

---

## Table of Contents

- [Quick Start](#quick-start)
- [What is Sentinel](#what-is-sentinel)
- [Performance](#performance)
- [Why Sentinel](#why-sentinel)
- [Architecture](#architecture)
- [Signature Coverage](#signature-coverage)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Reference](#output-reference)
- [False Positive Handling](#false-positive-handling)
- [Running Tests](#running-tests)
- [Contributing](#contributing)
- [License](#license)

---

## Performance

Measured on real-world repositories with Sentinel v2.0.5 against the two most popular alternatives.

<details>
<summary>Filesystem Scan Results (Standard Mode)</summary>

| Repository | Tool | Execution Time | Peak RAM | Findings |
|:---|:---|:---|:---|:---|
| sample\_secrets | **Sentinel v2.0.5** | **40 ms** | **11.3 MB** | **2** |
| | Gitleaks v8.30.1 | 220 ms | 15.0 MB | 1 |
| | TruffleHog v3.95.7 | 11.41 s | 153.2 MB | 3 |
| truffleHogRegexes | **Sentinel v2.0.5** | **30 ms** | **11.5 MB** | **0** (Noise Filtered) |
| | Gitleaks v8.30.1 | 210 ms | 16.0 MB | 1 |
| | TruffleHog v3.95.7 | 7.13 s | 154.5 MB | 0 |

</details>

<details>
<summary>Git History Scan Results (History Mode)</summary>

| Repository | Tool | Execution Time | Peak RAM | Findings |
|:---|:---|:---|:---|:---|
| sample\_secrets | **Sentinel v2.0.5** | **140 ms** | **11.2 MB** | **8** |
| | Gitleaks v8.30.1 | 160 ms | 16.0 MB | 5 |
| | TruffleHog v3.95.7 | 9.05 s | 155.7 MB | 3 |
| truffleHogRegexes | **Sentinel v2.0.5** | **60 ms** | **11.6 MB** | **5** |
| | Gitleaks v8.30.1 | 260 ms | 16.8 MB | 6 |
| | TruffleHog v3.95.7 | 6.32 s | 152.9 MB | 0 |

</details>

**Summary:**

| Metric | vs Gitleaks | vs TruffleHog |
|--------|-------------|---------------|
| **Speed** | **1.1x to 7x faster** | **64x to 285x faster** |
| **Memory** | **1.3x to 1.5x less RAM** | **12x to 14x less RAM** |
| **Recall (Accuracy)** | Finds obfuscated & encoded secrets ignored by others | Superior noise filtering (Zero false positives) |

---

## Why Sentinel

| Feature | Sentinel | git-secrets | detect-secrets | TruffleHog |
|---------|:--------:|:-----------:|:--------------:|:----------:|
| Statically compiled, no runtime dependencies | + | — bash | — Python | — Python |
| ARM / Android / Termux native | + | partial | — | — |
| Aho-Corasick O(n) multi-pattern matching | + | — | — | — |
| Shannon entropy analysis | + | — | + | + |
| Context-aware false-positive suppression | + | — | partial | partial |
| BIP-39 seed phrase detection | + | — | — | — |
| Single-layer Base64 decoding | + | — | + | + |
| Concurrent file scanning | + | — | — | — |
| SARIF output (GitHub Code Scanning) | + | — | + | + |
| JSON output | + | — | + | + |
| Global hook installation | + | + | — | — |
| Custom user-defined signatures | + | — | + | — |
| OTA self-updating binary | + | — | — | — |
| Zero external runtime dependencies | + | + | — | — |

---

## Architecture

### Detection Pipeline

```
  git commit (staged changes)
         |
  [Git Interop — internal/git]
   ListStagedFiles()   →  git diff --cached --name-status
   GetStagedDiff()     →  git diff --cached -- <path>  (modified files, added lines only)
   GetStagedContent()  →  git show :<path>              (new files, full content)
         |
  [Pre-flight Filters]
   - Binary detection: null-byte scan of first 8 KB (isBinaryFileFast)
   - Extension exclusion: case-insensitive match
   - Path exclusion: filepath.Match glob patterns
   - File size cap: files > 10 MB skipped
         |
  [Tier 1 — Aho-Corasick Trie  —  internal/trie/trie.go]
   Built once at startup via trie.Build() — allocation-free hot path
   Case-insensitive O(n) scan per line
   BIP-39 mnemonic detection: 12/15/18/21/24 words validated against 2048-word dictionary
   Single-layer Base64 decoding: re-feeds decoded value through trie (catches K8s secrets)
   Blob aggregation: 3+ consecutive high-entropy lines → single CRITICAL finding
         |
  [Tier 2 — Shannon Entropy  —  internal/entropy/entropy.go]
   Base64 tokens: entropy >= entropy_threshold (default 4.5 bits/symbol)
   Hex tokens:    entropy >= threshold × (4.0 / 6.0), min floor 3.0
   Skips: tokens < min_secret_length (default 20), all-identical chars, Java-style identifiers
         |
  [Tier 3 — Context Filter  —  internal/context/context.go]
   Checks (in order): test file path → commented line → UUID → version string
                    → env var placeholder → config placeholder → variable name → short alpha token
   Only Real decisions are forwarded to the reporter
         |
  [Reporter  —  internal/reporter/reporter.go]
   pretty / plain  → stderr    (human-readable, ANSI color)
   json / sarif    → stdout    (or directly to file if --output is used)
         |
  exit 0 (CLEAN)  |  exit 1 (BLOCKED)
```

<details>
<summary>Tier 1 — Aho-Corasick Pattern Matching (detailed)</summary>

**Source:** [`internal/trie/trie.go`](internal/trie/trie.go)

The automaton is built once at startup via `trie.Build(sigs)` and shared across all goroutines without locks. `Automaton.Search` performs zero heap allocations on the hot path.

Construction is two-phase:
1. All signature prefixes are inserted into a trie with lowercased keys.
2. BFS computes failure links and merges output sets so overlapping prefixes (e.g. `sk-` and `sk-proj-`) are both reported in one pass.

The scanner applies additional logic on top of the raw trie results:
- **BIP-39 mnemonics** — line is tested for 12/15/18/21/24 space-separated words, all validated against `bip39.go`.
- **Single-layer Base64 decoding** — extracted values are decoded and re-fed through the trie to catch masked secrets (e.g. Kubernetes Secret manifests).
- **Blob aggregation** — 3+ consecutive lines of the same entropy class are collapsed into one `CRITICAL` finding (`massive-base64-blob` / `massive-hex-blob`) to prevent alert fatigue.
- **Deduplication** — if a generic and a specific signature match the same token, the generic finding is promoted to the specific signature's ID and severity.

</details>

<details>
<summary>Tier 2 — Shannon Entropy Analysis (detailed)</summary>

**Source:** [`internal/entropy/entropy.go`](internal/entropy/entropy.go)

```
H(X) = - sum over i of P(xi) * log2(P(xi))
```

| Score | Meaning |
|-------|---------|
| 0.0 | All bytes identical |
| ~3.5 | English prose |
| ~5.5 – 6.5 | Cryptographically random Base64 secret |
| 8.0 | Perfectly uniform 256-symbol distribution |

Sentinel extracts two token classes per line:
- **Base64 tokens** — runs of `A-Za-z0-9+/=_-`; entropy must exceed `entropy_threshold` (default 4.5).
- **Hex tokens** — runs of `0-9a-fA-F`; must be even-length; threshold is scaled: `entropy_threshold × (4.0 / 6.0)`, floor 3.0.

Pre-filters applied before entropy computation: Java-style identifiers (all letters/dots/underscores) and all-identical-character tokens are discarded.

</details>

<details>
<summary>Tier 3 — Context-Aware Filtering (detailed)</summary>

**Source:** [`internal/context/context.go`](internal/context/context.go)

| Decision | Condition |
|----------|-----------|
| `Real` | None of the suppression checks matched |
| `SafeComment` | Line begins with `//` `#` `*` `/*` `<!--` `--` `;` `%` `!` |
| `SafeTestFile` | Path ends with `_test.go` `_spec.rb` `.test.js` `.spec.ts` `.md` `.rst`, or contains directory: `test` `tests` `testdata` `fixtures` `__tests__` `__mocks__` `mock` `mocks` `sample` `samples` `docs` `doc` |
| `SafeVariableName` | Variable name (left of `=` / `:=`) contains: `dummy` `fake` `mock` `placeholder` `sample` `fixture` `stub` `lorem` `foobar` `your_` `your-` `insert_` `replace_` `changeme` `redacted` `sanitized` `censored` |
| `SafePlaceholder` | Token matches `$VAR`, `${VAR}`, `<...>`, `[[...]]`, `{{...}}` |
| `SafeUUID` | Token matches UUID v4 pattern `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `SafeVersionString` | Token begins with `digit.digit.digit` |

The scanner also rejects tokens that match a `printf`-style format verb, are identical to their signature prefix, contain regex metacharacters, or (for short prefixes ≤ 3 bytes) are pure PascalCase/CamelCase with no special characters.

</details>

### Inline Suppression

Place `sentinel:ignore` on the flagged line or the preceding comment line:

```go
// sentinel:ignore
apiKey := "sk_live_example_for_documentation"

apiKey := "sk_live_example_for_documentation" // sentinel:ignore
```

```bash
# sentinel:ignore
STRIPE_KEY="sk_live_example"
```

```html
<!-- sentinel:ignore -->
<secret>sk-ant-api03-documented-example</secret>
```

A same-line annotation suppresses only that line. A comment-line annotation suppresses the immediately following line.

---

## Signature Coverage

<details>
<summary>View all 68 builtin signatures</summary>

| Category | Signatures |
|----------|-----------|
| **GitHub** | Classic PAT (`ghp_`), OAuth (`gho_`), App Installation (`ghs_`), Refresh (`ghr_`), Fine-grained PAT (`github_pat_`) |
| **GitLab** | Personal Access Token (`glpat-`), Pipeline Trigger (`glptt-`), Runner Registration (`GR1348941`) |
| **AWS** | Access Key ID (`AKIA`, validated `AKIA[0-9A-Z]{16}`), MFA Device (`ABIA`), STS Temporary Key (`ASIA`) |
| **Google Cloud** | Service Account JSON (`"type": "service_account"`), API Key (`AIzaSy`), OAuth Client ID (`.apps.googleusercontent.com`) |
| **Slack** | Bot (`xoxb-`), User (`xoxp-`), Workspace (`xoxa-`), Refresh (`xoxr-`) |
| **Stripe** | Live Secret (`sk_live_`), Live Restricted (`rk_live_`), Test Secret (`sk_test_`) |
| **OpenAI** | Classic (`sk-`), Project key (`sk-proj-`) |
| **Anthropic** | API key (`sk-ant-`) |
| **Twilio** | Account SID (`AC`, regex-validated), Auth Token (`SK`, regex-validated) |
| **SendGrid** | API key (`SG.`, regex-validated: `SG.[a-zA-Z0-9_-]{22}.[a-zA-Z0-9_-]{43}`) |
| **Mailgun** | API key (`key-`) |
| **npm** | Automation/Publish token (`npm_`) |
| **JWT** | JSON Web Token (`eyJ`, strict 3-part dot-separated regex) |
| **Private Keys (PEM)** | RSA, EC, OpenSSH, PKCS#8, PGP, DSA — all `-----BEGIN ... PRIVATE KEY-----` variants |
| **Databases** | PostgreSQL (`postgresql://`), MySQL (`mysql://`), MongoDB SRV (`mongodb+srv://`), MongoDB (`mongodb://`), Redis (`redis://:@`) |
| **HashiCorp Vault** | Service token (`hvs.`), Batch token (`hvb.`) |
| **DigitalOcean** | Personal Access Token (`dop_v1_`) |
| **Vercel** | API Token (`vercel_`) |
| **Cloudflare** | API Token (`CF_`) |
| **HuggingFace** | API Token (`hf_`) |
| **Shopify** | Custom App (`shpca_`), Private App (`shppa_`), Access Token (`shpat_`) |
| **Generic** | `password=` `secret=` `api_key=` `token=` and their YAML/JSON colon variants |
| **Django** | `SECRET_KEY =` |
| **WordPress** | `AUTH_KEY` `SECURE_AUTH_KEY` `LOGGED_IN_KEY` `NONCE_KEY` `AUTH_SALT` `SECURE_AUTH_SALT` `LOGGED_IN_SALT` `NONCE_SALT` |
| **Crypto Wallets** | BIP-39 mnemonic (12/15/18/21/24 words, validated against 2048-word dictionary) |

Custom signatures can be added in `.sentinel.yaml` and are compiled into the same automaton at startup — no performance overhead.

</details>

---

## Installation

### Pre-compiled Binary (Recommended)

Download the binary for your platform from the [Releases page](https://github.com/sentinel-cli/sentinel/releases):

```bash
# Replace <version> and <arch>  e.g.  linux-amd64  linux-arm64  darwin-amd64  darwin-arm64
wget https://github.com/sentinel-cli/sentinel/releases/download/<version>/sentinel-<version>-<arch> -O sentinel
chmod +x sentinel
mv sentinel /usr/local/bin/       # Linux / macOS
# mv sentinel $PREFIX/bin/        # Termux (Android)
sentinel version
```

### Go Install

```bash
go install github.com/sentinel-cli/sentinel/v2/cmd/sentinel@latest
```

### Build from Source

```bash
git clone https://github.com/sentinel-cli/sentinel.git
cd sentinel
make build            # outputs to dist/sentinel
./dist/sentinel version
```

---

### Git Hook Setup

**Protect the current repository:**

```bash
sentinel install          # installs .git/hooks/pre-commit
sentinel install --force  # overwrites an existing hook
```

**Protect every repository on this machine (global):**

```bash
sentinel install --global
# Creates ~/.config/sentinel/hooks/pre-commit
# Runs: git config --global core.hooksPath ~/.config/sentinel/hooks
```

**Remove global hook:**

```bash
git config --global --unset core.hooksPath
```

**Full uninstall — removes binary, hooks, and config directory:**

```bash
sentinel uninstall
```

### Native pre-commit Framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sentinel-cli/sentinel
    rev: v2.0.5
    hooks:
      - id: sentinel
```

---

## Configuration

Sentinel searches for `.sentinel.yaml` in this order:

1. `--config` / `-c` flag value
2. `.sentinel.yaml` in the current working directory (repository root)
3. `~/.sentinel.yaml` in the home directory

With no config file, built-in defaults apply. The file is merged on top of defaults, so omitted fields keep their default values.

<details>
<summary>Full configuration reference</summary>

```yaml
# Shannon entropy threshold (bits/symbol). Range: 0.0 to 8.0.
# Raise to reduce false positives. Lower to increase sensitivity.
# Default: 4.5
entropy_threshold: 4.5

# Minimum token length for entropy analysis.
# Tokens shorter than this produce unreliable scores.
# Default: 20
min_secret_length: 20

# Maximum file size to scan. Files exceeding this are skipped.
# Default: 10485760 (10 MB)
max_file_size_bytes: 10485760

# Whether to scan binary files (detected by null-byte in first 8 KB).
# Default: false
scan_binary_files: false

# Glob patterns (relative to repo root) to skip entirely.
# Default list below:
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "*.lock"
  - "go.sum"

# File extensions to skip (case-insensitive).
# Default includes images, fonts, audio, video, archives, binaries, office documents.
exclude_extensions:
  - ".png"
  - ".jpg"
  - ".gif"
  - ".zip"
  - ".tar"
  - ".gz"
  - ".exe"
  - ".dll"
  - ".so"
  - ".pdf"

# Allowlist: findings whose token matches are silently ignored.
# Supports exact strings and filepath.Match glob patterns.
allowlist_patterns:
  - "AKIAIOSFODNN7EXAMPLE"
  - "sk_test_*"
  - "*-dummy-token-*"

# Disable individual detection tiers. Use with caution.
disable_tiers:
  trie: false     # disables Tier 1 Aho-Corasick matching
  entropy: false  # disables Tier 2 entropy analysis
  context: false  # disables Tier 3 suppression — expect many false positives

# Stop after the first finding. Useful in CI fail-fast loops.
fail_fast: false

# Print debug output to stderr.
verbose: false

# Custom signatures compiled into the Aho-Corasick automaton alongside builtins.
# Severity must be one of: CRITICAL, HIGH, MEDIUM, LOW  (defaults to HIGH if omitted).
custom_signatures:
  - id: "internal-api-key"
    description: "Proprietary internal service credential"
    prefix: "mycompany_key_"
    severity: "CRITICAL"
    regex: "^mycompany_key_[a-zA-Z0-9]{32}$"
```

</details>

### Entropy Threshold Reference

| Value | Behavior |
|-------|----------|
| 3.0 | Very sensitive — may flag base32 identifiers |
| 3.5 | High sensitivity — catches most secrets, slightly elevated noise |
| **4.5** | **Default** — cryptographically random secrets, low false-positive rate |
| 5.0+ | Strict — may miss weak passwords; minimal noise |

---

## Usage

### Automatic (Pre-commit Hook)

After `sentinel install`, the hook fires on every `git commit` and scans only staged content:
- **New files** — full content via `git show :<path>`
- **Modified files** — added lines only via `git diff --cached -- <path>`

### Ad-hoc Scanning

```bash
# Single file
sentinel scan config/production.yaml

# Directory (non-recursive)
sentinel scan ./config

# Directory, recursive (skips .git, build, node_modules automatically)
sentinel scan -r ./src

# Full Git history audit (streams git log --all -p; deduplicates by token)
sentinel scan --history .

# JSON output — written to stdout for piping
sentinel scan -f json -r ./src | jq '.findings[] | select(.severity == "CRITICAL")'

# SARIF output saved directly to file (keeps pretty terminal logs)
sentinel scan -f sarif -o sentinel.sarif .

```

> In ad-hoc mode, files are processed concurrently using `max(runtime.NumCPU(), 4)` goroutines.
> In history mode, the Git log is streamed with a 10 MB line buffer; unique findings are deduplicated by token value.

### CI Integration

#### GitHub Actions (Official Reusable Action)
The easiest way to integrate Sentinel into your GitHub Actions workflow is by using our official reusable action. It handles Go installation, compilation cache, and scanning automatically:

```yaml
- name: Run Sentinel Git Secrets Scanner
  uses: sentinel-cli/sentinel@v2
  with:
    version: 'latest' # Optional: version to use (e.g. 'v2.0.5')
    args: '.'         # Optional: arguments to pass (e.g. "." or "--history .")
    sarif: 'true'     # Optional: set to 'true' to export findings as a SARIF report
```

To upload the results to GitHub Advanced Security (Code Scanning Alerts), configure the upload step:

```yaml
- name: Upload SARIF report
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel-results.sarif
```

> [!TIP]
> You can inspect the official [action.yml](action.yml) file in the root of this repository to use as a template or reference for building your own custom GitHub Actions.



```yaml
# GitLab CI
sentinel:
  script:
    - sentinel scan -f json -o sentinel-report.json .
    - jq -e '.status == "clean"' sentinel-report.json
  artifacts:
    reports:
      sast: sentinel-report.json

```

### Command Reference

<details>
<summary>sentinel run — pre-commit hook entry point</summary>

Scans staged changes only. Invoked automatically by the Git hook.

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config` | auto-detected | Path to `.sentinel.yaml` |
| `-f, --format` | `pretty` | `pretty` `json` `plain` `sarif` |
| `--fail-fast` | false | Stop after the first finding |
| `-v, --verbose` | false | Debug output to stderr |

</details>

<details>
<summary>sentinel scan [path...] — ad-hoc scanner</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config` | auto-detected | Path to `.sentinel.yaml` |
| `-f, --format` | `pretty` | `pretty` `json` `plain` `sarif` |
| `-o, --output` | | Write report directly to file, preserving pretty stdout logs |
| `-r, --recursive` | false | Walk subdirectories |
| `--history` | false | Scan entire Git commit history |
| `-v, --verbose` | false | Debug output to stderr |

</details>

<details>
<summary>sentinel install — hook installer</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--global` | false | Install globally via `core.hooksPath` |
| `--repo` | `.` | Target repository root |
| `-f, --force` | false | Overwrite existing hook |

</details>

<details>
<summary>sentinel update — OTA self-updater</summary>

Downloads the latest release for the current OS/arch from the GitHub Releases API, verifies the binary, and atomically replaces the running executable. Falls back to `go install` if no pre-compiled binary matches the platform.

A background check runs on each invocation, querying the API at most once per 24 hours. The result is cached at `~/.config/sentinel/last_check.json`. A notice is printed to stderr if a newer version is available.

</details>

---

## Output Reference

**Clean (exit 0):**

```
  SENTINEL CLEAN  --  4 file(s) scanned in 3.2ms
```

**Blocked (exit 1):**

```
   CRITICAL   cmd/main.go:12
               [PATTERN] GitHub Personal Access Token (classic)
               Token:  ghp_AB****************************cdef
               -> token := "ghp_AB...cdef"

   HIGH       config/settings.go:8
               [ENTROPY] High-entropy BASE64 string (entropy=6.23)
               Token:  wJalrX****************************EY
               -> AWS_SECRET = "wJalrX...EY"

---------------------------------------------------------------------
  Files scanned : 4  |  Elapsed : 5.1ms
  CRITICAL:1   HIGH:1   MEDIUM:0   LOW:0
---------------------------------------------------------------------
  COMMIT BLOCKED -- remove the secrets above and try again.
```

**JSON schema (`-f json` — written to stdout):**

```json
{
  "sentinel_version": "v2.0.5",
  "status": "blocked",
  "scanned_files": 4,
  "elapsed_ms": 5,
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

When clean: `"status": "clean"`, `"findings": []`.

**SARIF (`-f sarif` — written to stdout):** SARIF 2.1.0, compatible with GitHub Advanced Security Code Scanning.

---

## False Positive Handling

Tier 3 automatically eliminates the vast majority of false positives. For persistent cases:

| Method | When to use |
|--------|------------|
| `sentinel:ignore` comment | One-off suppression for a specific line |
| Safe variable name (`dummy_`, `fake_`, `mock_`) | Test or documentation values that look like secrets |
| `allowlist_patterns` in config | Known safe tokens used repeatedly across the codebase |
| Move to test file path | Values in `tests/`, `testdata/`, `*_test.go`, `.md` are suppressed automatically |
| `${ENV_VAR}` reference syntax | Replaced at runtime — not a hardcoded secret |
| `exclude_paths` in config | Entire directories that should never be scanned |
| Raise `entropy_threshold` | Codebase has many long high-entropy non-secret identifiers |

```yaml
# .sentinel.yaml
allowlist_patterns:
  - "AKIAIOSFODNN7EXAMPLE"   # exact match
  - "sk_test_*"              # all Stripe test keys
  - "*-placeholder-*"
```

---

## Running Tests

```bash
make test     # all tests with race detector
make bench    # benchmarks
make cover    # HTML coverage report → coverage.html
make lint     # staticcheck
```

Representative benchmark output (shows zero allocations on the hot scan path):

```
BenchmarkAutomatonBuild-8        3     195,234 ns/op    327,680 B/op
BenchmarkSearch-8             3000     341,012 ns/op          0 B/op   <- 0 allocs
BenchmarkSearchWithHit-8      2000     412,887 ns/op      3,456 B/op
BenchmarkShannonSmall-8    5000000         234 ns/op          0 B/op
BenchmarkFullPipeline-8         500   2,341,201 ns/op     12,340 B/op
```

---

## Contributing

Contributions are welcome. All contributors must agree to the **[Contributor License Agreement](CLA.md)**. By submitting a pull request you confirm that you transfer copyright of the contribution to Khaled Hani. This protects the project's dual-licensing model.

---

## Author

Developed by **Khaled Hani** — [https://t.me/A245F](https://t.me/A245F)

---

## License

GNU Affero General Public License v3.0.

Commercial SaaS deployment or distribution of a modified version without releasing the source under AGPL-3.0 is prohibited. See [LICENSE](LICENSE) for full terms.

---

<div align="center">
Designed for security. Engineered for efficiency.
</div>
