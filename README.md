# Sentinel — Git Secret Scanner & Pre-Commit Hook

<div align="center">

```text
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

**Enterprise-grade secret detector and Git pre-commit hook, written in Go.**

[![CI](https://github.com/sentinel-cli/sentinel/actions/workflows/ci.yml/badge.svg?v=2)](https://github.com/sentinel-cli/sentinel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sentinel-cli/sentinel?color=3670A0&logo=github)](https://github.com/sentinel-cli/sentinel/releases)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![Reference](https://pkg.go.dev/badge/github.com/sentinel-cli/sentinel/v2.svg)](https://pkg.go.dev/github.com/sentinel-cli/sentinel/v2)
[![License](https://img.shields.io/badge/license-AGPL_3.0-blue)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%2FTermux-informational)](#installation)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

</div>

---

## Overview

**Sentinel** is a statically compiled, zero-dependency Git pre-commit hook and credentials scanner written in Go. It automatically blocks accidental commits of API keys, SSH private keys, cloud credentials, database connection strings, and other sensitive material before they reach version control.

Sentinel operates through a **three-tier detection pipeline** built for speed and accuracy:

| Tier | Engine | Purpose |
|------|--------|---------|
| 1 — PATTERN | Aho-Corasick automaton | Matches 68 known secret signatures in O(n) time |
| 2 — ENTROPY | Shannon entropy analysis | Detects novel or unknown secrets by information density |
| 3 — CONTEXT | Context classifier | Eliminates false positives from comments, tests, and placeholders |

A finding must pass all three tiers before it is reported.

---

## Terminal Demo

```
asciinema play https://sentinel-cli.github.io/sentinel/demo.cast
```

![Sentinel Demo](docs/demo.gif)

---

## Table of Contents

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

The following benchmarks were measured on real-world repositories with Sentinel v2.0.4.

### Filesystem Scan

| Repository | Tool | Time | Peak RAM | Findings |
|:---|:---|:---|:---|:---|
| sample\_secrets | Sentinel v2.0.4 | 20 ms | 11.2 MB | **2** |
| | Gitleaks v8.30.1 | 150 ms | 37.6 MB | 1 |
| | TruffleHog v3.95.7 | 7.26 s | 209.2 MB | 1 |
| truffleHogRegexes | Sentinel v2.0.4 | 30 ms | 11.8 MB | **4** |
| | Gitleaks v8.30.1 | 210 ms | 37.2 MB | 1 |
| | TruffleHog v3.95.7 | 7.13 s | 207.8 MB | 1 |

### Git History Scan

| Repository | Tool | Time | Peak RAM | Findings |
|:---|:---|:---|:---|:---|
| sample\_secrets | Sentinel v2.0.4 | 30 ms | 10.9 MB | **8** |
| | Gitleaks v8.30.1 | 170 ms | 37.3 MB | 5 |
| | TruffleHog v3.95.7 | 3.21 s | 192.6 MB | 1 |
| truffleHogRegexes | Sentinel v2.0.4 | 40 ms | 12.0 MB | **6** |
| | Gitleaks v8.30.1 | 220 ms | 40.1 MB | 8 |
| | TruffleHog v3.95.7 | 3.24 s | 192.8 MB | 1 |

Sentinel is approximately **6x faster** than Gitleaks and **180x faster** than TruffleHog, using **3x less memory** than Gitleaks and **17x less** than TruffleHog.

---

## Why Sentinel

| Feature | Sentinel | git-secrets | detect-secrets | TruffleHog |
|---------|----------|-------------|----------------|------------|
| Statically compiled, no runtime dependencies | Yes | No — bash | No — Python | No — Python |
| ARM / Android / Termux native | Yes | Partial | No | No |
| Aho-Corasick O(n) multi-pattern matching | Yes | No | No | No |
| Shannon entropy analysis | Yes | No | Yes | Yes |
| Context-aware false-positive suppression | Yes | No | Partial | Partial |
| BIP-39 mnemonic seed phrase detection | Yes | No | No | No |
| Single-layer Base64 decoding | Yes | No | Yes | Yes |
| Concurrent file scanning | Yes | No | No | No |
| SARIF output (GitHub Code Scanning) | Yes | No | Yes | Yes |
| JSON output for automation | Yes | No | Yes | Yes |
| Global hook installation | Yes | Yes | No | No |
| Custom user-defined signatures | Yes | No | Yes | No |
| Self-updating binary | Yes | No | No | No |

---

## Architecture

### Detection Pipeline

```
  git commit (staged changes)
         |
  [Git Interop — internal/git]
   git diff --cached --name-status
   git diff --cached -- <path>
   git show :<path>  (new files)
         |
  [Pre-flight Filters]
   - Binary detection (null-byte scan of first 8 KB)
   - Extension exclusion (case-insensitive)
   - Path exclusion (glob matching)
   - Size cap: files > 10 MB are skipped
         |
  [Tier 1 — Aho-Corasick Trie  —  internal/trie]
   Built once at startup from 68 signatures
   O(n) single-pass over each line
   Case-insensitive matching
   BIP-39 mnemonic detection (12–24 word phrases)
   Single-layer Base64 decoding (for Kubernetes secrets etc.)
         |
  [Tier 2 — Shannon Entropy  —  internal/entropy]
   Base64-alphabet token extraction per line
   Hex-alphabet token extraction (even-length only)
   Entropy threshold: 4.5 bits/symbol (Base64)
   Scaled threshold for hex: threshold × (4.0 / 6.0), min 3.0
   Tokens below min_secret_length (default 20) are skipped
   Zero-entropy (all-identical) tokens are skipped
         |
  [Tier 3 — Context Filter  —  internal/context]
   Suppression checks (in order):
     1. File path — test files, docs, fixtures
     2. Commented-out line — //, #, /*, <!-- etc.
     3. UUID v4 pattern
     4. Version string pattern
     5. Environment variable placeholder ($VAR, ${VAR})
     6. Config placeholder (<placeholder>, {{template}})
     7. Variable name — dummy, fake, mock, sample, stub, etc.
     8. Short pure-alpha token (< 12 chars)
         |
  [Reporter  —  internal/reporter]
   Formats: pretty (ANSI color) | json | plain | sarif
   JSON and SARIF go to stdout; pretty and plain go to stderr
         |
  exit 0  (CLEAN)   or   exit 1  (BLOCKED)
```

---

### Tier 1 — Aho-Corasick Pattern Matching

**Source:** [`internal/trie/trie.go`](internal/trie/trie.go)

The automaton is built once at startup via `trie.Build(sigs)` and reused across all goroutines without locks. The hot scan path (`Automaton.Search`) performs zero heap allocations.

Construction is a two-phase process:
1. All signature prefixes are inserted into a trie with lowercased keys.
2. BFS computes failure links and merges output sets so overlapping prefixes (e.g. `sk-` and `sk-proj-`) are both reported in one pass.

Line numbers are tracked incrementally during the scan; `LineContent` is capped at 512 bytes per match.

**Additional detection handled at the pipeline level** (in `scanner.go`):
- **BIP-39 mnemonics** — the line is tested for 12, 15, 18, 21, or 24 words, all validated against the 2048-word dictionary in `internal/trie/bip39.go`.
- **Single-layer Base64 decoding** — when a value extracted from an assignment is a valid standard Base64 string, it is decoded in-memory and re-fed through the trie. This catches secrets stored in Kubernetes Secret manifests and similar encoded forms.
- **Blob aggregation** (`aggregateBlobs`) — three or more consecutive lines of the same high-entropy class (`high-entropy-base64` or `high-entropy-hex`) are collapsed into one `CRITICAL` finding labeled `massive-<kind>-blob` to prevent alert fatigue.
- **Deduplication** — if a generic-signature hit and a specific-signature hit refer to the same token, the generic finding is promoted to the specific signature ID and severity.

---

### Tier 2 — Shannon Entropy Analysis

**Source:** [`internal/entropy/entropy.go`](internal/entropy/entropy.go)

Shannon entropy measures the information density of a byte sequence:

```
H(X) = - sum over i of P(xi) * log2(P(xi))
```

| Range | Interpretation |
|-------|----------------|
| 0.0 | All bytes identical |
| ~3.5 | English prose |
| ~5.5 – 6.5 | Cryptographically random Base64 secret |
| 8.0 | Perfectly uniform 256-symbol distribution |

Sentinel extracts two classes of tokens per line:

- **Base64 tokens** — contiguous runs of `A-Za-z0-9+/=_-`; requires entropy >= `entropy_threshold` (default 4.5).
- **Hex tokens** — contiguous runs of `0-9a-fA-F`; must have even length; uses a scaled threshold of `entropy_threshold * (4.0 / 6.0)` with a minimum floor of 3.0.

Tokens from pure Java-style identifiers (all letters, dots, and underscores) and zero-entropy (all-identical) tokens are discarded before entropy is computed.

---

### Tier 3 — Context-Aware Filtering

**Source:** [`internal/context/context.go`](internal/context/context.go)

The classifier inspects the file path, the full line text, and the extracted token. It returns one of seven decisions:

| Decision | Condition |
|----------|-----------|
| `Real` | None of the suppression checks matched — report the finding |
| `SafeComment` | Line begins with `//`, `#`, `*`, `/*`, `<!--`, `--`, `;`, `%`, or `!` |
| `SafeTestFile` | Path ends with `_test.go`, `_spec.rb`, `.test.js`, `.spec.ts`, `.md`, `.rst`, or contains a directory named `test`, `tests`, `testdata`, `fixtures`, `__tests__`, `__mocks__`, `mock`, `mocks`, `sample`, `samples`, `docs`, `doc` |
| `SafeVariableName` | Variable name (text left of `=` or `:`) contains: `dummy`, `fake`, `mock`, `placeholder`, `sample`, `fixture`, `stub`, `lorem`, `foobar`, `your_`, `your-`, `insert_`, `replace_`, `changeme`, `redacted`, `sanitized`, `censored` |
| `SafePlaceholder` | Token matches `$VAR`, `${VAR}`, `<something>`, `[[something]]`, or `{{something}}` |
| `SafeUUID` | Token matches the UUID v4 pattern `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `SafeVersionString` | Token starts with a digit-dot-digit-dot-digit sequence |

Only `Real` findings are passed to the reporter.

The scanner additionally rejects tokens that:
- Match a `printf`-style format verb (e.g., `%s`, `%v`, `%d`).
- Are identical to their signature prefix (empty secret material).
- Contain regex metacharacters `[`, `]`, `{`, `}`, `(?:`, or `.*`.
- For short prefixes (<= 3 bytes): the suffix is a pure PascalCase/CamelCase identifier with no non-alphanumeric characters.

---

### Inline Suppression

Any line containing `sentinel:ignore` — whether the annotation appears on the same line or on the preceding comment line — is excluded from scanning.

Supported annotation styles:

```go
// sentinel:ignore
apiKey := "sk_live_realvalue..."

apiKey := "sk_live_realvalue..." // sentinel:ignore
```

```bash
# sentinel:ignore
API_KEY="sk_live_realvalue..."
```

```html
<!-- sentinel:ignore -->
<secret>sk-ant-api03-...</secret>
```

A same-line `sentinel:ignore` suppresses only that line. A comment-line annotation suppresses the immediately following line.

---

### Module Layout

```
sentinel/
├── cmd/
│   └── sentinel/
│       ├── commands/
│       │   ├── helpers.go        shared CLI helper (executeCommand)
│       │   ├── install.go        sentinel install — hook writer
│       │   ├── run.go            sentinel run — pre-commit entry point
│       │   ├── scan.go           sentinel scan — ad-hoc / history scanner
│       │   ├── uninstall.go      sentinel uninstall — full cleanup
│       │   ├── update.go         sentinel update — OTA self-updater
│       │   └── version.go        sentinel version — build metadata
│       └── main.go               Cobra CLI root; SSL bootstrap for Termux
│
├── docs/                         GitHub Pages landing site (HTML/CSS/JS)
│
├── internal/
│   ├── config/config.go          YAML loader and validator; all defaults
│   ├── context/context.go        Tier 3 context classifier
│   ├── entropy/entropy.go        Tier 2 Shannon entropy engine
│   ├── git/git.go                Git subprocess wrappers
│   ├── reporter/reporter.go      Pretty / JSON / Plain / SARIF renderer
│   ├── scanner/scanner.go        Three-tier pipeline orchestrator (stateless)
│   ├── trie/
│   │   ├── bip39.go              2048-word BIP-39 dictionary + init map
│   │   └── trie.go               Aho-Corasick automaton + 68 builtin signatures
│   └── updater/updater.go        Background update check (once per 24 hours)
│
├── pkg/
│   └── version/version.go        Build metadata; injected via ldflags at build time
│
├── tests/                        Integration and unit tests for all tiers
├── scripts/                      build.sh, test.sh
├── .github/workflows/            CI and coverage pipelines
├── .sentinel.yaml.example        Annotated reference configuration
├── Makefile                      Developer targets: build, test, bench, cover, lint
└── go.mod                        Module: github.com/sentinel-cli/sentinel/v2; Go 1.22+
```

---

## Signature Coverage

Sentinel's Tier 1 automaton contains **68 builtin signatures** spanning all major credential families. Custom signatures can be appended via the config file and are compiled into the same automaton at startup.

| Category | Signatures |
|----------|-----------|
| GitHub | Classic PAT (`ghp_`), OAuth (`gho_`), App Installation (`ghs_`), Refresh (`ghr_`), Fine-grained PAT (`github_pat_`) |
| GitLab | Personal Access Token (`glpat-`), Pipeline Trigger (`glptt-`), Runner Registration (`GR1348941`) |
| AWS | Access Key ID (`AKIA`, validator: `AKIA[0-9A-Z]{16}`), MFA Device (`ABIA`), STS Temporary Key (`ASIA`) |
| Google Cloud | Service Account JSON (`"type": "service_account"`), API Key (`AIzaSy`), OAuth Client ID suffix (`.apps.googleusercontent.com`) |
| Slack | Bot (`xoxb-`), User (`xoxp-`), Workspace (`xoxa-`), Refresh (`xoxr-`) |
| Stripe | Live Secret (`sk_live_`), Live Restricted (`rk_live_`), Test Secret (`sk_test_`) |
| OpenAI | Classic key (`sk-`), Project key (`sk-proj-`) |
| Anthropic | API key (`sk-ant-`) |
| Twilio | Account SID (`AC`, regex-validated), Auth Token (`SK`, regex-validated) |
| SendGrid | API key (`SG.`, regex-validated: `SG.[a-zA-Z0-9_-]{22}.[a-zA-Z0-9_-]{43}`) |
| Mailgun | API key (`key-`) |
| npm | Automation/Publish token (`npm_`) |
| JWT | JSON Web Token (`eyJ`, strict 3-part dot-separated regex) |
| Private Keys (PEM) | RSA, EC, OpenSSH, PKCS#8, PGP, DSA — all `-----BEGIN ... PRIVATE KEY-----` variants |
| Databases | PostgreSQL DSN (`postgresql://`), MySQL (`mysql://`), MongoDB SRV (`mongodb+srv://`), MongoDB plain (`mongodb://`), Redis (`redis://:@`) |
| HashiCorp Vault | Service token (`hvs.`), Batch token (`hvb.`) |
| DigitalOcean | Personal Access Token (`dop_v1_`) |
| Vercel | API Token (`vercel_`) |
| Cloudflare | API Token (`CF_`) |
| HuggingFace | API Token (`hf_`) |
| Shopify | Custom App (`shpca_`), Private App (`shppa_`), Access Token (`shpat_`) |
| Generic assignments | `password=`, `secret=`, `api_key=`, `token=` |
| Generic YAML / JSON | `password:`, `secret:`, `api_key:`, `token:` |
| Django | `SECRET_KEY =` |
| WordPress | `AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY`, `AUTH_SALT`, `SECURE_AUTH_SALT`, `LOGGED_IN_SALT`, `NONCE_SALT` |
| Crypto Wallets | BIP-39 mnemonic (12 / 15 / 18 / 21 / 24 words, all validated against 2048-word dictionary) |

---

## Installation

### Pre-compiled Binary (Recommended)

Download the binary for your platform from the [Releases page](https://github.com/sentinel-cli/sentinel/releases):

```bash
# Replace <version> and <arch> (e.g. linux-amd64, linux-arm64, darwin-amd64)
wget https://github.com/sentinel-cli/sentinel/releases/download/<version>/sentinel-<version>-<arch> -O sentinel
chmod +x sentinel

# Linux / macOS
mv sentinel /usr/local/bin/

# Termux (Android)
mv sentinel $PREFIX/bin/

sentinel version
```

### Go Install

```bash
go install github.com/sentinel-cli/sentinel/v2/cmd/sentinel@latest
```

Requires `$(go env GOPATH)/bin` in `$PATH`.

### Build from Source

```bash
git clone https://github.com/sentinel-cli/sentinel.git
cd sentinel
make build
./dist/sentinel version
```

The `Makefile` injects `Version`, `Commit`, and `Date` via `-ldflags` into `pkg/version/version.go`.

---

### Installing the Git Hook

**Current repository:**
```bash
sentinel install          # writes .git/hooks/pre-commit
sentinel install --force  # overwrites an existing hook
```

**All repositories (global):**
```bash
sentinel install --global
# Creates ~/.config/sentinel/hooks/pre-commit
# Sets: git config --global core.hooksPath ~/.config/sentinel/hooks
```

**Remove global hook only:**
```bash
git config --global --unset core.hooksPath
```

**Full uninstall (binary + hooks + config directory):**
```bash
sentinel uninstall
```

---

### pre-commit Framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sentinel-cli/sentinel
    rev: v2.0.4
    hooks:
      - id: sentinel
```

---

## Configuration

### Resolution Order

1. Path supplied via `--config` / `-c`
2. `.sentinel.yaml` in the current working directory (repository root)
3. `~/.sentinel.yaml` in the user home directory

If no file is found, built-in defaults apply. The config is unmarshaled on top of the defaults, so omitted fields retain their default values.

### Full Reference

```yaml
# Shannon entropy threshold (bits/symbol).
# Valid range: 0.0 to 8.0.
# Raise to reduce false positives. Lower to increase sensitivity.
# Default: 4.5
entropy_threshold: 4.5

# Minimum token length for entropy analysis.
# Tokens shorter than this produce unreliable entropy scores.
# Default: 20
min_secret_length: 20

# Maximum file size to scan. Files exceeding this are skipped with a warning.
# Default: 10485760 (10 MB)
max_file_size_bytes: 10485760

# Whether to attempt scanning binary files (detected by null-byte in first 8 KB).
# Default: false
scan_binary_files: false

# Glob patterns (relative to repo root) to skip.
# Default list:
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "*.lock"
  - "go.sum"

# File extensions to skip (case-insensitive).
# Default list includes images, fonts, audio, video, archives, binaries, office docs.
exclude_extensions:
  - ".png"
  - ".jpg"
  - ".jpeg"
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

# Exit after the first finding. Useful for fast CI fail loops.
# Default: false
fail_fast: false

# Print debug output (skipped files, verbose decisions) to stderr.
# Default: false
verbose: false

# Custom signatures compiled into the Aho-Corasick automaton alongside builtins.
# Severity must be one of: CRITICAL, HIGH, MEDIUM, LOW (defaults to HIGH if omitted).
custom_signatures:
  - id: "internal-api-key"
    description: "Proprietary internal service credential"
    prefix: "mycompany_key_"
    severity: "CRITICAL"
    regex: "^mycompany_key_[a-zA-Z0-9]{32}$"   # optional validation regex
```

### Entropy Threshold Reference

| Value | Behavior |
|-------|----------|
| 3.0 | Very sensitive — may flag base32 identifiers and short low-entropy passwords |
| 3.5 | High sensitivity — catches most secrets; slightly elevated noise |
| 4.5 | **Default** — catches cryptographically random secrets; low false-positive rate |
| 5.0 | Strict — may miss weak passwords; minimal noise |

---

## Usage

### Pre-commit Hook (Automatic)

After `sentinel install`, the hook fires automatically on every `git commit` and scans only the staged diff (added lines of modified files, full content of new files).

```bash
git add src/config.go
git commit -m "add config"
# Sentinel scans staged content here
```

For new files (status A), Sentinel reads the staged blob with `git show :<path>`.
For modified files (status M/R/C), it reads added lines from `git diff --cached -- <path>`.

### Ad-hoc Scanning

```bash
# Single file
sentinel scan config/production.yaml

# Directory (non-recursive, reads immediate children only)
sentinel scan ./config

# Directory, recursive (walks all subdirectories; skips .git, build, node_modules)
sentinel scan -r ./src

# Full Git history audit (streams git log --all -p, deduplicates by token)
sentinel scan --history .

# JSON output for automation
sentinel scan -f json -r ./src | jq '.findings[] | select(.severity == "CRITICAL")'

# SARIF for GitHub Advanced Security
sentinel scan -f sarif -r . > sentinel.sarif
```

In ad-hoc mode, files are processed concurrently using `max(runtime.NumCPU(), 4)` worker goroutines. Findings from concurrent workers are deduplicated by token value before output.

In history mode, Sentinel pipes `git log --all -p` through a streaming scanner with a 10 MB line buffer, producing one finding per unique token across the entire commit tree.

### Command Reference

#### `sentinel run`

Invoked automatically by the Git hook. Scans staged changes only.

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config` | auto-detected | Path to `.sentinel.yaml` |
| `-f, --format` | `pretty` | Output format: `pretty`, `json`, `plain`, `sarif` |
| `--fail-fast` | false | Stop after the first finding |
| `-v, --verbose` | false | Print debug information to stderr |

#### `sentinel scan [path...]`

Ad-hoc scan of files, directories, or history.

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config` | auto-detected | Path to `.sentinel.yaml` |
| `-f, --format` | `pretty` | Output format: `pretty`, `json`, `plain`, `sarif` |
| `-r, --recursive` | false | Recursively walk subdirectories |
| `--history` | false | Scan entire Git commit history |
| `-v, --verbose` | false | Print debug information to stderr |

#### `sentinel install`

| Flag | Default | Description |
|------|---------|-------------|
| `--global` | false | Install into `~/.config/sentinel/hooks/pre-commit` and set `core.hooksPath` |
| `--repo` | `.` | Target repository root path |
| `-f, --force` | false | Overwrite an existing hook without prompting |

#### `sentinel update`

Downloads the latest release binary for the current OS and architecture from the GitHub Releases API, verifies it, and atomically replaces the running executable. Falls back to `go install` if no pre-compiled binary matches the current platform.

A background update check runs asynchronously on each invocation. It queries the API at most once per 24 hours (result cached at `~/.config/sentinel/last_check.json`) and prints a notice to stderr if a newer version is available.

#### `sentinel uninstall`

Removes: the running binary (resolved dynamically from `os.Executable()`), `~/.config/sentinel/`, `git config --global core.hooksPath`, and `.git/hooks/pre-commit` in the current repository.

#### `sentinel version`

Prints `Version`, `Commit` (7-char SHA), and `Date` as injected by the build system.

---

## Output Reference

### Pretty Format (default)

**Clean scan (exit 0):**
```
  SENTINEL CLEAN  --  4 file(s) scanned in 3.2ms
```

**Blocked scan (exit 1):**
```
   CRITICAL   cmd/main.go:12
               [PATTERN] GitHub Personal Access Token (classic)
               Token:  ghp_AB****************************cdef
               -> token := "ghp_AB...cdef"

   HIGH       config/settings.go:8
               [ENTROPY] High-entropy BASE64 string (entropy=6.23)
               Token:  wJalrX****************************EY
               Entropy: 6.2301 bits/symbol
               -> AWS_SECRET = "wJalrX...EY"

---------------------------------------------------------------------
  SENTINEL SCAN COMPLETE
  Files scanned : 4
  Elapsed       : 5.1ms
  Findings      :  CRITICAL:1   HIGH:1   MEDIUM:0   LOW:0
---------------------------------------------------------------------

  COMMIT BLOCKED -- remove the secrets above and try again.
```

### JSON Format (`-f json`)

Written to `stdout`. All other formats write to `stderr`.

```json
{
  "sentinel_version": "v2.0.4",
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

When the scan is clean, `"status"` is `"clean"` and `"findings"` is an empty array.

### SARIF Format (`-f sarif`)

Produces a SARIF 2.1.0 document compatible with GitHub Advanced Security Code Scanning. Written to `stdout`.

```yaml
# .github/workflows/security.yml
- name: Secret scan
  run: |
    sentinel scan -f sarif -r . > sentinel.sarif
  
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

---

## False Positive Handling

Tier 3 eliminates most false positives automatically. When a genuine false positive appears, use one of the following remediation methods in order of preference:

**1. Inline suppression**

Place `sentinel:ignore` on the line itself or on the preceding comment line. Works in any language.

```go
// sentinel:ignore
const exampleToken = "ghp_DOCUMENTED_EXAMPLE_TOKEN_FOR_README"
```

```python
API_KEY = "sk_live_documented_example"  # sentinel:ignore
```

**2. Safe variable name**

Rename the variable to include a safe word. Tier 3 inspects the variable name left of `=` or `:=`.

```go
dummy_api_key := "ghp_REAL_LOOKING_TOKEN"   // suppressed
fake_stripe_key := "sk_live_example"         // suppressed
```

**3. Allowlist pattern**

Add exact strings or `filepath.Match` glob patterns to `allowlist_patterns` in `.sentinel.yaml`:

```yaml
allowlist_patterns:
  - "AKIAIOSFODNN7EXAMPLE"   # exact match
  - "sk_test_*"              # all Stripe test keys
  - "*-placeholder-*"
```

**4. Test file path**

Move the file to a path that Tier 3 recognizes as a test or documentation context: `*_test.go`, `tests/`, `testdata/`, `fixtures/`, `__tests__/`, `__mocks__/`, files ending in `.md` or `.rst`.

**5. Environment variable reference**

Use `$VAR` or `${VAR}` syntax. Tier 3 classifies these as `SafePlaceholder`.

```yaml
stripe_key: "${STRIPE_SECRET_KEY}"
```

**6. Exclude the path**

```yaml
exclude_paths:
  - "docs/examples/**"
  - "infra/terraform/**"
```

**7. Adjust entropy threshold**

Raise `entropy_threshold` slightly if your codebase contains many high-entropy non-secret identifiers (e.g., long UUIDs, content hashes used as identifiers).

---

## Running Tests

```bash
# All tests with race detector
make test

# Benchmarks
make bench

# HTML coverage report (output: coverage.html)
make cover

# Static analysis
make lint
```

Representative benchmark output:
```
BenchmarkAutomatonBuild-8        3     195,234 ns/op    327,680 B/op
BenchmarkSearch-8             3000     341,012 ns/op          0 B/op
BenchmarkSearchWithHit-8      2000     412,887 ns/op      3,456 B/op
BenchmarkShannonSmall-8    5000000         234 ns/op          0 B/op
BenchmarkFullPipeline-8         500   2,341,201 ns/op     12,340 B/op
```

The `BenchmarkSearch` zero-allocation figure confirms the hot path performs no heap allocations during scanning.

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
