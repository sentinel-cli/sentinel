# Crenox — Statically Compiled Git Secret Scanner & Pre-Commit Hook

<!-- SEO: git secret scanner, pre-commit hook, gitleaks alternative, credentials detector, api key detection, go security tool, git-secrets alternative -->

<div align="center">

<pre style="line-height: 1.15; font-size: min(1.1vw, 11px); white-space: pre; overflow-x: auto; font-family: monospace; border: none; background: transparent; padding: 0; margin: 0; display: inline-block; text-align: left;">
 ██████╗ ██████╗  ███████╗ ████╗  ██╗  ██████╗  ██╗  ██╗
██╔════╝ ██╔══██╗ ██╔════╝ ██╔██╗ ██║ ██╔═══██╗ ╚██╗██╔╝
██║      ██████╔╝ █████╗   ██║╚██╗██║ ██║   ██║  ╚███╔╝ 
██║      ██╔══██╗ ██╔══╝   ██║ ╚████║ ██║   ██║  ██╔██╗ 
╚██████╗ ██║  ██║ ███████╗ ██║  ╚███║ ╚██████╔╝ ██╔╝╚██╗
 ╚═════╝ ╚═╝  ╚═╝ ╚══════╝ ╚═╝   ╚══╝  ╚═════╝  ╚═╝  ╚═╝
</pre>

**Statically compiled Git pre-commit secret scanner and credentials detector written in Go.**

[![Release](https://img.shields.io/github/v/release/crenoxhq/crenox?color=3c6382&logo=github&label=latest&v=4)](https://github.com/crenoxhq/crenox/releases)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Crenox-3c6382.svg?logo=github&v=4)](https://github.com/marketplace/actions/crenox-git-secrets-scanner)
[![Downloads](https://img.shields.io/github/downloads/crenoxhq/crenox/total?color=4b6584&logo=github&v=4)](https://github.com/crenoxhq/crenox/releases)
[![CI](https://github.com/crenoxhq/crenox/actions/workflows/ci.yml/badge.svg?branch=main&v=4)](https://github.com/crenoxhq/crenox/actions/workflows/ci.yml)
[![Stars](https://img.shields.io/github/stars/crenoxhq/crenox?style=flat&logo=github&color=3c6382&v=4)](https://github.com/crenoxhq/crenox/stargazers)
[![Go Version](https://img.shields.io/badge/Go-1.22+-2f3542?logo=go&v=4)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/crenoxhq/crenox/v2.svg?v=4)](https://pkg.go.dev/github.com/crenoxhq/crenox/v2)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%2FTermux-2f3542?v=4)](#installation)
[![License](https://img.shields.io/badge/license-AGPL_3.0-4b6584?v=4)](LICENSE)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg?v=4)](https://github.com/avelino/awesome-go)

<br><br>

</div>

<p align="left">
<a href="https://www.producthunt.com/products/crenox-leak-secret-scanner?embed=true&amp;utm_source=badge-featured&amp;utm_medium=badge&amp;utm_campaign=badge-crenox-secret-scanner" target="_blank" rel="noopener noreferrer"><img alt="Crenox Secret Scanner - Context-aware Git secret scanner in Go | Product Hunt" width="250" height="54" src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1196224&amp;theme=neutral&amp;t=1784131078630"></a>
</p>

---

## What is Crenox?

**Crenox** is a statically compiled, zero-dependency Git pre-commit hook and credentials scanner written in Go. It automatically blocks commits of API keys, SSH private keys, cloud credentials, database connection strings, and other sensitive material before they are recorded in version control history.

It is an alternative to tools like **Gitleaks** and **git-secrets**, focusing on lower resource utilization and local workflow integration.

Crenox uses a **three-tier detection pipeline** designed for speed and false positive reduction:

| Tier | Engine | Purpose |
|------|--------|---------|
| 1 — PATTERN | Aho-Corasick automaton | Matches 100 known secret signatures in O(n) time, zero allocations |
| 2 — ENTROPY | Shannon entropy analysis | Catches unknown secrets by measuring information density |
| 3 — CONTEXT | Context classifier | Suppresses false positives from comments, test files, and placeholders |

A finding must survive all three tiers before it is reported.

---

## Quick Start

**Install and protect your repository in under 60 seconds:**

```bash
# 1. Install
go install github.com/crenoxhq/crenox/v2/cmd/crenox@latest

# 2. Protect the current repository
crenox install

# 3. Verify — Crenox will now scan every commit automatically
git add . && git commit -m "test"
```

**Or scan any directory right now, without a hook:**

```bash
crenox scan --recursive ./src
```

That is all. No configuration file required. No runtime dependencies. Works on Linux, macOS, Windows, and Android/Termux.

---

## Terminal Demo

```bash
asciinema play https://crenoxhq.github.io/crenox/demo.cast
```

![Crenox Demo](docs/demo.gif?v=2.1.2)

---

## Table of Contents

- [What is Crenox](#what-is-crenox)
- [Quick Start](#quick-start)
- [Performance](#performance)
- [Why Crenox](#why-crenox)
- [Architecture](#architecture)
- [Signature Coverage](#signature-coverage)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Reference](#output-reference)
- [False Positive Handling](#false-positive-handling)
- [In the Wild (Live Archive)](https://crenoxhq.github.io/crenox/wild.html)
- [Running Tests](#running-tests)
- [Contributing](#contributing)
- [License](#license)

---

## Performance

Measured on real-world repositories with Crenox against the most popular alternatives, on a standard **GitHub Actions Ubuntu cloud runner** — the same infrastructure used in real-world CI/CD pipelines.

<details>
<summary>Filesystem Scan Results (Standard Mode)</summary>

| Repository | Tool | Avg Time | Peak RAM | Findings |
|:---|:---|:---:|:---:|:---:|
| [sample_secrets](https://github.com/GitGuardian/sample_secrets) | **Crenox** | **6.4 ms** | **17.0 MB** | **3** |
| | Gitleaks v8.18.2 | 24.3 ms | 23.0 MB | 1 |
| | Betterleaks v1.6.1 | 53.1 ms | 37.1 MB | 2 |
| [truffleHogRegexes](https://github.com/dxa4481/truffleHogRegexes) | **Crenox** | **7.1 ms** | **17.2 MB** | **0** |
| | Gitleaks v8.18.2 | 36.1 ms | 21.2 MB | 1 |
| | Betterleaks v1.6.1 | 76.0 ms | 37.8 MB | 1 |
| [serverless-node-api-boilerplate](https://github.com/crenoxhq/serverless-node-api-boilerplate) | **Crenox** | **7.7 ms** | **17.2 MB** | **6** |
| | Gitleaks v8.18.2 | 27.0 ms | 23.0 MB | 2 |
| | Betterleaks v1.6.1 | 175.9 ms | 54.2 MB | 1 |

</details>

<details>
<summary>Git History Scan Results (History Mode)</summary>

| Repository | Tool | Avg Time | Peak RAM | Findings |
|:---|:---|:---:|:---:|:---:|
| [sample_secrets](https://github.com/GitGuardian/sample_secrets) | **Crenox** | **9.9 ms** | **17.3 MB** | **9** |
| | Gitleaks v8.18.2 | 27.1 ms | 23.1 MB | 5 |
| | Betterleaks v1.6.1 | 184.3 ms | 53.2 MB | 5 |
| [truffleHogRegexes](https://github.com/dxa4481/truffleHogRegexes) | **Crenox** | **12.5 ms** | **17.6 MB** | **3** |
| | Gitleaks v8.18.2 | 42.7 ms | 23.0 MB | 6 |
| | Betterleaks v1.6.1 | 89.4 ms | 40.3 MB | 8 |
| [serverless-node-api-boilerplate](https://github.com/crenoxhq/serverless-node-api-boilerplate) | **Crenox** | **9.9 ms** | **17.3 MB** | **6** |
| | Gitleaks v8.18.2 | 31.8 ms | 21.6 MB | 2 |
| | Betterleaks v1.6.1 | 180.8 ms | 53.2 MB | 1 |

</details>

> **Transparent & Auditable** — These results were generated by an [open-source automated benchmark script](https://github.com/crenoxhq/serverless-node-api-boilerplate/blob/main/scripts/run_benchmark.py) running on a standard GitHub Actions Ubuntu cloud runner. The full methodology, tooling, and workflow configuration are publicly visible — results are triggered and verified by the maintainer on each release. [**View the latest benchmark run →**](https://github.com/crenoxhq/serverless-node-api-boilerplate/actions/workflows/benchmark.yml)

**Summary:**

| Metric | vs Gitleaks | vs Betterleaks |
|--------|-------------|---------------|
| **Speed** | **3x to 5x faster** | **6x to 15x faster** |
| **Memory** | **1.2x to 1.5x less RAM** | **2.5x to 4x less RAM** |
| **Recall (Accuracy)** | Finds obfuscated & encoded secrets ignored by Gitleaks | Finds critical secrets missed by Betterleaks |

---

## Why Crenox — Comparison (vs Gitleaks, Betterleaks)

| Feature | Crenox | Gitleaks | Betterleaks |
|---------|:--------:|:-----------:|:--------------:|
| Statically compiled, zero runtime dependencies | + | + | + |
| ARM / Android / Termux native support | + | partial | partial |
| Aho-Corasick O(n) multi-pattern matching | + | + | + |
| Shannon entropy analysis | + | + | — |
| Token efficiency (BPE tokenizer) | — | — | + |
| Context-aware false-positive suppression | + | — | — |
| BIP-39 seed phrase detection | + | — | — |
| Single-layer Base64 decoding | + | + | + |
| Concurrent file scanning | + | + | + |
| SARIF & JSON output formatting | + | + | + |
| Global hook installation | + | + | — |
| Custom user-defined signatures | + | + | + |
| OTA self-updating binary | + | — | — |

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
   Built once at startup via trie.Build() — allocation-free DFA matching
   Case-insensitive O(n) scan using a branchless 256-byte toLower lookup table
   and sync.Pool-recycled 64 KB streaming buffers to cap heap memory to ~3 MB
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
   Checks (in order): test file path → commented line → unquoted RHS in source → UUID → version string
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

Crenox extracts two token classes per line:
- **Base64 tokens** — runs of `A-Za-z0-9+/=_-`; entropy must exceed `entropy_threshold` (default 4.5).
- **Hex tokens** — runs of `0-9a-fA-F`; must be even-length if short (< 32 characters) to filter out arbitrary non-secret hex strings; threshold is scaled: `entropy_threshold × (4.0 / 6.0)`, floor 3.0.

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
| `SafePlaceholder` | Token matches `$VAR`, `${VAR}`, `<...>`, `[[...]]`, `{{...}}`, `${{...}}` |
| `SafeUUID` | Token matches UUID v4 pattern `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `SafeVersionString` | Token begins with `digit.digit.digit` |
| `SafeSourceRHS` | Token on RHS of assignment in programming source files is bare/unquoted (e.g. Go struct types, function calls) |

The scanner also rejects tokens that match a `printf`-style format verb, are identical to their signature prefix, contain regex metacharacters, or (for short prefixes ≤ 3 bytes) are pure PascalCase/CamelCase with no special characters.

</details>

### Inline Suppression

Place `crenox:ignore` on the flagged line or the preceding comment line:

```go
// crenox:ignore
apiKey := "sk_live_example_for_documentation"

apiKey := "sk_live_example_for_documentation" // crenox:ignore
```

```bash
# crenox:ignore
STRIPE_KEY="sk_live_example"
```

```html
<!-- crenox:ignore -->
<secret>sk-ant-api03-documented-example</secret>
```

A same-line annotation suppresses only that line. A comment-line annotation suppresses the immediately following line.

---

## Signature Coverage

<details>
<summary>View all builtin signatures</summary>

| Category | Signatures |
|----------|-----------|
| **GitHub** | Classic PAT (`ghp_`), OAuth (`gho_`), App Installation (`ghs_`), Refresh (`ghr_`), Fine-grained PAT (`github_pat_`), Client ID (`Iv1.`, 16-char hex validated), and suffix-matched environment tokens (`_GITHUB_TOKEN`) |
| **Heroku** | API Key (`HEROKU_API_KEY`, regex-validated), OAuth Token (`heroku_oauth_token`) |
| **GitLab** | Personal Access Token (`glpat-`), Pipeline Trigger (`glptt-`), Runner Registration (`GR1348941`), Runner Token (`glrt-`) |
| **AWS** | Access Key ID (`AKIA`, validated `AKIA[0-9A-Z]{16}`), MFA Device (`ABIA`), STS Temporary Key (`ASIA`), and Secret Access Key variable assignments (`aws_secret`, `aws_key`) |
| **Google Cloud** | Service Account JSON (`"type": "service_account"`), API Key (`AIzaSy`), OAuth Client ID (`.apps.googleusercontent.com`), OAuth Client Secret (`GOCSPX-`) |
| **Slack** | Bot (`xoxb-`), User (`xoxp-`), Workspace (`xoxa-`), Refresh (`xoxr-`), and Incoming Webhook (`https://hooks.slack.com/services/`, regex-validated) |
| **Discord** | Webhook URL (`https://discord.com/api/webhooks/`, regex-validated) |
| **Stripe** | Live Secret (`sk_live_`), Live Restricted (`rk_live_`), Test Secret (`sk_test_`) |
| **OpenAI** | Classic (`sk-`), Project key (`sk-proj-`) |
| **Anthropic** | API key (`sk-ant-`) |
| **Twilio** | Account SID (`AC`, regex-validated), Auth Token (`SK`, regex-validated) |
| **SendGrid** | API key (`SG.`, regex-validated: `SG.[a-zA-Z0-9_-]{22}.[a-zA-Z0-9_-]{43}`) |
| **Mailgun** | API key (`key-`) |
| **npm** | Automation/Publish token (`npm_`), Classic/Auth Token (`_authToken=`, `_auth=`) |
| **JWT** | JSON Web Token (`eyJ`, strict 3-part dot-separated regex) |
| **Private Keys & Certs** | RSA, EC, OpenSSH, PKCS#8, PGP, DSA — all `-----BEGIN ... PRIVATE KEY-----` variants, PuTTY Private Keys (`PuTTY-User-Key-File-`) |
| **Databases & DSNs** | PostgreSQL (`postgresql://`, `postgres://`), MySQL (`mysql://`), MongoDB SRV (`mongodb+srv://`), MongoDB (`mongodb://`), Redis (`redis://`), RabbitMQ (`amqp://`, `amqps://`) — DSN connection strings with embedded passwords |
| **PyPI** | Upload Token (`pypi-`) |
| **Square** | Access Token (`sq0atp-`) |
| **Basic Auth** | HTTPS (`https://user:pass@`), HTTP (`http://user:pass@`) |
| **HashiCorp Vault** | Service token (`hvs.`), Batch token (`hvb.`) |
| **DigitalOcean** | Personal Access Token (`dop_v1_`) |
| **Vercel** | API Token (`vercel_`) |
| **Cloudflare** | API Token (`cloudflare-api-token`) |
| **Linear** | API Key (`lin_api_`) |
| **Databricks** | Personal Access Token (`dapi`) |
| **PlanetScale** | Service Token (`pscale_tkn_`) |
| **Supabase** | Service Role Key (JWT with Supabase-specific header) |
| **Pinecone** | API Key (`pcsk_`) |
| **Railway** | API Token (`railway_`) |
| **HuggingFace** | API Token (`hf_`) |
| **Shopify** | Custom App (`shpca_`), Private App (`shppa_`), Access Token (`shpat_`) |
| **Generic** | `password=`, `secret=`, `api_key=`, `token=`, `auth=`, `pass=`, `pwd=`, and their YAML/JSON/space colon and snake_case variants |
| **Django & Rails**| `SECRET_KEY =`, Rails `secret_key_base` (space and colon assignments) |
| **WordPress** | `AUTH_KEY` `SECURE_AUTH_KEY` `LOGGED_IN_KEY` `NONCE_KEY` `AUTH_SALT` `SECURE_AUTH_SALT` `LOGGED_IN_SALT` `NONCE_SALT` |
| **Crypto Wallets** | BIP-39 mnemonic (12/15/18/21/24 words, validated against 2048-word dictionary) |

Custom signatures can be added in `.crenox.yaml` and are compiled into the same automaton at startup — no performance overhead.

</details>

---

## Installation

### Pre-compiled Binary (Recommended)

Download the binary for your platform from the [Releases page](https://github.com/crenoxhq/crenox/releases):

```bash
# Replace <version> and <arch>  e.g.  linux-amd64  linux-arm64  darwin-amd64  darwin-arm64
wget https://github.com/crenoxhq/crenox/releases/download/<version>/crenox-<version>-<arch> -O crenox
chmod +x crenox
mv crenox /usr/local/bin/       # Linux / macOS
# mv crenox $PREFIX/bin/        # Termux (Android)
crenox version
```

### Go Install

```bash
go install github.com/crenoxhq/crenox/v2/cmd/crenox@latest
```

### Build from Source

```bash
git clone https://github.com/crenoxhq/crenox.git
cd crenox
make build            # outputs to dist/crenox
./dist/crenox version
```

### Android / Termux

Crenox can be easily installed on Android using Termux via the Termux User Repository (TUR):

```bash
pkg install tur-repo
pkg install crenox
```


---

### Git Hook Setup

**Protect the current repository:**

```bash
crenox install          # installs .git/hooks/pre-commit
crenox install --force  # overwrites an existing hook
```

**Protect every repository on this machine (global):**

```bash
crenox install --global
# Creates ~/.config/crenox/hooks/pre-commit
# Runs: git config --global core.hooksPath ~/.config/crenox/hooks
```

**Remove global hook:**

```bash
git config --global --unset core.hooksPath
```

**Full uninstall — removes binary, hooks, and config directory:**

```bash
crenox uninstall
```

### Native pre-commit Framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/crenoxhq/crenox
    rev: v2.1.2 # Replace with the latest release version
    hooks:
      - id: crenox
```

---

## Configuration

Crenox searches for `.crenox.yaml` in this order:

1. `--config` / `-c` flag value
2. `.crenox.yaml` in the current working directory (repository root)
3. `~/.crenox.yaml` in the home directory

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
  - "dist/**"
  - "build/**"
  - "out/**"
  - "target/**"
  - "bin/**"
  - ".next/**"
  - ".nuxt/**"
  - ".yarn/**"
  - ".git/**"
  - "*.lock"
  - "go.sum"
  - "package-lock.json"
  - "pnpm-lock.yaml"
  - "yarn.lock"
  - "**/locales/**"
  - "**/i18n/**"
  - "**/*.min.js"
  - "**/*.min.css"

# File extensions to skip (case-insensitive).
# Default includes images, fonts, audio, video, archives, binaries, office documents.
exclude_extensions:
  - ".png"
  - ".jpg"
  - ".jpeg"
  - ".gif"
  - ".bmp"
  - ".ico"
  - ".svg"
  - ".woff"
  - ".woff2"
  - ".ttf"
  - ".eot"
  - ".mp4"
  - ".webm"
  - ".mp3"
  - ".ogg"
  - ".zip"
  - ".tar"
  - ".gz"
  - ".bz2"
  - ".xz"
  - ".7z"
  - ".pdf"
  - ".doc"
  - ".docx"
  - ".xls"
  - ".xlsx"
  - ".exe"
  - ".dll"
  - ".so"
  - ".dylib"
  - ".a"
  - ".o"
  - ".css"
  - ".scss"
  - ".csv"
  - ".hex"
  - ".eml"
  - ".msg"
  - ".mbox"
  - ".vcf"
  - ".ics"
  - ".cache"
  - ".pb.go"
  - ".gen.go"
  - ".g.go"
  - ".map"

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

After `crenox install`, the hook fires on every `git commit` and scans only staged content:
- **New files** — full content via `git show :<path>`
- **Modified files** — added lines only via `git diff --cached -- <path>`

### Ad-hoc Scanning

```bash
# Single file
crenox scan config/production.yaml

# Directory (non-recursive)
crenox scan ./config

# Directory, recursive (skips .git, build, node_modules automatically)
crenox scan -r ./src

# Full Git history audit (streams git log --all -p; deduplicates by token)
crenox scan --history .

# JSON output — written to stdout for piping
crenox scan -f json -r ./src | jq '.findings[] | select(.severity == "CRITICAL")'

# SARIF output saved directly to file (keeps pretty terminal logs)
crenox scan -f sarif -o crenox.sarif .

```

> In ad-hoc mode, files are processed concurrently using `max(runtime.NumCPU(), 4)` goroutines.
> In history mode, the Git log is streamed with a 10 MB line buffer; unique findings are deduplicated by token value.

### CI Integration

#### GitHub Actions (Official Reusable Action)
The easiest way to integrate Crenox into your GitHub Actions workflow is by using our official reusable action. It handles Go installation, compilation cache, and scanning automatically:

```yaml
- name: Run Crenox Git Secrets Scanner
  uses: crenoxhq/crenox@v2
  with:
    version: 'latest' # Optional: specific version to use (e.g. 'v2.x.x')
    args: '.'         # Optional: arguments to pass (e.g. "." or "--history .")
    sarif: 'true'     # Optional: set to 'true' to export findings as a SARIF report
```

To upload the results to GitHub Advanced Security (Code Scanning Alerts), configure the upload step:

```yaml
- name: Upload SARIF report
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: crenox-results.sarif
```

> [!TIP]
> You can inspect the official [action.yml](action.yml) file in the root of this repository to use as a template or reference for building your own custom GitHub Actions.



```yaml
# GitLab CI
crenox-scan:
  stage: test
  image: golang:1.22
  before_script:
    - go install github.com/crenoxhq/crenox/v2/cmd/crenox@latest
  script:
    # Run scan; output JSON to file and print pretty results to console
    - crenox scan -f pretty -o crenox-report.json .
  artifacts:
    when: always
    paths:
      - crenox-report.json
```

### Command Reference

<details>
<summary>crenox run — pre-commit hook entry point</summary>

Scans staged changes only. Invoked automatically by the Git hook.

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config` | auto-detected | Path to `.crenox.yaml` |
| `-f, --format` | `pretty` | `pretty` `json` `plain` `sarif` |
| `--fail-fast` | false | Stop after the first finding |
| `-v, --verbose` | false | Debug output to stderr |

</details>

<details>
<summary>crenox scan [path...] — ad-hoc scanner</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config` | auto-detected | Path to `.crenox.yaml` |
| `-f, --format` | `pretty` | `pretty` `json` `plain` `sarif` |
| `-o, --output` | | Write report directly to file, preserving pretty stdout logs |
| `-r, --recursive` | false | Walk subdirectories |
| `--history` | false | Scan entire Git commit history |
| `--fail-fast` | false | Stop after the first finding |
| `-v, --verbose` | false | Debug output to stderr |

</details>

<details>
<summary>crenox install — hook installer</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--global` | false | Install globally via `core.hooksPath` |
| `--repo` | `.` | Target repository root |
| `-f, --force` | false | Overwrite existing hook |

</details>

<details>
<summary>crenox update — OTA self-updater</summary>

Downloads the latest stable release for the current OS/arch from the GitHub Releases API, verifies the binary, and atomically replaces the running executable. Falls back to `go install` if no pre-compiled binary matches the platform.

| Flag | Default | Description |
|------|---------|-------------|
| `--beta` | false | Allow updating to pre-release (beta) versions |

A background check runs on each invocation, querying the API at most once per 24 hours. The result is cached at `~/.config/crenox/last_check.json`. A notice is printed to stderr if a newer version is available.

</details>

<details>
<summary>crenox dashboard — local control panel</summary>

Launches the interactive, self-hosted web control panel and worker scan queue on your local machine.

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --port` | `8080` | Port to run the HTTP web server on |
| `--no-open` | `false` | Do not automatically open dashboard in default browser |

</details>

---

## Output Reference

**Clean (exit 0):**

```
  CRENOX CLEAN  --  4 file(s) scanned in 3.2ms
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
  "crenox_version": "v2.x.x",
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
| `crenox:ignore` comment | One-off suppression for a specific line |
| Safe variable name (`dummy_`, `fake_`, `mock_`) | Test or documentation values that look like secrets |
| **Automatic Mock Value Filter** | Automatically ignores generic token rules if values contain mock/fake/test/dummy |
| **Key File Entropy Bypass** | Skips raw line-by-line entropy checks on key extensions (`.pem`, `.key`, `.rsa`, `.crt`, `.pub`) |
| **Function Call Protection** | Automatically filters out code function calls and methods containing parentheses |
| **Source RHS Quote Enforcement** | Automatically skips unquoted RHS tokens (variables, struct types, function calls) in source code files |
| **Rust/C++ Generic Type Filter** | Tokens containing `<` or `>` (e.g. `Option<u64>`, `Vec<T>`) are never reported as secrets |
| **Lowercase Identifier Filter** | Tokens composed entirely of lowercase letters and underscores (e.g. `pass_summaries`) are rejected by generic rules |
| **Git Commit SHA Filter** | 20-char and 40-char pure hex tokens are rejected by the `high-entropy-hex` rule to eliminate dependency pinning hashes |
| **YAML Key Name Filter** | Key names without values (e.g. `api-key:`) are detected and discarded before being reported |
| **Seed Directory Suppression** | Files inside `seed/` or `seeds/` directories are treated as safe test data automatically |
| `allowlist_patterns` in config | Known safe tokens used repeatedly across the codebase |
| Move to test file path | Values in `tests/`, `testdata/`, `*_test.go`, `.md` are suppressed automatically |
| `${ENV_VAR}` reference syntax | Replaced at runtime — not a hardcoded secret |
| `exclude_paths` in config | Entire directories that should never be scanned |
| Raise `entropy_threshold` | Codebase has many long high-entropy non-secret identifiers |

```yaml
# .crenox.yaml
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
Zero-dependency, local secret detection.
</div>
