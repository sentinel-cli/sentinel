# Sentinel Public Roadmap (TODO)

This document serves as our public roadmap to explain upcoming enterprise features to users and contributors.

- [x] **Inline Suppression (`sentinel:ignore`)**
  *Status: Implemented*
  Allows developers to bypass false positives directly in the source code. By adding a comment containing `sentinel:ignore` on the preceding line, the engine will completely skip scanning the immediately following line.

- [x] **SARIF Output Format**
  *Status: Implemented*
  Adding support for the Static Analysis Results Interchange Format (SARIF). This will allow Sentinel's JSON reports to be natively ingested by GitHub Advanced Security (Code Scanning Alerts) and other enterprise CI/CD dashboards.

- [x] **Deep Git History Scan (`--history`)**
  *Status: Implemented*
  Expanding the CLI capabilities to audit the entire historical commit tree of a repository, rather than just staged files, enabling teams to trace and remediate retroactively leaked credentials.

- [x] **Custom User Signatures**
  *Status: Implemented*
  Empowering enterprise teams to define their own proprietary regex patterns, static prefixes, and custom rules within the `.sentinel.yaml` configuration file to catch company-specific tokens.

- [x] **Native `pre-commit` Framework Hook**
  *Status: Implemented*
  Adding a `.pre-commit-hooks.yaml` configuration to the repository. This will allow large engineering teams to manage and distribute Sentinel seamlessly using the globally recognized Python-based `pre-commit` ecosystem without manual binary installations.

- [x] **Allowlist Patterns (`allowlist_patterns`)**
  *Status: Implemented*
  Allows developers to define exact strings or glob patterns in `.sentinel.yaml` that are completely whitelisted from detection, preventing false positive alerts for known safe dummy credentials.

- [x] **Industry Benchmark Validation**
  *Status: Implemented*
  Validated Sentinel's custom multi-tier extraction engine head-to-head against Gitleaks and Trufflehog using GitGuardian's `sample_secrets` dataset, capturing 100% of historical secrets at an industry-leading 15MB RAM footprint.

- [x] **Core Engine Performance Optimizations**
  *Status: Implemented*
  Further refine the core scanning engine and token extraction pipelines to reduce execution times and optimize memory consumption during large filesystem sweeps.

- [ ] **Official GitHub Actions Integration**
  *Status: Planned*
  Develop a reusable composite GitHub Action (`action.yml`) enabling developers to integrate Sentinel directly into their CI/CD pipelines in 3 lines of code. The action will compile Sentinel from source, configure cache, and scan target workspaces recursively.
