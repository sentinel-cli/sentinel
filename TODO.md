# Sentinel Public Roadmap (TODO)

This document serves as our public roadmap to explain upcoming enterprise features to users and contributors.

- [x] **Inline Suppression (`sentinel:ignore`)**
  *Status: Implemented*
  Allows developers to bypass false positives directly in the source code. By adding a comment containing `sentinel:ignore` on the preceding line, the engine will completely skip scanning the immediately following line.

- [ ] **SARIF Output Format**
  *Status: Planned*
  Adding support for the Static Analysis Results Interchange Format (SARIF). This will allow Sentinel's JSON reports to be natively ingested by GitHub Advanced Security (Code Scanning Alerts) and other enterprise CI/CD dashboards.

- [x] **Deep Git History Scan (`--history`)**
  *Status: Implemented*
  Expanding the CLI capabilities to audit the entire historical commit tree of a repository, rather than just staged files, enabling teams to trace and remediate retroactively leaked credentials.

- [ ] **Custom User Signatures**
  *Status: Planned*
  Empowering enterprise teams to define their own proprietary regex patterns, static prefixes, and custom rules within the `.sentinel.yaml` configuration file to catch company-specific tokens.

- [x] **Native `pre-commit` Framework Hook**
  *Status: Implemented*
  Adding a `.pre-commit-hooks.yaml` configuration to the repository. This will allow large engineering teams to manage and distribute Sentinel seamlessly using the globally recognized Python-based `pre-commit` ecosystem without manual binary installations.
