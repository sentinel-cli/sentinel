// Package main implements the Sentinel CLI — a `cobra`-based command dispatcher
// that exposes:
//
//	sentinel run     — the core pre-commit hook (default)
//	sentinel install — install the hook into a git repository
//	sentinel version — print build metadata
//	sentinel scan    — scan an arbitrary file or directory (ad-hoc mode)
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sentinel-cli/sentinel/v2/cmd/sentinel/commands"
	"github.com/sentinel-cli/sentinel/v2/pkg/version"
)

func init() {
	// Termux self-healing mechanism for SSL certificates.
	// Go's crypto/x509 does not natively check Termux's custom certificate path.
	// If we are in Termux (e.g. the path exists or PREFIX is set),
	// and SSL_CERT_FILE is not already overridden by the user, inject it automatically.
	termuxCertPath := "/data/data/com.termux/files/usr/etc/tls/cert.pem"
	if os.Getenv("SSL_CERT_FILE") == "" {
		if _, err := os.Stat(termuxCertPath); err == nil {
			os.Setenv("SSL_CERT_FILE", termuxCertPath)
		} else if strings.Contains(os.Getenv("PREFIX"), "com.termux") {
			os.Setenv("SSL_CERT_FILE", termuxCertPath)
		}
	}
}

func main() {
	root := &cobra.Command{
		Use:   "sentinel",
		Short: "Sentinel — enterprise-grade Git pre-commit secret detector",
		Long: `Sentinel is an ultra-lightweight, modular Git pre-commit security hook
that prevents accidental commits of API keys, SSH private keys, passwords,
and other sensitive data using a three-tier detection pipeline:

  Tier 1 (PATTERN)  — Aho-Corasick trie matching of 64 known secret signatures
  Tier 2 (ENTROPY)  — Shannon entropy analysis for unknown/novel secrets
  Tier 3 (CONTEXT)  — Context-aware false-positive suppression
  
  Inline Suppression — Append '// sentinel:ignore' to the preceding line or at the end of the line to ignore false positives.
  Framework Support  — Compatible with the Python 'pre-commit' ecosystem.
  CI/CD Integration  — Official GitHub Actions support with native SARIF output.

CLI Commands & Flags:

  sentinel run                  Run the core pre-commit scan on staged files.
      -c, --config string       Path to .sentinel.yaml config file.
      -f, --format string       Output format: pretty|json|plain|sarif.
      --fail-fast               Stop after the first finding.
      -v, --verbose             Enable verbose debug output.

  sentinel scan [path...]       Ad-hoc mode to scan arbitrary files or directories.
      -c, --config string       Path to config file.
      -f, --format string       Output format: pretty|json|plain|sarif.
      -o, --output string       Write scan report directly to a file (preserving pretty logs).
      -r, --recursive           Scan directories recursively.
      -v, --verbose             Enable verbose output.
      --history                 Deep scan the entire git commit history.

  sentinel install              Install the pre-commit hook into a repository.
      --global                  Install globally via git core.hooksPath.
      --repo string             Path to the git repository root.
      -f, --force               Overwrite an existing hook without prompting.

  sentinel uninstall            Completely remove Sentinel, binary, and all hooks.
  sentinel update               Update Sentinel to the latest version.
  sentinel version              Print Sentinel version and build metadata.

Developed by: Khaled Hani | Contact: https://t.me/A245F`,
		Version:       version.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	root.SetVersionTemplate(`Sentinel version
{{printf "sentinel %s" .Version}} (commit: ` + version.Commit + `, built: ` + version.Date + `)
Developed by: Khaled Hani | Contact: https://t.me/A245F
`)

	root.AddCommand(
		commands.NewRunCmd(),
		commands.NewInstallCmd(),
		commands.NewScanCmd(),
		commands.NewUpdateCmd(),
		commands.NewUninstallCmd(),
		commands.NewVersionCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel: error:", err)
		os.Exit(1)
	}
}
