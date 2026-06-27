// Package commands contains all cobra sub-command implementations.
package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentinel-cli/sentinel/internal/config"
	"github.com/sentinel-cli/sentinel/internal/git"
	"github.com/sentinel-cli/sentinel/internal/reporter"
	"github.com/sentinel-cli/sentinel/internal/scanner"
	"github.com/sentinel-cli/sentinel/internal/trie"
	"github.com/sentinel-cli/sentinel/internal/updater"
)

// NewRunCmd builds the `sentinel run` sub-command, which is the actual
// pre-commit hook entry point.  Git calls this with no arguments; Sentinel
// reads the staged files from git's index and scans only the new content.
func NewRunCmd() *cobra.Command {
	var (
		configPath string
		format     string
		failFast   bool
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the pre-commit security scan (called by git hook)",
		Long: `Run is invoked automatically by git when you execute 'git commit'.
It scans all staged changes for secrets using the three-tier detection pipeline.
Exit code 0 means clean. Exit code 1 blocks the commit.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(configPath, format, failFast, verbose)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .sentinel.yaml config file")
	cmd.Flags().StringVarP(&format, "format", "f", "pretty", "output format: pretty|json|plain")
	cmd.Flags().BoolVar(&failFast, "fail-fast", false, "stop after first finding")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose debug output")

	return cmd
}

// runScan is the core scanning logic used by both `run` and `scan` commands.
func runScan(configPath, format string, failFast, verbose bool) error {
	updateChan := updater.CheckForUpdateAsync()
	startTime := time.Now()

	// ── Load configuration ────────────────────────────────────────────────────
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if failFast {
		cfg.FailFast = true
	}
	if verbose {
		cfg.Verbose = true
	}

	// ── Initialise reporter ───────────────────────────────────────────────────
	rep := reporter.New(os.Stderr, reporter.ParseFormat(format))
	rep.PrintHeader()

	// ── Verify we are inside a git repository ────────────────────────────────
	if !git.IsInsideWorkTree() {
		return fmt.Errorf("not inside a git repository")
	}

	// ── List staged files ─────────────────────────────────────────────────────
	stagedFiles, err := git.ListStagedFiles()
	if err != nil {
		return fmt.Errorf("could not list staged files: %w", err)
	}
	if len(stagedFiles) == 0 {
		rep.PrintClean(time.Since(startTime), 0)
		return nil
	}

	// ── Build Aho-Corasick automaton once ─────────────────────────────────────
	automaton := trie.Build(trie.BuiltinSignatures)

	// ── Construct scanner ─────────────────────────────────────────────────────
	scanOpts := scanner.Options{
		EntropyThreshold: cfg.EntropyThreshold,
		MinSecretLength:  cfg.MinSecretLength,
		DisableTrie:      cfg.DisableTiers.Trie,
		DisableEntropy:   cfg.DisableTiers.Entropy,
		DisableContext:   cfg.DisableTiers.Context,
	}
	sec := scanner.New(automaton, scanOpts)

	// ── Scan each staged file ─────────────────────────────────────────────────
	var allFindings []scanner.Finding
	scannedCount := 0

	for _, sf := range stagedFiles {
		// ── Skip excluded extensions ────────────────────────────────────────
		if scanner.HasExcludedExtension(sf.Path, cfg.ExcludeExtensions) {
			rep.PrintSkipped(sf.Path, "excluded extension")
			continue
		}

		// ── Skip excluded paths ─────────────────────────────────────────────
		if scanner.MatchesExcludePath(sf.Path, cfg.ExcludePaths) {
			rep.PrintSkipped(sf.Path, "excluded path")
			continue
		}

		// ── Retrieve content ────────────────────────────────────────────────
		var content []byte
		if sf.Status == "A" {
			// Newly added file: scan full staged blob.
			content, err = git.GetStagedContent(sf.Path)
		} else {
			// Modified/renamed: scan only the new lines from the diff.
			content, err = git.GetStagedDiff(sf.Path)
		}
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [verbose] skipping %s: %v\n", sf.Path, err)
			}
			continue
		}

		// ── Skip empty content (e.g. pure deletions that slipped through) ───
		if len(content) == 0 {
			continue
		}

		// ── Skip files exceeding max size ───────────────────────────────────
		if int64(len(content)) > cfg.MaxFileSizeBytes {
			rep.PrintSkipped(sf.Path, fmt.Sprintf("file too large (%d bytes)", len(content)))
			continue
		}

		// ── Skip binary files ───────────────────────────────────────────────
		if !cfg.ScanBinaryFiles && scanner.IsBinary(content) {
			rep.PrintSkipped(sf.Path, "binary file")
			continue
		}

		scannedCount++
		findings := sec.ScanContent(sf.Path, content)
		allFindings = append(allFindings, findings...)

		if cfg.FailFast && len(allFindings) > 0 {
			break
		}
	}

	elapsed := time.Since(startTime)

	// ── Report results ────────────────────────────────────────────────────────
	if len(allFindings) == 0 {
		rep.PrintClean(elapsed, scannedCount)
		if msg := <-updateChan; msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
		return nil
	}

	rep.PrintFindings(allFindings)
	rep.PrintSummary(allFindings, elapsed, scannedCount)
	
	if msg := <-updateChan; msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}

	// Exit 1 to block the commit.
	os.Exit(1)
	return nil
}
