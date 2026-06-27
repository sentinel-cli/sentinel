package commands

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentinel-cli/sentinel/internal/config"
	"github.com/sentinel-cli/sentinel/internal/reporter"
	"github.com/sentinel-cli/sentinel/internal/scanner"
	"github.com/sentinel-cli/sentinel/internal/trie"
	"github.com/sentinel-cli/sentinel/internal/updater"
)

// NewScanCmd builds the `sentinel scan` sub-command for ad-hoc scanning
// of arbitrary files or directories outside of the git hook workflow.
func NewScanCmd() *cobra.Command {
	var (
		configPath string
		format     string
		recursive  bool
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan files or directories for secrets (ad-hoc mode)",
		Long: `Scan lets you run Sentinel against arbitrary files or directories,
independent of git staging.  Useful for auditing existing codebases.

Examples:
  sentinel scan ./src
  sentinel scan config.yaml secrets.env
  sentinel scan --recursive /home/user/projects/myapp`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdHocScan(args, configPath, format, recursive, verbose)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .sentinel.yaml config file")
	cmd.Flags().StringVarP(&format, "format", "f", "pretty", "output format: pretty|json|plain")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "scan directories recursively")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	return cmd
}

func runAdHocScan(paths []string, configPath, format string, recursive, verbose bool) error {
	updateChan := updater.CheckForUpdateAsync()
	startTime := time.Now()

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if verbose {
		cfg.Verbose = true
	}

	rep := reporter.New(os.Stderr, reporter.ParseFormat(format))
	rep.PrintHeader()

	automaton := trie.Build(trie.BuiltinSignatures)
	scanOpts := scanner.Options{
		EntropyThreshold: cfg.EntropyThreshold,
		MinSecretLength:  cfg.MinSecretLength,
		DisableTrie:      cfg.DisableTiers.Trie,
		DisableEntropy:   cfg.DisableTiers.Entropy,
		DisableContext:   cfg.DisableTiers.Context,
	}
	sec := scanner.New(automaton, scanOpts)

	var allFindings []scanner.Finding
	scannedCount := 0

	// Collect all target file paths.
	var targets []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: cannot stat %q: %v\n", p, err)
			continue
		}
		if info.IsDir() {
			if recursive {
				cmd := exec.Command("git", "ls-files", "-z")
				cmd.Dir = p
				out, err := cmd.Output()
				if err == nil && len(out) > 0 {
					files := bytes.Split(out, []byte{0})
					for _, f := range files {
						if len(f) > 0 {
							targets = append(targets, filepath.Join(p, string(f)))
						}
					}
				} else {
					_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
						if err != nil {
							return nil
						}
						if d.IsDir() {
							name := d.Name()
							if name == ".git" || name == "build" || name == "node_modules" {
								return fs.SkipDir
							}
							return nil
						}
						targets = append(targets, path)
						return nil
					})
				}
			} else {
				entries, _ := os.ReadDir(p)
				for _, e := range entries {
					if !e.IsDir() {
						targets = append(targets, filepath.Join(p, e.Name()))
					}
				}
			}
		} else {
			targets = append(targets, p)
		}
	}

	for _, filePath := range targets {
		if scanner.HasExcludedExtension(filePath, cfg.ExcludeExtensions) {
			continue
		}
		if scanner.MatchesExcludePath(filePath, cfg.ExcludePaths) {
			continue
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [verbose] cannot read %s: %v\n", filePath, err)
			}
			continue
		}
		if len(content) == 0 {
			continue
		}
		if int64(len(content)) > cfg.MaxFileSizeBytes {
			continue
		}
		if !cfg.ScanBinaryFiles && scanner.IsBinary(content) {
			continue
		}

		scannedCount++
		findings := sec.ScanContent(filePath, content)
		allFindings = append(allFindings, findings...)
	}

	elapsed := time.Since(startTime)

	if len(allFindings) == 0 {
		rep.PrintClean(elapsed, scannedCount)
		if msg := <-updateChan; msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
		return nil
	}

	rep.PrintFindings(allFindings)
	rep.PrintSummary(allFindings, elapsed, scannedCount)
	os.Exit(1)
	return nil
}
