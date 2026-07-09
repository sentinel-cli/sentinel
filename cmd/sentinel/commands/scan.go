package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentinel-cli/sentinel/v2/internal/config"
	"github.com/sentinel-cli/sentinel/v2/internal/reporter"
	"github.com/sentinel-cli/sentinel/v2/internal/scanner"
	"github.com/sentinel-cli/sentinel/v2/internal/trie"
	"github.com/sentinel-cli/sentinel/v2/internal/updater"
)

// NewScanCmd builds the `sentinel scan` sub-command for ad-hoc scanning
// of arbitrary files or directories outside of the git hook workflow.
func NewScanCmd() *cobra.Command {
	var (
		configPath string
		format     string
		recursive  bool
		verbose    bool
		history    bool
		outputPath string
		failFast   bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan files or directories for secrets (ad-hoc mode)",
		Long: `Scan arbitrary files, directories, or historical Git commits for secrets in ad-hoc mode.
Unlike the 'run' command (which only inspects Git-staged modifications), 'scan' allows you to audit entire folders recursively or scan the full commit history of a repository to locate historical credentials leaks.

Scanning Modes:
  1. Files & Directories (Default):
     Pass specific files or directories as arguments. Directories are scanned recursively when the '--recursive' flag is active.
  
  2. Git History (--history):
     Audits the entire Git commit log history of the repository. Findings will be prefixed with the triggering Git commit hash (e.g. 5906dee:config/app.json).

You can bypass false positives on specific lines using '// sentinel:ignore' comments.

Custom rules, user-defined signatures, allowlist patterns, and file exclusions are resolved automatically from the '.sentinel.yaml' configuration file.

Examples:
  # Scan a folder recursively
  sentinel scan -r ./src
  
  # Scan specific configuration files
  sentinel scan config.yaml secrets.env

  # Scan and save report directly to a SARIF file (keeps pretty terminal logs)
  sentinel scan -f sarif -o sentinel.sarif .
  
  # Scan the entire Git commit tree history of the current repository
  sentinel scan --history .`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !history && len(args) == 0 {
				return fmt.Errorf("requires at least 1 arg(s), only received 0")
			}
			return runAdHocScan(args, configPath, format, recursive, verbose, history, outputPath, failFast)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .sentinel.yaml config file")
	cmd.Flags().StringVarP(&format, "format", "f", "pretty", "output format: pretty|json|plain|sarif")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "scan directories recursively")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	cmd.Flags().BoolVar(&history, "history", false, "scan entire git commit history")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "write scan report to file")
	cmd.Flags().BoolVar(&failFast, "fail-fast", false, "stop after first finding")

	return cmd
}

func runAdHocScan(paths []string, configPath, format string, recursive, verbose, history bool, outputPath string, failFast bool) error {
	updateChan := updater.CheckForUpdateAsync()
	startTime := time.Now()

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

	var fileReporter *reporter.Reporter
	var file *os.File
	if outputPath != "" {
		var err error
		file, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		fileReporter = reporter.New(file, reporter.ParseFormat(format))
		format = "pretty"
	}

	// JSON is machine-readable output — write to stdout so it can be piped/redirected.
	// Human-readable formats (pretty, plain) go to stderr so progress messages
	// and findings are visible even when stdout is redirected.
	outStream := os.Stderr
	parsedFormat := reporter.ParseFormat(format)
	if parsedFormat == reporter.FormatJSON || parsedFormat == reporter.FormatSARIF {
		outStream = os.Stdout
	}
	rep := reporter.New(outStream, parsedFormat)
	rep.PrintHeader()

	sigs := make([]trie.Signature, len(trie.BuiltinSignatures))
	copy(sigs, trie.BuiltinSignatures)
	for _, cs := range cfg.CustomSignatures {
		var val *regexp.Regexp
		if cs.Regex != "" {
			val = regexp.MustCompile(cs.Regex)
		}
		sev := cs.Severity
		if sev == "" {
			sev = "HIGH"
		}
		sigs = append(sigs, trie.Signature{
			ID:          cs.ID,
			Description: cs.Description,
			Prefix:      cs.Prefix,
			Severity:    sev,
			Validator:   val,
		})
	}
	automaton := trie.Build(sigs)
	scanOpts := scanner.Options{
		EntropyThreshold:  cfg.EntropyThreshold,
		MinSecretLength:   cfg.MinSecretLength,
		DisableTrie:       cfg.DisableTiers.Trie,
		DisableEntropy:    cfg.DisableTiers.Entropy,
		DisableContext:    cfg.DisableTiers.Context,
		AllowlistPatterns: cfg.AllowlistPatterns,
	}
	sec := scanner.New(automaton, scanOpts)

	var allFindings []scanner.Finding
	scannedCount := 0
	seenTokens := make(map[string]struct{})

	if history {
		targetDir := "."
		if len(paths) > 0 {
			targetDir = paths[0]
		}
		if _, err := os.Stat(filepath.Join(targetDir, ".git")); os.IsNotExist(err) {
			return fmt.Errorf("%q is not a git repository (no .git directory found)", targetDir)
		}
		cmd := exec.Command("git", "log", "--all", "-p")
		cmd.Dir = targetDir
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("git log pipe: %w", err)
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("git log start: %w", err)
		}

		bufScanner := bufio.NewScanner(stdout)
		buf := make([]byte, 64*1024)
		bufScanner.Buffer(buf, 10*1024*1024) // 10MB max line length

		var currentChunk []byte
		var currentFile string
		var currentCommit string

		processChunk := func() {
			if len(currentChunk) == 0 || currentFile == "" {
				return
			}
			if cfg.FailFast && len(allFindings) > 0 {
				return
			}
			displayPath := currentCommit + ":" + currentFile
			if scanner.HasExcludedExtension(displayPath, cfg.ExcludeExtensions) {
				return
			}
			if scanner.MatchesExcludePath(currentFile, cfg.ExcludePaths) {
				return
			}
			if int64(len(currentChunk)) > cfg.MaxFileSizeBytes {
				return
			}
			scannedCount++
			findings := sec.ScanContent(displayPath, currentChunk)
			for _, f := range findings {
				if _, exists := seenTokens[f.Token]; !exists {
					seenTokens[f.Token] = struct{}{}
					allFindings = append(allFindings, f)
				}
			}
			currentChunk = currentChunk[:0]
			if scannedCount%250 == 0 {
				debug.FreeOSMemory()
			}
		}

		for bufScanner.Scan() {
			if cfg.FailFast && len(allFindings) > 0 {
				break
			}
			line := bufScanner.Bytes()

			if bytes.HasPrefix(line, []byte("commit ")) {
				processChunk()
				currentCommit = string(line[7:])
				if len(currentCommit) > 7 {
					currentCommit = currentCommit[:7]
				}
				continue
			}

			if bytes.HasPrefix(line, []byte("diff --git")) {
				processChunk()
				continue
			}

			if bytes.HasPrefix(line, []byte("+++ b/")) {
				currentFile = string(line[6:])
				continue
			}

			if len(line) > 0 && line[0] == '+' && !bytes.HasPrefix(line, []byte("+++")) {
				currentChunk = append(currentChunk, line[1:]...)
				currentChunk = append(currentChunk, '\n')
			}
		}

		// If the scanner failed (e.g. token too long), we must close the pipe
		// so git log gets SIGPIPE and exits, otherwise cmd.Wait() deadlocks.
		stdout.Close()

		processChunk()
		cmd.Wait()
	} else {
		type scanJob struct {
			filePath string
			scanRoot string
		}
		var targets []scanJob
		for _, p := range paths {
			info, err := os.Stat(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sentinel: the path %q does not exist or is inaccessible\n", p)
				continue
			}
			absP, err := filepath.Abs(p)
			if err != nil {
				absP = p
			}
			if info.IsDir() {
				if recursive {
					_ = filepath.WalkDir(absP, func(path string, d fs.DirEntry, err error) error {
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
						targets = append(targets, scanJob{filePath: path, scanRoot: absP})
						return nil
					})
				} else {
					entries, _ := os.ReadDir(absP)
					for _, e := range entries {
						if !e.IsDir() {
							targets = append(targets, scanJob{filePath: filepath.Join(absP, e.Name()), scanRoot: absP})
						}
					}
				}
			} else {
				targets = append(targets, scanJob{filePath: absP, scanRoot: filepath.Dir(absP)})
			}
		}

		var wg sync.WaitGroup
		var mu sync.Mutex

		// Limit concurrency to NumCPU to prevent thrashing
		numWorkers := runtime.NumCPU()
		if numWorkers < 4 {
			numWorkers = 4
		}

		jobs := make(chan scanJob, len(targets))
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					filePath := job.filePath
					if cfg.FailFast {
						mu.Lock()
						hasFindings := len(allFindings) > 0
						mu.Unlock()
						if hasFindings {
							continue
						}
					}
					displayPath, err := filepath.Rel(job.scanRoot, filePath)
					if err != nil || displayPath == "" {
						displayPath = filePath
					}

					if scanner.HasExcludedExtension(displayPath, cfg.ExcludeExtensions) {
						continue
					}
					if scanner.MatchesExcludePath(displayPath, cfg.ExcludePaths) {
						continue
					}

					info, err := os.Stat(filePath)
					if err != nil {
						continue
					}
					if !info.Mode().IsRegular() {
						continue
					}
					if info.Size() == 0 || info.Size() > cfg.MaxFileSizeBytes {
						continue
					}

					if !cfg.ScanBinaryFiles && isBinaryFileFast(filePath) {
						continue
					}

					content, err := os.ReadFile(filePath)
					if err != nil {
						if cfg.Verbose {
							mu.Lock()
							fmt.Fprintf(os.Stderr, "  [verbose] cannot read %s: %v\n", filePath, err)
							mu.Unlock()
						}
						continue
					}

					mu.Lock()
					scannedCount++
					shouldGC := scannedCount%500 == 0
					mu.Unlock()

					if shouldGC {
						debug.FreeOSMemory()
					}

					findings := sec.ScanContent(displayPath, content)
					if len(findings) > 0 {
						mu.Lock()
						for _, f := range findings {
							if _, exists := seenTokens[f.Token]; !exists {
								seenTokens[f.Token] = struct{}{}
								allFindings = append(allFindings, f)
							}
						}
						mu.Unlock()
					}
				}
			}()
		}
		wg.Wait()
	}

	elapsed := time.Since(startTime)

	if len(allFindings) == 0 {
		rep.PrintClean(elapsed, scannedCount)
		if fileReporter != nil {
			fileReporter.PrintClean(elapsed, scannedCount)
		}
		select {
		case msg := <-updateChan:
			if msg != "" {
				fmt.Fprintln(os.Stderr, msg)
			}
		default:
		}
		return nil
	}

	rep.PrintFindings(allFindings)
	rep.PrintSummary(allFindings, elapsed, scannedCount)
	if fileReporter != nil {
		fileReporter.PrintFindings(allFindings)
		fileReporter.PrintSummary(allFindings, elapsed, scannedCount)
		if file != nil {
			file.Close()
		}
	}
	os.Exit(1)
	return nil
}

func isBinaryFileFast(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	var buf [8192]byte
	n, _ := f.Read(buf[:])
	return bytes.IndexByte(buf[:n], 0x00) != -1
}
