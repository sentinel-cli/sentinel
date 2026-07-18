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

	"github.com/crenoxhq/crenox/v2/internal/config"
	"github.com/crenoxhq/crenox/v2/internal/reporter"
	"github.com/crenoxhq/crenox/v2/internal/scanner"
	"github.com/crenoxhq/crenox/v2/internal/trie"
	"github.com/crenoxhq/crenox/v2/internal/updater"
)

// NewScanCmd builds the `crenox scan` sub-command for ad-hoc scanning
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

You can bypass false positives on specific lines using '// crenox:ignore' comments.

Custom rules, user-defined signatures, allowlist patterns, and file exclusions are resolved automatically from the '.crenox.yaml' configuration file.

Examples:
  # Scan a folder recursively
  crenox scan -r ./src
  
  # Scan specific configuration files
  crenox scan config.yaml secrets.env

  # Scan and save report directly to a SARIF file (keeps pretty terminal logs)
  crenox scan -f sarif -o crenox.sarif .
  
  # Scan the entire Git commit tree history of the current repository
  crenox scan --history .`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !history && len(args) == 0 {
				return fmt.Errorf("requires at least 1 arg(s), only received 0")
			}
			return runAdHocScan(args, configPath, format, recursive, verbose, history, outputPath, failFast)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .crenox.yaml config file")
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
		var chunkTooLarge bool

		processChunk := func() {
			if chunkTooLarge {
				currentChunk = nil
				chunkTooLarge = false
				return
			}
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
			if scannedCount%250 == 0 {
				currentChunk = nil
				debug.FreeOSMemory()
			} else {
				currentChunk = currentChunk[:0]
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
				if !chunkTooLarge {
					if int64(len(currentChunk)+len(line)-1) > cfg.MaxFileSizeBytes {
						chunkTooLarge = true
						currentChunk = nil
					} else {
						currentChunk = append(currentChunk, line[1:]...)
						currentChunk = append(currentChunk, '\n')
					}
				}
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

		var wg sync.WaitGroup
		var mu sync.Mutex

		numWorkers := runtime.NumCPU()
		if numWorkers < 4 {
			numWorkers = 4
		}

		// Buffer of 1024 keeps RAM footprint low on large repositories
		// by not queuing too many files in memory at once.
		jobs := make(chan scanJob, 1024)

		// Start concurrent workers
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
					displayPath := fastRelPath(job.scanRoot, filePath)

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

					file, err := os.Open(filePath)
					if err != nil {
						if cfg.Verbose {
							mu.Lock()
							fmt.Fprintf(os.Stderr, "  [verbose] cannot open %s: %v\n", filePath, err)
							mu.Unlock()
						}
						continue
					}

					var head [8192]byte
					n, _ := file.Read(head[:])
					if !cfg.ScanBinaryFiles && scanner.IsBinary(head[:n]) {
						file.Close()
						continue
					}

					_, _ = file.Seek(0, 0)

					mu.Lock()
					scannedCount++
					mu.Unlock()

					findings := sec.ScanReader(displayPath, file)
					file.Close()
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

		// Stream files to workers on the fly to avoid allocating a huge slice of all files in memory.
		// Excluded directories are pruned early during the WalkDir to avoid unnecessary system calls.
		go func() {
			defer close(jobs)
			for _, p := range paths {
				info, err := os.Stat(p)
				if err != nil {
					fmt.Fprintf(os.Stderr, "crenox: the path %q does not exist or is inaccessible\n", p)
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
								if name == ".git" {
									return fs.SkipDir
								}
								rel := fastRelPath(absP, path)
								if rel != "." && rel != "" {
									if scanner.MatchesExcludePath(rel, cfg.ExcludePaths) {
										return fs.SkipDir
									}
								}
								return nil
							}
							jobs <- scanJob{filePath: path, scanRoot: absP}
							return nil
						})
					} else {
						entries, _ := os.ReadDir(absP)
						for _, e := range entries {
							if !e.IsDir() {
								jobs <- scanJob{filePath: filepath.Join(absP, e.Name()), scanRoot: absP}
							}
						}
					}
				} else {
					jobs <- scanJob{filePath: absP, scanRoot: filepath.Dir(absP)}
				}
			}
		}()

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

func fastRelPath(root, path string) string {
	if len(path) > len(root) {
		rel := path[len(root):]
		if len(rel) > 0 && (rel[0] == '/' || rel[0] == '\\') {
			return rel[1:]
		}
		return rel
	}
	return path
}
