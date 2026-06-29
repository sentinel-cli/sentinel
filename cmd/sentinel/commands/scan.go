package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
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
		history    bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan files or directories for secrets (ad-hoc mode)",
		Long: `Scan lets you run Sentinel against arbitrary files or directories,
independent of git staging.  Useful for auditing existing codebases.

You can also use the '--history' flag to audit the entire Git commit tree.
The output will prefix findings with their respective commit hashes (e.g. 3de60c5:file.go).

You can bypass false positives by adding '// sentinel:ignore' to the preceding line.

Examples:
  sentinel scan ./src
  sentinel scan config.yaml secrets.env
  sentinel scan --recursive /home/user/projects/myapp
  sentinel scan --history .`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !history && len(args) == 0 {
				return fmt.Errorf("requires at least 1 arg(s), only received 0")
			}
			return runAdHocScan(args, configPath, format, recursive, verbose, history)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .sentinel.yaml config file")
	cmd.Flags().StringVarP(&format, "format", "f", "pretty", "output format: pretty|json|plain")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "scan directories recursively")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	cmd.Flags().BoolVar(&history, "history", false, "scan entire git commit history")

	return cmd
}

func runAdHocScan(paths []string, configPath, format string, recursive, verbose, history bool) error {
	updateChan := updater.CheckForUpdateAsync()
	startTime := time.Now()

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if verbose {
		cfg.Verbose = true
	}

	// JSON is machine-readable output — write to stdout so it can be piped/redirected.
	// Human-readable formats (pretty, plain) go to stderr so progress messages
	// and findings are visible even when stdout is redirected.
	outStream := os.Stderr
	if reporter.ParseFormat(format) == reporter.FormatJSON {
		outStream = os.Stdout
	}
	rep := reporter.New(outStream, reporter.ParseFormat(format))
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
	seenTokens := make(map[string]struct{})

	if history {
		cmd := exec.Command("git", "log", "--all", "-p")
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
		}

		for bufScanner.Scan() {
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
		// Collect all target file paths.
		var targets []string
		for _, p := range paths {
			info, err := os.Stat(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sentinel: the path %q does not exist or is inaccessible\n", p)
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

		var wg sync.WaitGroup
		var mu sync.Mutex

		// Limit concurrency to NumCPU to prevent thrashing
		numWorkers := runtime.NumCPU()
		if numWorkers < 4 {
			numWorkers = 4
		}
		
		jobs := make(chan string, len(targets))
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for filePath := range jobs {
					if scanner.HasExcludedExtension(filePath, cfg.ExcludeExtensions) {
						continue
					}
					if scanner.MatchesExcludePath(filePath, cfg.ExcludePaths) {
						continue
					}

					info, err := os.Stat(filePath)
					if err != nil {
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
					mu.Unlock()

					findings := sec.ScanContent(filePath, content)
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
