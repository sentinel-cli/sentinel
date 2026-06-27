// Package reporter handles all output rendering for the Sentinel pre-commit
// hook.  It supports three output modes:
//
//   - Pretty (default): ANSI-coloured, human-friendly terminal output with
//     severity badges, file paths, line numbers, and a summary banner.
//   - JSON: machine-readable structured output for CI system integration.
//   - Plain: no ANSI escapes, suitable for log files and non-TTY environments.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sentinel-cli/sentinel/internal/scanner"
	"github.com/sentinel-cli/sentinel/pkg/version"
)

// ──────────────────────────────────────────────────────────────────────────────
// Output format type
// ──────────────────────────────────────────────────────────────────────────────

// Format controls how findings are rendered.
type Format int

const (
	FormatPretty Format = iota
	FormatJSON
	FormatPlain
)

// ParseFormat converts a string to a Format constant.
func ParseFormat(s string) Format {
	switch strings.ToLower(s) {
	case "json":
		return FormatJSON
	case "plain", "text":
		return FormatPlain
	default:
		return FormatPretty
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Reporter
// ──────────────────────────────────────────────────────────────────────────────

// Reporter writes scan results to an output stream.
type Reporter struct {
	w      io.Writer
	format Format
}

// New returns a Reporter writing to w in the given format.
func New(w io.Writer, format Format) *Reporter {
	return &Reporter{w: w, format: format}
}

// Default returns a Reporter writing to os.Stderr in Pretty format, which is
// the standard for git hooks (stdout may be captured by git).
func Default() *Reporter {
	return &Reporter{w: os.Stderr, format: FormatPretty}
}

// ──────────────────────────────────────────────────────────────────────────────
// Severity colours
// ──────────────────────────────────────────────────────────────────────────────

var (
	criticalBadge = color.New(color.BgRed, color.FgWhite, color.Bold)
	highBadge     = color.New(color.BgHiRed, color.FgBlack, color.Bold)
	mediumBadge   = color.New(color.BgYellow, color.FgBlack, color.Bold)
	lowBadge      = color.New(color.BgHiBlack, color.FgWhite, color.Bold)

	fileColor    = color.New(color.FgHiCyan, color.Bold)
	lineColor    = color.New(color.FgHiWhite)
	tokenColor   = color.New(color.FgHiMagenta, color.Bold)
	tierColor    = color.New(color.FgHiBlue)
	successColor = color.New(color.FgHiGreen, color.Bold)
	errorColor   = color.New(color.FgHiRed, color.Bold)
	dimColor     = color.New(color.FgHiBlack)
	headerColor  = color.New(color.FgHiWhite, color.Bold)
)

// ──────────────────────────────────────────────────────────────────────────────
// Public reporting methods
// ──────────────────────────────────────────────────────────────────────────────

// PrintHeader prints the Sentinel startup banner.
func (r *Reporter) PrintHeader() {
	switch r.format {
	case FormatJSON:
		// No header in JSON mode.
	case FormatPlain:
		fmt.Fprintf(r.w, "sentinel %s — pre-commit security scan\n", version.Version)
		fmt.Fprintln(r.w, strings.Repeat("-", 60))
	default:
		r.prettyHeader()
	}
}

// PrintFindings renders all findings.  Returns true if any CRITICAL or HIGH
// severity findings were emitted (useful for exit-code logic).
func (r *Reporter) PrintFindings(findings []scanner.Finding) bool {
	if r.format == FormatJSON {
		return r.jsonFindings(findings)
	}
	hasBlocker := false
	for _, f := range findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			hasBlocker = true
		}
		r.printOneFinding(f)
	}
	return hasBlocker
}

// PrintSummary renders the final summary line.
func (r *Reporter) PrintSummary(findings []scanner.Finding, elapsed time.Duration, scannedFiles int) {
	switch r.format {
	case FormatJSON:
		r.jsonSummary(findings, elapsed, scannedFiles)
	case FormatPlain:
		r.plainSummary(findings, elapsed, scannedFiles)
	default:
		r.prettySummary(findings, elapsed, scannedFiles)
	}
}

// PrintClean renders the success message when no findings are detected.
func (r *Reporter) PrintClean(elapsed time.Duration, scannedFiles int) {
	switch r.format {
	case FormatJSON:
		fmt.Fprintf(r.w, `{"status":"clean","scanned_files":%d,"elapsed_ms":%d}`+"\n",
			scannedFiles, elapsed.Milliseconds())
	case FormatPlain:
		fmt.Fprintf(r.w, "sentinel: clean — %d file(s) scanned in %s\n",
			scannedFiles, elapsed.Round(time.Millisecond))
	default:
		fmt.Fprintln(r.w)
		successColor.Fprintf(r.w, "  ✔ SENTINEL CLEAN")
		dimColor.Fprintf(r.w, "  —  %d file(s) scanned in %s\n",
			scannedFiles, elapsed.Round(time.Microsecond))
		fmt.Fprintln(r.w)
	}
}

// PrintSkipped logs a file that was skipped with a reason.
func (r *Reporter) PrintSkipped(filePath, reason string) {
	if r.format == FormatPretty {
		dimColor.Fprintf(r.w, "  ⊘  skipping %s (%s)\n", filePath, reason)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Pretty-format internals
// ──────────────────────────────────────────────────────────────────────────────

const sentinelLogo = `
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝`

func (r *Reporter) prettyHeader() {
	dimColor.Fprintln(r.w, sentinelLogo)
	dimColor.Fprintf(r.w, "  Pre-Commit Security Hook  %s  %s\n\n",
		dimColor.Sprint("│"), version.Version)
}

func (r *Reporter) printOneFinding(f scanner.Finding) {
	badge := severityBadge(f.Severity)

	fmt.Fprintln(r.w)
	fmt.Fprintf(r.w, "  %s  ", badge)
	fileColor.Fprintf(r.w, "%s", f.FilePath)
	lineColor.Fprintf(r.w, ":%d\n", f.Line)

	fmt.Fprintf(r.w, "  %s    ", strings.Repeat(" ", len(f.Severity)+2))
	dimColor.Fprintf(r.w, "[%s] ", tierColor.Sprint(f.DetectionTier.String()))
	fmt.Fprintf(r.w, "%s\n", f.Description)

	if f.Token != "" && len(f.Token) > 0 {
		displayToken := maskToken(f.Token)
		fmt.Fprintf(r.w, "  %s    Token:  ", strings.Repeat(" ", len(f.Severity)+2))
		tokenColor.Fprintf(r.w, "%s\n", displayToken)
	}

	if f.DetectionTier == scanner.TierEntropy {
		fmt.Fprintf(r.w, "  %s    Entropy: %.4f bits/symbol\n",
			strings.Repeat(" ", len(f.Severity)+2), f.Entropy)
	}

	// Print a snippet of the offending line, redacting the token.
	snippet := truncateForDisplay(f.LineContent, 120)
	fmt.Fprintf(r.w, "  %s    %s %s\n",
		strings.Repeat(" ", len(f.Severity)+2),
		dimColor.Sprint("→"),
		dimColor.Sprint(snippet))
}

func (r *Reporter) prettySummary(findings []scanner.Finding, elapsed time.Duration, scanned int) {
	critical, high, medium, low := countBySeverity(findings)
	fmt.Fprintln(r.w)
	fmt.Fprintln(r.w, strings.Repeat("─", 68))
	headerColor.Fprintf(r.w, "  SENTINEL SCAN COMPLETE\n")
	fmt.Fprintf(r.w, "  Files scanned : %d\n", scanned)
	fmt.Fprintf(r.w, "  Elapsed       : %s\n", elapsed.Round(time.Microsecond))
	fmt.Fprintf(r.w, "  Findings      : ")
	criticalBadge.Fprintf(r.w, " CRITICAL:%d ", critical)
	fmt.Fprintf(r.w, " ")
	highBadge.Fprintf(r.w, " HIGH:%d ", high)
	fmt.Fprintf(r.w, " ")
	mediumBadge.Fprintf(r.w, " MEDIUM:%d ", medium)
	fmt.Fprintf(r.w, " ")
	lowBadge.Fprintf(r.w, " LOW:%d ", low)
	fmt.Fprintln(r.w)
	fmt.Fprintln(r.w, strings.Repeat("─", 68))
	fmt.Fprintln(r.w)

	errorColor.Fprintf(r.w, "  ✘ COMMIT BLOCKED — remove the secrets above and try again.\n\n")
}

func (r *Reporter) plainSummary(findings []scanner.Finding, elapsed time.Duration, scanned int) {
	critical, high, medium, low := countBySeverity(findings)
	fmt.Fprintf(r.w, "sentinel: %d finding(s) — CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d — %d file(s) in %s\n",
		len(findings), critical, high, medium, low, scanned, elapsed.Round(time.Millisecond))
	fmt.Fprintln(r.w, "commit blocked")
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON output internals
// ──────────────────────────────────────────────────────────────────────────────

type jsonFinding struct {
	FilePath    string  `json:"file_path"`
	Line        int     `json:"line"`
	Severity    string  `json:"severity"`
	Tier        string  `json:"tier"`
	SignatureID string  `json:"signature_id"`
	Description string  `json:"description"`
	Token       string  `json:"token"`
	Entropy     float64 `json:"entropy,omitempty"`
	LineSnippet string  `json:"line_snippet"`
}

type jsonReport struct {
	Version     string        `json:"sentinel_version"`
	Status      string        `json:"status"`
	ScannedFiles int          `json:"scanned_files"`
	ElapsedMs   int64         `json:"elapsed_ms"`
	Findings    []jsonFinding `json:"findings"`
}

func (r *Reporter) jsonFindings(findings []scanner.Finding) bool {
	// Findings are batched; actual JSON output happens in jsonSummary.
	// This method just determines whether there are blockers.
	for _, f := range findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			return true
		}
	}
	return false
}

func (r *Reporter) jsonSummary(findings []scanner.Finding, elapsed time.Duration, scanned int) {
	status := "clean"
	if len(findings) > 0 {
		status = "blocked"
	}

	jf := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		jf = append(jf, jsonFinding{
			FilePath:    f.FilePath,
			Line:        f.Line,
			Severity:    f.Severity,
			Tier:        f.DetectionTier.String(),
			SignatureID: f.SignatureID,
			Description: f.Description,
			Token:       maskToken(f.Token),
			Entropy:     f.Entropy,
			LineSnippet: truncateForDisplay(f.LineContent, 200),
		})
	}

	report := jsonReport{
		Version:      version.Version,
		Status:       status,
		ScannedFiles: scanned,
		ElapsedMs:    elapsed.Milliseconds(),
		Findings:     jf,
	}
	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
}

// ──────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ──────────────────────────────────────────────────────────────────────────────

// maskToken partially redacts a token for display, preserving the first 6 and
// last 4 characters.  Short tokens are fully masked.
func maskToken(tok string) string {
	if len(tok) <= 10 {
		return strings.Repeat("*", len(tok))
	}
	visible := 6
	suffix := 4
	return tok[:visible] + strings.Repeat("*", len(tok)-visible-suffix) + tok[len(tok)-suffix:]
}

// severityBadge returns a coloured badge for the given severity string.
func severityBadge(severity string) string {
	label := fmt.Sprintf(" %-8s ", severity)
	switch severity {
	case "CRITICAL":
		return criticalBadge.Sprint(label)
	case "HIGH":
		return highBadge.Sprint(label)
	case "MEDIUM":
		return mediumBadge.Sprint(label)
	default:
		return lowBadge.Sprint(label)
	}
}

// countBySeverity tallies findings by severity bucket.
func countBySeverity(findings []scanner.Finding) (critical, high, medium, low int) {
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		default:
			low++
		}
	}
	return
}

// truncateForDisplay returns up to maxLen visible bytes from a line.
func truncateForDisplay(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}


