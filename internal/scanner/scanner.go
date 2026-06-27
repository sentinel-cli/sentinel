// Package scanner orchestrates the three-tier Sentinel detection pipeline
// for a single staged file.  It coordinates:
//
//   - Tier 1 (trie)    — Aho-Corasick pattern matching
//   - Tier 2 (entropy) — Shannon entropy analysis
//   - Tier 3 (context) — Context-aware false-positive filtering
//
// The scanner is intentionally stateless: the same Scanner value can be reused
// concurrently across multiple goroutines.
package scanner

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	sentinelcontext "github.com/sentinel-cli/sentinel/internal/context"
	"github.com/sentinel-cli/sentinel/internal/entropy"
	"github.com/sentinel-cli/sentinel/internal/trie"
)

// ──────────────────────────────────────────────────────────────────────────────
// Finding — the universal result type
// ──────────────────────────────────────────────────────────────────────────────

// Tier identifies which detection tier produced a finding.
type Tier int

const (
	TierTrie    Tier = 1
	TierEntropy Tier = 2
)

// String returns a short label for the tier.
func (t Tier) String() string {
	switch t {
	case TierTrie:
		return "PATTERN"
	case TierEntropy:
		return "ENTROPY"
	default:
		return "UNKNOWN"
	}
}

// Finding is a confirmed detection after all three tiers have been applied.
type Finding struct {
	// FilePath is the repository-relative path of the file.
	FilePath string

	// Line is the 1-indexed line number.
	Line int

	// LineContent is the text of the triggering line (≤512 bytes).
	LineContent string

	// Token is the specific value that triggered the detector.
	Token string

	// Entropy is the Shannon entropy of Token (0 for Tier 1 pattern hits).
	Entropy float64

	// DetectionTier records which pipeline stage found this secret.
	DetectionTier Tier

	// SignatureID is the Signature.ID (Tier 1) or "high-entropy-{kind}" (Tier 2).
	SignatureID string

	// Description is a human-readable label.
	Description string

	// Severity is one of CRITICAL / HIGH / MEDIUM / LOW.
	Severity string
}

// ──────────────────────────────────────────────────────────────────────────────
// Scanner
// ──────────────────────────────────────────────────────────────────────────────

// Options controls what the scanner does during a scan.
type Options struct {
	EntropyThreshold float64
	MinSecretLength  int
	DisableTrie      bool
	DisableEntropy   bool
	DisableContext   bool
}

// Scanner is the central scanning engine.
type Scanner struct {
	automaton *trie.Automaton
	opts      Options
}

// New builds a Scanner from the compiled Aho-Corasick automaton and options.
func New(automaton *trie.Automaton, opts Options) *Scanner {
	return &Scanner{
		automaton: automaton,
		opts:      opts,
	}
}

// fmtVerbRE matches printf-style format verbs so they can be rejected as tokens.
var fmtVerbRE = regexp.MustCompile(`^%[+\-# 0-9]*[vTtbcdoOqxXUeEfFgGsSpw]`)

// ScanContent runs the full three-tier pipeline against the given raw content
// and returns all confirmed Findings.
//
// filePath is used only for Tier 3 context decisions (test-file suppression).
func (s *Scanner) ScanContent(filePath string, content []byte) []Finding {
	var findings []Finding

	// We don't need a global map anymore since we process line by line.
	lineNum := 0
	start := 0
	for start < len(content) {
		lineNum++
		end := bytes.IndexByte(content[start:], '\n')
		var rawLine []byte
		if end == -1 {
			rawLine = content[start:]
			start = len(content)
		} else {
			rawLine = content[start : start+end]
			start = start + end + 1
		}

		lineTrim := bytes.TrimSpace(rawLine)
		var capturedTokens []string

		// ── Skip comment lines early (Tier 3 check 2 fast path) ──────────────
		if bytes.HasPrefix(lineTrim, []byte("//")) || bytes.HasPrefix(lineTrim, []byte("#")) {
			continue
		}

		// ── Value isolation ───────────────────────────────────────────────────
		// CRITICAL FIX: We must isolate only the secret *value* portion of the
		// line, not format strings, variable names, or function arguments.
		//
		// Strategy:
		//  1. If the line contains an assignment operator (:= or =), extract
		//     only the RHS, then further isolate the first quoted literal or the
		//     first whitespace-delimited token from the RHS.
		//  2. If there is no assignment, scan only the content of quoted string
		//     literals on the line (what lives between quote chars).
		//
		// This prevents "token=%s" format verbs, SQL bind params like
		// "password=?", and variable names like "ACAccountSID" from being
		// treated as secret values.



		val, _ := extractSecretValue(lineTrim)
		// We do not 'continue' here if val == nil, because we still want to run
		// the Tier 1 Aho-Corasick automaton on the full line to catch leaks
		// dumped directly in logs, text files, or raw JSON.

		targetStr := val
		if targetStr == nil {
			targetStr = lineTrim
		} else {
			targetStr = bytes.TrimSpace(targetStr)
		}

		vLen := len(targetStr)

		// ── Build the compact form (strip string-joining noise) ───────────────
		var compVal []byte
		var cLen int
		if vLen >= 16 && vLen <= 400 {
			var compBuf [512]byte
			for _, b := range targetStr {
				if b != ' ' && b != '+' && b != '.' && b != '"' && b != '\'' && b != '`' {
					if cLen < len(compBuf) {
						compBuf[cLen] = b
						cLen++
					}
				}
			}
			compVal = compBuf[:cLen]
		}

		hasSpace := bytes.ContainsRune(targetStr, ' ')
		if hasSpace {
			spaceCount := bytes.Count(targetStr, []byte{' '})
			if spaceCount == 11 || spaceCount == 14 || spaceCount == 17 || spaceCount == 20 || spaceCount == 23 {
				if isStrictBip39Mnemonic(string(targetStr)) {
					findings = append(findings, Finding{
						FilePath:      filePath,
						Line:          lineNum,
						LineContent:   string(rawLine),
						Token:         cleanToken(string(targetStr)),
						Entropy:       0,
						DetectionTier: TierTrie,
						SignatureID:   "bip39-mnemonic",
						Description:   "BIP-39 Crypto Recovery Seed",
						Severity:      "CRITICAL",
					})
					continue
				}
			}
		}
		if !s.opts.DisableTrie && s.automaton != nil {
			// CRITICAL: We search the FULL lineTrim to catch leaked tokens in logs,
			// raw JSON, or unstructured text, bypassing the strict assignment rules.
			matches := s.automaton.Search(lineTrim)

			// Process line matches
			for _, m := range matches {
				token := extractTokenFromOffset(string(lineTrim), m.Sig.Prefix, m.Offset)
				if token == "" {
					continue
				}

				if m.Sig.Validator != nil && !m.Sig.Validator.MatchString(token) {
					continue
				}

				if fmtVerbRE.MatchString(token) {
					continue
				}
				if !isPlausibleSecretToken(token, m.Sig.Prefix, s.opts.MinSecretLength) {
					continue
				}
				decision := sentinelcontext.Real
				if !s.opts.DisableContext {
					decision = sentinelcontext.Classify(filePath, string(rawLine), token)
				}
				if decision == sentinelcontext.Real {
					isDuplicate := false
					for _, ct := range capturedTokens {
						if ct == token {
							isDuplicate = true
							break
						}
					}
					if isDuplicate {
						continue
					}
					capturedTokens = append(capturedTokens, token)
					findings = append(findings, Finding{
						FilePath:      filePath,
						Line:          lineNum,
						LineContent:   string(rawLine),
						Token:         cleanToken(token),
						Entropy:       entropy.Shannon([]byte(token)),
						DetectionTier: TierTrie,
						SignatureID:   m.Sig.ID,
						Description:   m.Sig.Description,
						Severity:      m.Sig.Severity,
					})
				}
			}

			// Process compMatches if needed
			if len(matches) == 0 && cLen > 0 && cLen < vLen {
				compMatches := s.automaton.Search(compVal)
				for _, m := range compMatches {
					token := extractTokenFromOffset(string(compVal), m.Sig.Prefix, m.Offset)
					if token == "" {
						continue
					}

					if m.Sig.Validator != nil && !m.Sig.Validator.MatchString(token) {
						continue
					}

					if fmtVerbRE.MatchString(token) {
						continue
					}
					if !isPlausibleSecretToken(token, m.Sig.Prefix, s.opts.MinSecretLength) {
						continue
					}
					decision := sentinelcontext.Real
					if !s.opts.DisableContext {
						decision = sentinelcontext.Classify(filePath, string(rawLine), token)
					}
					if decision == sentinelcontext.Real {
						isDuplicate := false
						for _, ct := range capturedTokens {
							if ct == token {
								isDuplicate = true
								break
							}
						}
						if isDuplicate {
							continue
						}
						capturedTokens = append(capturedTokens, token)
						findings = append(findings, Finding{
							FilePath:      filePath,
							Line:          lineNum,
							LineContent:   string(rawLine),
							Token:         cleanToken(token),
							Entropy:       entropy.Shannon([]byte(token)),
							DetectionTier: TierTrie,
							SignatureID:   m.Sig.ID,
							Description:   m.Sig.Description,
							Severity:      m.Sig.Severity,
						})
					}
				}
			}
		}

		// ── Single-Layer Base64 Decoding ─────────────────────────────
		if cLen >= 20 {
			isB64 := true
			for _, b := range compVal {
				if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '=') {
					isB64 = false
					break
				}
			}
			if isB64 {
				decLen := base64.StdEncoding.DecodedLen(len(compVal))
				decBuf := make([]byte, decLen)
				n, err := base64.StdEncoding.Decode(decBuf, compVal)
				if err == nil {
					decodedVal := decBuf[:n]
					if !s.opts.DisableTrie && s.automaton != nil {
						decMatches := s.automaton.Search(decodedVal)
						for _, m := range decMatches {
							token := extractTokenFromOffset(string(decodedVal), m.Sig.Prefix, m.Offset)
							if token == "" {
								continue
							}
							if m.Sig.Validator != nil && !m.Sig.Validator.MatchString(token) {
								continue
							}
							if fmtVerbRE.MatchString(token) {
								continue
							}
							if !isPlausibleSecretToken(token, m.Sig.Prefix, s.opts.MinSecretLength) {
								continue
							}
							decision := sentinelcontext.Real
							if !s.opts.DisableContext {
								decision = sentinelcontext.Classify(filePath, string(rawLine), token)
							}
							if decision == sentinelcontext.Real {
								isDuplicate := false
								for _, ct := range capturedTokens {
									if ct == token {
										isDuplicate = true
										break
									}
								}
								if isDuplicate {
									continue
								}
								capturedTokens = append(capturedTokens, token)
								findings = append(findings, Finding{
									FilePath:      filePath,
									Line:          lineNum,
									LineContent:   string(rawLine),
									Token:         cleanToken(token),
									Entropy:       entropy.Shannon([]byte(token)),
									DetectionTier: TierTrie,
									SignatureID:   m.Sig.ID,
									Description:   m.Sig.Description + " (Base64 Decoded)",
									Severity:      m.Sig.Severity,
								})
							}
						}
					}
				}
			}
		}

		if !s.opts.DisableEntropy {
			// Entropy tier runs when the value has no spaces (looks like a single
			// dense token)
			if !hasSpace {
				if cLen >= s.opts.MinSecretLength {
					hits := entropy.Analyze(compVal, s.opts.EntropyThreshold, s.opts.MinSecretLength)
					for _, h := range hits {
						isDuplicate := false
						for _, ct := range capturedTokens {
							if strings.Contains(h.Token, ct) || strings.Contains(ct, h.Token) {
								isDuplicate = true
								break
							}
						}
						if isDuplicate {
							continue
						}
						decision := sentinelcontext.Real
						if !s.opts.DisableContext {
							decision = sentinelcontext.Classify(filePath, string(rawLine), h.Token)
						}
						if decision == sentinelcontext.Real {
							capturedTokens = append(capturedTokens, h.Token)
							findings = append(findings, Finding{
								FilePath:      filePath,
								Line:          lineNum,
								LineContent:   string(rawLine),
								Token:         cleanToken(h.Token),
								Entropy:       h.Entropy,
								DetectionTier: TierEntropy,
								SignatureID:   fmt.Sprintf("high-entropy-%s", h.Kind),
								Description:   fmt.Sprintf("High-entropy %s string (entropy=%.2f)", strings.ToUpper(h.Kind), h.Entropy),
								Severity:      entropySeverity(h.Entropy),
							})
						}
					}
				}
			}
		}
	}
	return aggregateBlobs(findings)
}

// IsBinary performs a fast binary-file check by scanning the first 8 KB of
// content for null bytes — a reliable heuristic used by git itself.
func IsBinary(content []byte) bool {
	sample := content
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	return bytes.IndexByte(sample, 0x00) != -1
}

// HasExcludedExtension returns true when the file's extension is in the
// excluded list.
func HasExcludedExtension(filePath string, excluded []string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, e := range excluded {
		if strings.ToLower(e) == ext {
			return true
		}
	}
	return false
}

// MatchesExcludePath returns true when filePath matches any of the given glob
// patterns.
func MatchesExcludePath(filePath string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, filePath)
		if err == nil && matched {
			return true
		}
		// Also check if the pattern matches any path component.
		if matchesPathComponent(filePath, pattern) {
			return true
		}
	}
	return false
}

// matchesPathComponent checks whether pattern matches any directory segment or
// suffix of filePath, enabling patterns like "vendor/**" to work correctly.
func matchesPathComponent(filePath, pattern string) bool {
	// Strip trailing /** for simpler matching.
	trimmedPattern := strings.TrimSuffix(pattern, "/**")
	trimmedPattern = strings.TrimSuffix(trimmedPattern, "/*")

	return strings.HasPrefix(filePath, trimmedPattern+"/") ||
		strings.HasPrefix(filePath, trimmedPattern+"\\") ||
		filePath == trimmedPattern
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

// extractSecretValue isolates the portion of a line that could plausibly
// contain a secret value, returning (value, isAssignment).
//
// Rules:
//  1. If the line has a Go-style ":=" or shell/YAML "=" assignment, return
//     the isolated RHS token (first quoted literal or first space-delimited
//     word on the RHS). isAssignment = true.
//  2. Otherwise, collect and concatenate the content of every quoted string
//     literal on the line separated by spaces. isAssignment = false.
//
// This ensures that:
//   - Format strings like "token=%s" are never returned as values.
//   - Variable names like "ACAccountSID" are never returned as values.
//   - Only the actual RHS of an assignment or an inline literal is evaluated.
func extractSecretValue(lineTrim []byte) (val []byte, isAssignment bool) {
	line := string(lineTrim)

	// ── Assignment branch ─────────────────────────────────────────────────────
	// Detect ":=" (Go) or "=" (shell/env/YAML/generic) assignment operators.
	// We must be careful not to trigger on "==" (comparison) or inside quotes.
	rhsStr, ok := extractRHS(line)
	if ok {
		// From the RHS, prefer the first quoted literal. If none, take the first
		// whitespace-delimited token (could be a bare value like an API key).
		quoted := firstQuotedLiteral(rhsStr)
		if quoted != "" {
			return []byte(quoted), true
		}
		// Bare token: strip trailing punctuation common in code.
		fields := strings.Fields(rhsStr)
		if len(fields) > 0 {
			bare := strings.TrimRight(fields[0], `"'`+"`,;)")
			if bare != "" {
				return []byte(bare), true
			}
		}
		return nil, true
	}

	// ── Quoted-literal branch (non-assignment lines) ───────────────────────────
	// Only scan what is inside quoted strings on the line. Never the raw tokens
	// like variable names or format verbs outside quotes.
	quoted := allQuotedLiterals(line)
	if quoted == "" {
		return nil, false
	}
	return []byte(quoted), false
}

// extractRHS detects an assignment operator on the line and returns the RHS.
// It returns ("", false) if no assignment is present.
// It correctly handles:
//   - ":="  Go short variable declaration
//   - "="   shell / env / YAML / generic (but not "==" or "!=")
//   - ":"   YAML key: value (but only when "=" is absent)
func extractRHS(line string) (string, bool) {
	// :=  — highest priority (Go)
	if idx := strings.Index(line, ":="); idx >= 0 {
		return strings.TrimSpace(line[idx+2:]), true
	}

	// = — but not == or !=
	// Scan character by character to find a bare = that is not doubled.
	inQuote := false
	var quoteChar byte
	for i := 0; i < len(line); i++ {
		b := line[i]
		if inQuote {
			if b == quoteChar && (i == 0 || line[i-1] != '\\') {
				inQuote = false
			}
			continue
		}
		if b == '"' || b == '\'' || b == '`' {
			inQuote = true
			quoteChar = b
			continue
		}
		if b == '=' {
			// Reject "==" and "!=" and ">=" and "<="
			prev := byte(0)
			if i > 0 {
				prev = line[i-1]
			}
			next := byte(0)
			if i+1 < len(line) {
				next = line[i+1]
			}
			if next == '=' || prev == '!' || prev == '<' || prev == '>' || prev == '=' {
				continue
			}
			return strings.TrimSpace(line[i+1:]), true
		}
	}

	// : YAML-style — only if there is no = on the line at all.
	if idx := strings.Index(line, ":"); idx >= 0 {
		// Make sure it is not inside a quoted string or URL (://).
		after := strings.TrimSpace(line[idx+1:])
		if strings.HasPrefix(after, "//") {
			return "", false // URL protocol like https://
		}
		return after, true
	}

	return "", false
}

// firstQuotedLiteral returns the content of the first quoted string (using
// double-quote, single-quote, or backtick delimiters) found in s.
func firstQuotedLiteral(s string) string {
	inQuote := false
	var quoteChar byte
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if inQuote {
			if b == quoteChar && (i == 0 || s[i-1] != '\\') {
				return buf.String()
			}
			buf.WriteByte(b)
		} else if b == '"' || b == '\'' || b == '`' {
			inQuote = true
			quoteChar = b
			buf.Reset()
		}
	}
	return ""
}

// allQuotedLiterals returns the concatenated content of every quoted string
// literal found in s, separated by spaces.  Used for non-assignment lines
// where we want to scan only what is inside string literals.
func allQuotedLiterals(s string) string {
	var parts []string
	inQuote := false
	var quoteChar byte
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if inQuote {
			if b == quoteChar && (i == 0 || s[i-1] != '\\') {
				inQuote = false
				if buf.Len() > 0 {
					parts = append(parts, buf.String())
					buf.Reset()
				}
			} else {
				buf.WriteByte(b)
			}
		} else if b == '"' || b == '\'' || b == '`' {
			inQuote = true
			quoteChar = b
		}
	}
	return strings.Join(parts, " ")
}

// extractTokenFromMatch attempts to extract the actual secret value that
// follows the matched prefix.  It is called with val — the already-isolated
// RHS or literal content — not the raw line.
//
// If isAssignment is true the prefix may appear directly in val; if false,
// val is already the quoted-literal content and the prefix must be present
// extractTokenFromOffset isolates the secret token from the string given the exact offset
// where the pattern prefix ends.
func extractTokenFromOffset(val, prefix string, offset int) string {
	start := offset - len(prefix) + 1
	if start < 0 || offset >= len(val) {
		return ""
	}

	after := ""
	if strings.HasSuffix(prefix, "=") || strings.HasSuffix(prefix, ":") {
		after = strings.TrimSpace(val[offset+1:])
	} else {
		after = strings.TrimSpace(val[start:])
	}

	// Strict bypass for PEM headers (don't break on spaces, keep dashes)
	if strings.HasPrefix(after, "-----BEGIN ") {
		endIdx := strings.Index(after[11:], "-----")
		if endIdx != -1 {
			return after[:11+endIdx+5]
		}
		return after // fallback
	}

	after = strings.TrimLeft(after, "\"'`=: ")
	
	// Truncate at the first closing quote to properly isolate tokens in minified code
	// where space delimiters do not exist.
	if qIdx := strings.IndexAny(after, "\"'`"); qIdx > 0 {
		after = after[:qIdx]
	}

	fields := strings.Fields(after)
	if len(fields) == 0 {
		return ""
	}
	tok := cleanToken(fields[0])
	if len(tok) == 0 {
		return ""
	}
	return tok
}

// cleanToken strips non-alphanumeric characters commonly found trailing or leading
// in code, JSON, and string literals to prevent token leakage.
func cleanToken(tok string) string {
	tok = strings.TrimSpace(tok)
	return strings.Trim(tok, "\\\"'`{}[](),;:.<>")
}

// isStrictBip39Mnemonic verifies that the value is an exact BIP-39 mnemonic phrase.
// It must be precisely 12, 15, 18, 21, or 24 words long, separated by single spaces,
// and contain ONLY valid words from the BIP-39 list. No punctuation allowed.
func isStrictBip39Mnemonic(val string) bool {
	fields := strings.Split(val, " ")
	count := len(fields)
	if count != 12 && count != 15 && count != 18 && count != 21 && count != 24 {
		return false
	}
	for _, word := range fields {
		if !trie.IsBIP39Word(word) {
			return false
		}
	}
	return true
}

// isPlausibleSecretToken returns true when the token is a plausible secret
// rather than a code identifier or format verb.
//
// The key heuristic: for signatures with very short prefixes (≤ 3 bytes, like
// "AC", "SK", "SG."), the suffix (token minus prefix) must be long enough to
// qualify as a secret and must not look like a plain CamelCase/PascalCase
// Go identifier (all ASCII letters and digits with no special chars).
func isPlausibleSecretToken(token, prefix string, minLen int) bool {
	if len(token) < minLen/2 {
		return false
	}
	// For short prefixes, apply stricter checks.
	if len(prefix) <= 3 {
		suffix := token
		if strings.HasPrefix(strings.ToLower(token), strings.ToLower(prefix)) {
			suffix = token[len(prefix):]
		}
		// The suffix must be long enough.
		if len(suffix) < minLen {
			return false
		}
		// If the suffix is pure ASCII letters/digits it looks like a code
		// identifier (e.g., "ACAccountSID", "SKStatusCode") — reject it.
		if isPureIdentifier(suffix) {
			return false
		}
	}
	return true
}

// isPureIdentifier returns true when s consists only of ASCII letters and
// digits (a Go/Java-style identifier with no separators or special chars).
// Real API tokens always contain at least one non-alphanumeric character
// (dash, underscore, dot) or mix of case + digits typical of base64/hex.
func isPureIdentifier(s string) bool {
	hasNonAlpha := false
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			hasNonAlpha = true
			break
		}
	}
	return !hasNonAlpha
}

// entropySeverity maps an entropy value to a severity level.
func entropySeverity(e float64) string {
	switch {
	case e >= 7.0:
		return "CRITICAL"
	case e >= 6.0:
		return "HIGH"
	case e >= 5.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// aggregateBlobs finds consecutive lines of high-entropy base64 and merges them
// into a single massive blob finding, preventing alert fragmentation.
func aggregateBlobs(findings []Finding) []Finding {
	if len(findings) < 3 {
		return findings
	}
	var result []Finding
	var currentBlob []Finding

	flushBlob := func() {
		if len(currentBlob) >= 3 {
			first := currentBlob[0]
			result = append(result, Finding{
				FilePath:      first.FilePath,
				Line:          first.Line,
				LineContent:   fmt.Sprintf("[... %d consecutive lines of Base64 ...]", len(currentBlob)),
				Token:         fmt.Sprintf("<%d lines aggregated>", len(currentBlob)),
				Entropy:       first.Entropy,
				DetectionTier: TierTrie,
				SignatureID:   "massive-base64-blob",
				Description:   "Massive Base64/Cryptographic Blob Detected (Potential Keystore/Vault)",
				Severity:      "CRITICAL",
			})
		} else {
			result = append(result, currentBlob...)
		}
		currentBlob = nil
	}

	for _, f := range findings {
		if f.SignatureID == "high-entropy-base64" {
			if len(currentBlob) == 0 {
				currentBlob = append(currentBlob, f)
			} else {
				lastLine := currentBlob[len(currentBlob)-1].Line
				if f.Line == lastLine+1 || f.Line == lastLine {
					currentBlob = append(currentBlob, f)
				} else {
					flushBlob()
					currentBlob = append(currentBlob, f)
				}
			}
		} else {
			flushBlob()
			result = append(result, f)
		}
	}
	flushBlob()

	return result
}
