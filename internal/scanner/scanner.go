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
	"sync"

	sentinelcontext "github.com/sentinel-cli/sentinel/v2/internal/context"
	"github.com/sentinel-cli/sentinel/v2/internal/entropy"
	"github.com/sentinel-cli/sentinel/v2/internal/trie"
)

// ──────────────────────────────────────────────────────────────────────────────
// Finding — the universal result type
// ──────────────────────────────────────────────────────────────────────────────

// Tier identifies which detection tier produced a finding.
// Note: "Tier 3 (Context)" is implemented as a suppression/filtering layer
// via the sentinelcontext package, which is why it doesn't have a direct
// TierContext constant representing a detection source here.
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
	EntropyThreshold  float64
	MinSecretLength   int
	DisableTrie       bool
	DisableEntropy    bool
	DisableContext    bool
	AllowlistPatterns []string
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

// isDuplicateMatch checks if a new Finding's token already exists in the matches slice.
func (s *Scanner) isDuplicateMatch(matches []Finding, newMatch Finding) bool {
	for _, m := range matches {
		if m.FilePath == newMatch.FilePath && m.Line == newMatch.Line {
			if m.Token == newMatch.Token {
				return true
			}
			if strings.Contains(newMatch.Token, m.Token) || strings.Contains(m.Token, newMatch.Token) {
				return true
			}
		}
		if newMatch.DetectionTier == TierEntropy || m.DetectionTier == TierEntropy {
			if strings.Contains(newMatch.Token, m.Token) || strings.Contains(m.Token, newMatch.Token) {
				return true
			}
		} else if m.Token == newMatch.Token {
			return true
		}
	}
	return false
}

// isAllowed checks if the token matches any of the glob patterns in the allowlist.
func (s *Scanner) isAllowed(token string) bool {
	if len(s.opts.AllowlistPatterns) == 0 {
		return false
	}
	for _, pattern := range s.opts.AllowlistPatterns {
		matched, err := filepath.Match(pattern, token)
		if err == nil && matched {
			return true
		}
		// Also allow exact substring match just in case
		if pattern == token {
			return true
		}
	}
	return false
}

// fmtVerbRE matches printf-style format verbs so they can be rejected as tokens.
var fmtVerbRE = regexp.MustCompile(`^%[+\-# 0-9]*[vTtbcdoOqxXUeEfFgGsSpw]`)

// isLogIndicator checks if a line clearly indicates structured log/trace output.
// Replaces the extremely slow case-insensitive regex.
func isLogIndicator(line []byte) bool {
	// Fast-path: look for known substrings manually in a case-insensitive way
	// "bearer ", "token: ", "auth: ", "authorization: "
	for i := 0; i < len(line)-5; i++ {
		// Quick check for the first character of each word (b, t, a)
		c := line[i] | 0x20 // lowercase ascii
		if c == 'b' && i+7 <= len(line) {
			if (line[i+1]|0x20) == 'e' && (line[i+2]|0x20) == 'a' && (line[i+3]|0x20) == 'r' && (line[i+4]|0x20) == 'e' && (line[i+5]|0x20) == 'r' && (line[i+6] == ' ' || line[i+6] == '\t') {
				// Word boundary check
				if i == 0 || !isAlphaNum(line[i-1]) {
					return true
				}
			}
		} else if c == 't' && i+7 <= len(line) {
			if (line[i+1]|0x20) == 'o' && (line[i+2]|0x20) == 'k' && (line[i+3]|0x20) == 'e' && (line[i+4]|0x20) == 'n' && line[i+5] == ':' && (line[i+6] == ' ' || line[i+6] == '\t') {
				if i == 0 || !isAlphaNum(line[i-1]) {
					return true
				}
			}
		} else if c == 'a' && i+6 <= len(line) {
			if (line[i+1]|0x20) == 'u' && (line[i+2]|0x20) == 't' && (line[i+3]|0x20) == 'h' && line[i+4] == ':' && (line[i+5] == ' ' || line[i+5] == '\t') {
				if i == 0 || !isAlphaNum(line[i-1]) {
					return true
				}
			}
			// authorization:
			if i+15 <= len(line) {
				if (line[i+1]|0x20) == 'u' && (line[i+2]|0x20) == 't' && (line[i+3]|0x20) == 'h' &&
					(line[i+4]|0x20) == 'o' && (line[i+5]|0x20) == 'r' && (line[i+6]|0x20) == 'i' &&
					(line[i+7]|0x20) == 'z' && (line[i+8]|0x20) == 'a' && (line[i+9]|0x20) == 't' &&
					(line[i+10]|0x20) == 'i' && (line[i+11]|0x20) == 'o' && (line[i+12]|0x20) == 'n' &&
					line[i+13] == ':' && (line[i+14] == ' ' || line[i+14] == '\t') {
					if i == 0 || !isAlphaNum(line[i-1]) {
						return true
					}
				}
			}
		}
	}
	return false
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

var (
	sentinelIgnoreBytes = []byte("sentinel:ignore")
	prefixSlash         = []byte("//")
	prefixHash          = []byte("#")
	prefixBlock         = []byte("/*")
	prefixHtml          = []byte("<!--")
)

// b64Pool caches reusable Base64 decoding buffers to minimize GC pressure during hot paths.
var b64Pool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 3072)
		return &buf
	},
}

// ScanContent runs the full three-tier pipeline against the given raw content
// and returns all confirmed Findings.
//
// filePath is used only for Tier 3 context decisions (test-file suppression).
func (s *Scanner) ScanContent(filePath string, content []byte) []Finding {
	// Fast-path: skip files that are known to never contain production secrets.
	if isKnownSafeFile(filePath) {
		return nil
	}
	var findings []Finding
	isSource := isSourceCodeFile(filePath)
	ext := strings.ToLower(filepath.Ext(filePath))
	isNetrc := filepath.Base(filePath) == ".netrc"
	isEntropyExcluded := ext == ".pem" || ext == ".rsa" || ext == ".crt" || ext == ".pub" ||
		ext == ".json" || ext == ".nix" || ext == ".lock" || ext == ".sum" ||
		ext == ".xml" || ext == ".html" || ext == ".md" || ext == ".txt" ||
		ext == ".log" || ext == ".sql" || ext == ".yaml" || ext == ".yml" ||
		ext == ".toml" || ext == ".gradle" || ext == ".kts" || ext == ".cmake" ||
		ext == ".patch" || ext == ".diff" || ext == ".plist" || ext == ".editorconfig" ||
		strings.Contains(filePath, "package-lock.json") ||
		strings.Contains(filePath, "yarn.lock") ||
		strings.Contains(filePath, "pnpm-lock.yaml")

	// Retrieve a reusable decoding buffer from the pool
	decBufPtr := b64Pool.Get().(*[]byte)
	decBuf := *decBufPtr
	defer b64Pool.Put(decBufPtr)

	// We don't need a global map anymore since we process line by line.
	lineNum := 0
	start := 0
	skipNextLine := false
	var prevLineTrim []byte // track the previous trimmed line for multiline macro context
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

		// ── Speed: skip extremely long lines (data-URLs, minified JS, base64 blobs)
		// Lines > 4096 bytes cannot realistically contain a typed secret token.
		if len(lineTrim) > 4096 {
			continue
		}

		// ── Inline Suppression (sentinel:ignore) ──────────────────────────────
		if skipNextLine {
			skipNextLine = false
			continue
		}
		if bytes.Contains(lineTrim, sentinelIgnoreBytes) {
			if bytes.HasPrefix(lineTrim, prefixSlash) || bytes.HasPrefix(lineTrim, prefixHash) || bytes.HasPrefix(lineTrim, prefixBlock) || bytes.HasPrefix(lineTrim, prefixHtml) {
				skipNextLine = true
			}
			continue
		}

		// ── Skip code comment lines (// and #) but NOT log/data lines ─────────
		// Log lines start with digits (timestamps) or letters. Only skip lines
		// that are clearly source-code comments (start with // or #).
		// Do NOT skip lines starting with digits — those are log timestamps.
		isCodeComment := bytes.HasPrefix(lineTrim, prefixSlash) || bytes.HasPrefix(lineTrim, prefixHash)
		if isCodeComment {
			if bytes.HasPrefix(lineTrim, prefixSlash) {
				lineTrim = bytes.TrimSpace(bytes.TrimPrefix(lineTrim, prefixSlash))
			} else if bytes.HasPrefix(lineTrim, prefixHash) {
				lineTrim = bytes.TrimSpace(bytes.TrimPrefix(lineTrim, prefixHash))
			}
			// We strip the comment prefix and let the pipeline process the inner content.
			// Tier 3's SafeComment classification will properly suppress it if needed,
			// which is the architecturally correct approach for handling comments.
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

		val, isAssignment := extractSecretValue(lineTrim)
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
			// Space counts of 11, 14, 17, 20, and 23 correspond strictly to
			// 12, 15, 18, 21, and 24-word BIP-39 crypto wallet recovery phrases.
			if spaceCount == 11 || spaceCount == 14 || spaceCount == 17 || spaceCount == 20 || spaceCount == 23 {
				if isStrictBip39Mnemonic(string(targetStr)) {
					if !s.opts.DisableContext && sentinelcontext.IsTestFilePath(filePath) {
						continue
					}
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
			hasMatches := len(matches) > 0
			for _, m := range matches {
				// Whole-word boundary check: skip matches embedded inside a larger
				// alphanumeric identifier (e.g. "tcf_exts_for_each_action" triggering
				// the cloudflare cf_ rule). Applied to ALL rules, not just generic-.
				{
					startIdx := m.Offset - len(m.Sig.Prefix) + 1
					if startIdx > 0 {
						prevChar := lineTrim[startIdx-1]
						if (prevChar >= 'a' && prevChar <= 'z') || (prevChar >= 'A' && prevChar <= 'Z') || (prevChar >= '0' && prevChar <= '9') || prevChar == '_' {
							continue
						}
					}
				}
				token := extractTokenFromOffset(lineTrim, m.Sig, m.Offset, isSource, isNetrc)
				if token == "" {
					continue
				}

				if !isPlausibleSecretToken(token, m.Sig.Prefix, m.Sig.ID, s.opts.MinSecretLength) {
					continue
				}
				if m.Sig.Validator != nil && !m.Sig.Validator.MatchString(token) {
					continue
				}
				if len(token) > 0 && token[0] == '%' && fmtVerbRE.MatchString(token) {
					continue
				}
				decision := sentinelcontext.Real
				if !s.opts.DisableContext {
					decision = sentinelcontext.Classify(filePath, string(rawLine), token, m.Sig.ID)
					if decision == sentinelcontext.Real {
						decision = sentinelcontext.ClassifyWithPrev(filePath, string(rawLine), string(prevLineTrim), token, m.Sig.ID)
					}
				}
				if decision == sentinelcontext.Real {
					if s.isAllowed(token) {
						continue
					}
					newMatch := Finding{
						FilePath:      filePath,
						Line:          lineNum,
						LineContent:   string(rawLine),
						Token:         cleanToken(token),
						Entropy:       entropy.Shannon([]byte(token)),
						DetectionTier: TierTrie,
						SignatureID:   m.Sig.ID,
						Description:   m.Sig.Description,
						Severity:      m.Sig.Severity,
					}
					if s.isDuplicateMatch(findings, newMatch) {
						replaced := false
						for idx, existing := range findings {
							if existing.Line == newMatch.Line {
								if severityWeight(newMatch.Severity) > severityWeight(existing.Severity) {
									findings[idx] = newMatch
									replaced = true
									break
								}
								if severityWeight(newMatch.Severity) == severityWeight(existing.Severity) && len(newMatch.Token) < len(existing.Token) {
									findings[idx] = newMatch
									replaced = true
									break
								}
								replaced = true
								break
							}
							if existing.Token == newMatch.Token && strings.HasPrefix(existing.SignatureID, "generic-") && !strings.HasPrefix(newMatch.SignatureID, "generic-") {
								findings[idx].SignatureID = newMatch.SignatureID
								findings[idx].Description = newMatch.Description
								findings[idx].Severity = newMatch.Severity
								replaced = true
								break
							}
							if (existing.DetectionTier == TierEntropy || strings.HasPrefix(existing.SignatureID, "high-entropy-")) && newMatch.DetectionTier == TierTrie {
								findings[idx] = newMatch
								replaced = true
								break
							}
						}
						if !replaced {
							continue
						}
					} else {
						findings = append(findings, newMatch)
					}
				}
			}

			// Process compMatches if needed
			if !hasMatches && cLen > 0 && cLen < vLen {
				compMatches := s.automaton.Search(compVal)
				for _, m := range compMatches {
					{
						startIdx := m.Offset - len(m.Sig.Prefix) + 1
						if startIdx > 0 {
							prevChar := compVal[startIdx-1]
							if (prevChar >= 'a' && prevChar <= 'z') || (prevChar >= 'A' && prevChar <= 'Z') || (prevChar >= '0' && prevChar <= '9') || prevChar == '_' {
								continue
							}
						}
					}
					token := extractTokenFromOffset(compVal, m.Sig, m.Offset, isSource, isNetrc)
					if token == "" {
						continue
					}

					if !isPlausibleSecretToken(token, m.Sig.Prefix, m.Sig.ID, s.opts.MinSecretLength) {
						continue
					}
					if m.Sig.Validator != nil && !m.Sig.Validator.MatchString(token) {
						continue
					}
					if len(token) > 0 && token[0] == '%' && fmtVerbRE.MatchString(token) {
						continue
					}
					if s.isAllowed(token) {
						continue
					}
					decision := sentinelcontext.Real
					if !s.opts.DisableContext {
						decision = sentinelcontext.Classify(filePath, string(rawLine), token, m.Sig.ID)
					}
					if decision == sentinelcontext.Real {
						newMatch := Finding{
							FilePath:      filePath,
							Line:          lineNum,
							LineContent:   string(rawLine),
							Token:         cleanToken(token),
							Entropy:       entropy.Shannon([]byte(token)),
							DetectionTier: TierTrie,
							SignatureID:   m.Sig.ID,
							Description:   m.Sig.Description,
							Severity:      m.Sig.Severity,
						}
						if s.isDuplicateMatch(findings, newMatch) {
							continue
						}
						findings = append(findings, newMatch)
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
				var decodedVal []byte
				var err error
				n := 0
				if decLen <= len(decBuf) {
					n, err = base64.StdEncoding.Decode(decBuf, compVal)
					if err == nil {
						decodedVal = decBuf[:n]
					}
				} else {
					tempBuf := make([]byte, decLen)
					n, err = base64.StdEncoding.Decode(tempBuf, compVal)
					if err == nil {
						decodedVal = tempBuf[:n]
					}
				}
				if err == nil {
					if !s.opts.DisableTrie && s.automaton != nil {
						decMatches := s.automaton.Search(decodedVal)
						for _, m := range decMatches {
							{
								startIdx := m.Offset - len(m.Sig.Prefix) + 1
								if startIdx > 0 {
									prevChar := decodedVal[startIdx-1]
									if (prevChar >= 'a' && prevChar <= 'z') || (prevChar >= 'A' && prevChar <= 'Z') || (prevChar >= '0' && prevChar <= '9') || prevChar == '_' {
										continue
									}
								}
							}
							token := extractTokenFromOffset(decodedVal, m.Sig, m.Offset, isSource, isNetrc)
							if token == "" {
								continue
							}
							if !isPlausibleSecretToken(token, m.Sig.Prefix, m.Sig.ID, s.opts.MinSecretLength) {
								continue
							}
							if m.Sig.Validator != nil && !m.Sig.Validator.MatchString(token) {
								continue
							}
							if len(token) > 0 && token[0] == '%' && fmtVerbRE.MatchString(token) {
								continue
							}
							if s.isAllowed(token) {
								continue
							}
							decision := sentinelcontext.Real
							if !s.opts.DisableContext {
								decision = sentinelcontext.Classify(filePath, string(rawLine), token, m.Sig.ID)
							}
							if decision == sentinelcontext.Real {
								newMatch := Finding{
									FilePath:      filePath,
									Line:          lineNum,
									LineContent:   string(rawLine),
									Token:         cleanToken(token),
									Entropy:       entropy.Shannon([]byte(token)),
									DetectionTier: TierTrie,
									SignatureID:   m.Sig.ID,
									Description:   m.Sig.Description + " (Base64 Decoded)",
									Severity:      m.Sig.Severity,
								}
								if s.isDuplicateMatch(findings, newMatch) {
									continue
								}
								findings = append(findings, newMatch)
							}
						}
					}
				}
			}
		}

		// isEntropyExcluded is now pre-calculated at the file level

		if !s.opts.DisableEntropy && !isEntropyExcluded {
			// Entropy tier runs when the value has no spaces (looks like a single
			// dense token)
			if !hasSpace {
				if cLen >= s.opts.MinSecretLength {
					hits := entropy.Analyze(compVal, s.opts.EntropyThreshold, s.opts.MinSecretLength)
					for _, h := range hits {
						if s.isAllowed(h.Token) {
							continue
						}
						if !isPlausibleSecretToken(h.Token, "", "high-entropy-"+h.Kind, s.opts.MinSecretLength) {
							continue
						}
						// In source code files with no assignment context, base64 entropy hits
						// almost always come from type names, byte-sequence docs, or generated
						// constants — not real secrets. Require an actual assignment (val != nil).
						if isSource && !isAssignment && h.Kind == "base64" {
							continue
						}
						decision := sentinelcontext.Real
						if !s.opts.DisableContext {
							decision = sentinelcontext.Classify(filePath, string(rawLine), h.Token, h.Kind)
							if decision == sentinelcontext.Real {
								decision = sentinelcontext.ClassifyWithPrev(filePath, string(rawLine), string(prevLineTrim), h.Token, h.Kind)
							}
						}
						if decision == sentinelcontext.Real {
							idx := strings.Index(string(rawLine), h.Token)
							if idx > 0 && rawLine[idx-1] == '@' {
								continue
							}
							// Skip SHA-256 / OCI container digest lines (e.g. sha256:<hex>)
							if h.Kind == "hex" && strings.Contains(string(rawLine), "sha256:") {
								continue
							}
							// Skip hashes of length 40 or 64 that appear in code/configuration lines
							// containing metadata keywords (e.g. git commit SHAs, file checksums).
							if h.Kind == "hex" && (len(h.Token) == 40 || len(h.Token) == 64) {
								rl := strings.ToLower(string(rawLine))
								if strings.Contains(rl, "hash") || strings.Contains(rl, "sha") ||
									strings.Contains(rl, "digest") || strings.Contains(rl, "commit") ||
									strings.Contains(rl, "parent") || strings.Contains(rl, "rev") ||
									strings.Contains(rl, "fingerprint") || strings.Contains(rl, "checksum") ||
									strings.Contains(rl, "manifest") {
									continue
								}
							}
							// Skip OAuth client IDs / App IDs from being flagged as hex entropy secrets.
							if h.Kind == "hex" {
								rl := strings.ToLower(string(rawLine))
								if strings.Contains(rl, "client_id") || strings.Contains(rl, "client-id") ||
									strings.Contains(rl, "clientid") || strings.Contains(rl, "appid") ||
									strings.Contains(rl, "app_id") {
									continue
								}
							}
							// Skip checksum verification lines in Dockerfiles/shell scripts
							// (e.g. "echo '<hash>  file' | sha256sum -c" or "--sha256 <hash>")
							if h.Kind == "hex" {
								rl := strings.ToLower(string(rawLine))
								if strings.Contains(rl, "sha256sum") || strings.Contains(rl, "sha512sum") ||
									strings.Contains(rl, "--sha256") || strings.Contains(rl, "--checksum") ||
									strings.Contains(rl, "checksum:") || strings.Contains(rl, "integrity:") {
									continue
								}
							}
							// Skip explicit programmatic hex decode constants (e.g. hex.DecodeString("..."))
							if h.Kind == "hex" && (strings.Contains(string(rawLine), "hex.DecodeString(") || strings.Contains(string(rawLine), "hex.Decode(")) {
								continue
							}
							// Skip base64 tokens containing dots: real base64 never includes dots,
							// but Go/C qualified names like ssa.OpARM64LoweredAtomicExchange32 do.
							if h.Kind == "base64" && strings.ContainsRune(h.Token, '.') {
								continue
							}
							// Skip CamelCase identifiers (Go/Java type/method names).
							// Requires BOTH uppercase letters AND 4+ consecutive lowercase:
							// pure-lowercase secrets (e.g. "supersecretpassword") are preserved.
							if h.Kind == "base64" {
								// Only apply CamelCase class/method checks to tokens that are
								// pure identifiers (contain only letters, dots, and underscores).
								// If the token contains digits, +, /, or =, it is highly likely
								// to be a real base64 secret rather than a code identifier.
								isPureIdent := true
								for _, c := range h.Token {
									if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '_') {
										isPureIdent = false
										break
									}
								}
								if isPureIdent {
									hasUpper := false
									for _, c := range h.Token {
										if c >= 'A' && c <= 'Z' {
											hasUpper = true
											break
										}
									}
									if hasUpper {
										maxLower, cur := 0, 0
										for _, c := range h.Token {
											if c >= 'a' && c <= 'z' {
												cur++
												if cur > maxLower {
													maxLower = cur
												}
											} else {
												cur = 0
											}
										}
										if maxLower >= 4 {
											continue
										}
									}
								}
							}
							// Skip pure-decimal integer constants (e.g. math.MaxUint = 18446744073709551615)
							if h.Kind == "hex" {
								onlyDecimal := true
								for _, c := range h.Token {
									if c < '0' || c > '9' {
										onlyDecimal = false
										break
									}
								}
								if onlyDecimal {
									continue
								}
							}
							// Skip Linux kernel sysfs documentation paths (/sys/bus/..., /sys/class/...)
							if strings.HasPrefix(string(compVal), "/sys/") {
								continue
							}
							// Skip JSON schema $ref paths and operationId strings (OpenAPI specs)
							if strings.Contains(string(rawLine), `"$ref":`) || strings.Contains(string(rawLine), `"operationId":`) {
								continue
							}
							// Skip cryptographic signature/digest/checksum/fingerprint JSON fields
							if h.Kind == "hex" {
								ll := strings.ToLower(string(rawLine))
								if strings.Contains(ll, `"signature":`) || strings.Contains(ll, `"digest":`) ||
									strings.Contains(ll, `"checksum":`) || strings.Contains(ll, `"fingerprint":`) {
									continue
								}
							}
							newMatch := Finding{
								FilePath:      filePath,
								Line:          lineNum,
								LineContent:   string(rawLine),
								Token:         cleanToken(h.Token), // sentinel:ignore
								Entropy:       h.Entropy,
								DetectionTier: TierEntropy,
								SignatureID:   fmt.Sprintf("high-entropy-%s", h.Kind),
								Description:   fmt.Sprintf("High-entropy %s string (entropy=%.2f)", strings.ToUpper(h.Kind), h.Entropy),
								Severity:      entropySeverity(h.Entropy),
							}
							if s.isDuplicateMatch(findings, newMatch) {
								continue
							}
							findings = append(findings, newMatch)
						}
					}
				}
			}
		}

		// ── Log-line heuristic: Bearer / Token: / auth: indicators ────────────
		// For lines that look like structured log output with an explicit auth
		// keyword, run entropy on each whitespace-delimited token. This catches
		// Base64-encoded credentials in log files without relaxing the global parser.
		if !s.opts.DisableEntropy && isLogIndicator(lineTrim) {
			startTok := 0
			for i := 0; i <= len(lineTrim); i++ {
				if i == len(lineTrim) || lineTrim[i] == ' ' || lineTrim[i] == '\t' || lineTrim[i] == '\n' || lineTrim[i] == '\r' {
					if i > startTok {
						tok := lineTrim[startTok:i]
						if len(tok) >= s.opts.MinSecretLength {
							tokStr := cleanTokenBytes(tok)
							if len(tokStr) >= s.opts.MinSecretLength {
								hits := entropy.Analyze(tokStr, 4.0, s.opts.MinSecretLength)
								for _, h := range hits {
									if s.isAllowed(h.Token) {
										continue
									}
									decision := sentinelcontext.Real
									if !s.opts.DisableContext {
										decision = sentinelcontext.Classify(filePath, string(rawLine), h.Token, h.Kind)
									}
									if decision == sentinelcontext.Real {
										newMatch := Finding{
											FilePath:      filePath,
											Line:          lineNum,
											LineContent:   string(rawLine),
											Token:         cleanToken(h.Token), // sentinel:ignore
											Entropy:       h.Entropy,
											DetectionTier: TierEntropy,
											SignatureID:   fmt.Sprintf("log-high-entropy-%s", h.Kind),
											Description:   fmt.Sprintf("High-entropy %s in log auth context (entropy=%.2f)", strings.ToUpper(h.Kind), h.Entropy),
											Severity:      entropySeverity(h.Entropy),
										}
										if !s.isDuplicateMatch(findings, newMatch) {
											findings = append(findings, newMatch)
										}
									}
								}
							}
						}
					}
					startTok = i + 1
				}
			}
		}
		// Update prevLineTrim for the next iteration (multiline macro context)
		prevLineTrim = append(prevLineTrim[:0], lineTrim...)
	}

	// ── Apply Allowlist Patterns ────────────────────────────────────────────
	if len(s.opts.AllowlistPatterns) > 0 {
		filtered := findings[:0]
		for _, f := range findings {
			allowed := false
			for _, pat := range s.opts.AllowlistPatterns {
				if matched, err := filepath.Match(pat, f.Token); (err == nil && matched) || f.Token == pat {
					allowed = true
					break
				}
			}
			if !allowed {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
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

// isKnownSafeFile returns true for file types that are architecturally
// incapable of containing production secrets. These include security-tool
// suppression configs, generated code, and package documentation.
func isKnownSafeFile(filePath string) bool {
	base := strings.ToLower(filepath.Base(filePath))
	ext := strings.ToLower(filepath.Ext(filePath))

	// Microsoft Guardian / security scanner suppression files.
	// They contain SHA-256 hashes of known FPs, not secrets.
	if ext == ".gdnsuppress" || ext == ".snyk" {
		return true
	}
	// Go package-level documentation files: contain instruction encoding
	// tables and CPU register examples in hex, never production secrets.
	if base == "doc.go" {
		return true
	}
	// Protocol Buffer generated code — machine-written, no human secrets.
	if strings.HasSuffix(base, ".pb.go") || strings.HasSuffix(base, ".pb.gw.go") {
		return true
	}
	// Controller-runtime / Kubernetes code-gen output.
	if strings.HasPrefix(base, "zz_generated") {
		return true
	}
	// Microsoft Component Governance manifests contain only SHA512 package hashes.
	if base == "cgmanifest.json" {
		return true
	}
	// Git blame suppression files contain only commit SHA hashes, never secrets.
	if base == ".git-blame-ignore-revs" {
		return true
	}
	// product.json and similar build manifests with reproducibility hashes.
	if base == "product.json" {
		return true
	}
	// Terraform lock files contain only provider binary hashes.
	if base == ".terraform.lock.hcl" {
		return true
	}
	return false
}

// HasExcludedExtension returns true when the file's extension is in the
// excluded list.
func HasExcludedExtension(filePath string, excluded []string) bool {
	ext := filepath.Ext(filePath)
	for _, e := range excluded {
		if strings.EqualFold(e, ext) {
			return true
		}
	}
	return false
}

// MatchesExcludePath returns true when filePath matches any of the given glob
// patterns.
func MatchesExcludePath(filePath string, patterns []string) bool {
	base := filepath.Base(filePath)
	for _, pattern := range patterns {
		if !strings.ContainsRune(pattern, '/') && !strings.ContainsRune(pattern, '\\') {
			matched, err := filepath.Match(pattern, base)
			if err == nil && matched {
				return true
			}
		}
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
	filePath = strings.ReplaceAll(filePath, "\\", "/")
	pattern = strings.ReplaceAll(pattern, "\\", "/")

	trimmedPattern := strings.TrimSuffix(pattern, "/**")
	trimmedPattern = strings.TrimSuffix(trimmedPattern, "/*")
	trimmedPattern = strings.TrimPrefix(trimmedPattern, "**/")

	patternSegs := strings.Split(trimmedPattern, "/")
	fileSegs := strings.Split(filePath, "/")

	if len(patternSegs) == 0 || len(fileSegs) == 0 || patternSegs[0] == "" {
		return false
	}

	for i := 0; i <= len(fileSegs)-len(patternSegs); i++ {
		match := true
		for j := 0; j < len(patternSegs); j++ {
			matched, err := filepath.Match(patternSegs[j], fileSegs[i+j])
			if err != nil || !matched {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
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
	// ── Assignment branch ─────────────────────────────────────────────────────
	// Detect ":=" (Go) or "=" (shell/env/YAML/generic) assignment operators.
	// We must be careful not to trigger on "==" (comparison) or inside quotes.
	rhsStr, ok := extractRHS(lineTrim)
	if ok {
		// From the RHS, prefer the first quoted literal. If none, take the first
		// whitespace-delimited token (could be a bare value like an API key).
		quoted := firstQuotedLiteral(rhsStr)
		if len(quoted) > 0 {
			return quoted, true
		}
		// Bare token: find the first whitespace to isolate the first word
		endIdx := -1
		for i, b := range rhsStr {
			if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
				endIdx = i
				break
			}
		}
		var firstWord []byte
		if endIdx == -1 {
			firstWord = rhsStr
		} else {
			firstWord = rhsStr[:endIdx]
		}

		if len(firstWord) > 0 {
			bare := bytes.TrimRight(firstWord, `"'`+"`,;)")
			if len(bare) > 0 {
				return bare, true
			}
		}
		return nil, true
	}

	// ── Quoted-literal branch (non-assignment lines) ───────────────────────────
	// Only scan what is inside quoted strings on the line. Never the raw tokens
	// like variable names or format verbs outside quotes.
	quoted := allQuotedLiterals(lineTrim)
	if len(quoted) == 0 {
		return nil, false
	}
	return quoted, false
}

var (
	opColonEqual = []byte(":=")
	opColon      = []byte(":")
	urlProto     = []byte("//")
)

// extractRHS detects an assignment operator on the line and returns the RHS.
// It returns ("", false) if no assignment is present.
// It correctly handles:
//   - ":="  Go short variable declaration
//   - "="   shell / env / YAML / generic (but not "==" or "!=")
//   - ":"   YAML key: value (but only when "=" is absent)
func extractRHS(line []byte) ([]byte, bool) {
	// :=  — highest priority (Go)
	if idx := bytes.Index(line, opColonEqual); idx >= 0 {
		return bytes.TrimSpace(line[idx+2:]), true
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
			if i+1 >= len(line) {
				return nil, false
			}
			return bytes.TrimSpace(line[i+1:]), true
		}
	}

	// : YAML-style — only if there is no = on the line at all.
	if idx := bytes.Index(line, opColon); idx >= 0 {
		// Make sure it is not inside a quoted string or URL (://).
		after := bytes.TrimSpace(line[idx+1:])
		if bytes.HasPrefix(after, urlProto) {
			return nil, false // URL protocol like https://
		}
		return after, true
	}

	return nil, false
}

// firstQuotedLiteral returns the content of the first quoted string (using
// double-quote, single-quote, or backtick delimiters) found in s.
func firstQuotedLiteral(s []byte) []byte {
	inQuote := false
	var quoteChar byte
	var start int
	for i := 0; i < len(s); i++ {
		b := s[i]
		if inQuote {
			if b == quoteChar && (i == 0 || s[i-1] != '\\') {
				return s[start:i]
			}
		} else if b == '"' || b == '\'' || b == '`' {
			inQuote = true
			quoteChar = b
			start = i + 1
		}
	}
	return nil
}

// allQuotedLiterals returns the concatenated content of every quoted string
// literal found in s, separated by spaces.  Used for non-assignment lines
// where we want to scan only what is inside string literals.
func allQuotedLiterals(s []byte) []byte {
	var partsBuf [8][]byte
	parts := partsBuf[:0]
	inQuote := false
	var quoteChar byte
	var start int
	for i := 0; i < len(s); i++ {
		b := s[i]
		if inQuote {
			if b == quoteChar && (i == 0 || s[i-1] != '\\') {
				inQuote = false
				if i > start {
					parts = append(parts, s[start:i])
				}
			}
		} else if b == '"' || b == '\'' || b == '`' {
			inQuote = true
			quoteChar = b
			start = i + 1
		}
	}
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return bytes.Join(parts, []byte(" "))
}

func extractTokenFromOffset(val []byte, sig *trie.Signature, offset int, isSourceFile bool, isNetrc bool) string {
	prefix := sig.Prefix
	start := offset - len(prefix) + 1
	if start < 0 || offset >= len(val) {
		return ""
	}

	var after []byte
	if sig.IsAssignmentOrKeyword {
		after = bytes.TrimSpace(val[offset+1:])
	} else {
		after = bytes.TrimSpace(val[start:])
	}

	// If it is a generic keyword assignment in a source file, the value must be quoted.
	// That is, the first non-whitespace character after the assignment operator (= or :) must be a quote.
	if sig.IsAssignmentOrKeyword && isSourceFile && strings.HasPrefix(sig.ID, "generic-") {
		idx := bytes.IndexAny(after, "=:")
		if idx != -1 && idx+1 < len(after) {
			trimmed := bytes.TrimLeft(after[idx+1:], " \t\r\n")
			if len(trimmed) > 0 {
				firstChar := trimmed[0]
				if firstChar != '"' && firstChar != '\'' && firstChar != '`' {
					return "" // Not a quoted string literal in a source file!
				}
			} else {
				return ""
			}
		} else {
			return ""
		}
	}

	// Strict bypass for PEM headers (don't break on spaces, keep dashes)
	if bytes.HasPrefix(after, []byte("-----BEGIN ")) {
		endIdx := bytes.Index(after[11:], []byte("-----"))
		if endIdx != -1 {
			return string(after[:11+endIdx+5])
		}
		return string(after) // fallback
	}

	after = bytes.TrimLeft(after, "\"'`=: ,() \t\n\r")

	// Early return for GitHub Actions / Jinja / Helm expressions like ${{...}} or {{...}}
	// These must pass intact to the context classifier to be recognized as safe placeholders.
	if bytes.HasPrefix(after, []byte("${{")) {
		end := bytes.Index(after, []byte("}}"))
		if end != -1 {
			return string(after[:end+2])
		}
		return string(after)
	}
	if bytes.HasPrefix(after, []byte("{{")) {
		end := bytes.Index(after, []byte("}}"))
		if end != -1 {
			return string(after[:end+2])
		}
		return string(after)
	}

	// Truncate at the first closing quote to properly isolate tokens in minified code
	if qIdx := bytes.IndexAny(after, "\"'`"); qIdx > 0 {
		after = after[:qIdx]
	}

	// Optimize: find the end of the first field without allocating a full fields slice via bytes.FieldsFunc
	endIdx := -1
	for i, b := range after {
		isTerm := b == ' ' || b == '\t' || b == '\n' || b == '\r'
		if !strings.Contains(sig.ID, "-dsn") && !strings.Contains(sig.ID, "url-basic-auth") {
			if b == '@' || b == '/' || b == '?' || b == '&' {
				isTerm = true
			}
		}
		if isTerm {
			endIdx = i
			break
		}
	}
	var firstField []byte
	if endIdx == -1 {
		firstField = after
	} else {
		firstField = after[:endIdx]
	}

	if bytes.ContainsAny(firstField, "()") {
		return ""
	}
	cleaned := cleanTokenBytes(firstField)
	if len(cleaned) == 0 {
		return ""
	}
	if strings.HasPrefix(sig.ID, "generic-") && !isNetrc {
		// Generic key must have assignment operator (= or :) between prefix and token.
		idx := bytes.Index(val[offset+1:], cleaned)
		if idx != -1 {
			between := val[offset+1 : offset+1+idx]
			if bytes.IndexByte(between, '=') == -1 && bytes.IndexByte(between, ':') == -1 {
				return ""
			}
		} else {
			return ""
		}
	}
	return string(cleaned)
}

// cleanTokenBytes strips non-alphanumeric characters commonly found trailing or leading
// in code, JSON, and string literals directly on byte slices (no allocation).
func cleanTokenBytes(tok []byte) []byte {
	tok = bytes.TrimSpace(tok)
	return bytes.Trim(tok, "\\\"'`{}[](),;:.<>")
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
func isPlausibleSecretToken(token, prefix, sigID string, minLen int) bool {
	if len(token) > 400 {
		return false
	}
	if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") ||
		strings.HasPrefix(token, "//") || strings.HasPrefix(token, "www.") ||
		strings.HasPrefix(token, "urn:") || strings.HasPrefix(token, "vless://") ||
		strings.HasPrefix(token, "vmess://") || strings.HasPrefix(token, "ss://") ||
		strings.HasPrefix(token, "trojan://") || strings.HasPrefix(token, "shadowsocks://") {
		if !strings.Contains(sigID, "-dsn") && !strings.Contains(sigID, "url-basic-auth") {
			return false
		}
	}
	// Filter out public cryptocurrency wallet addresses (e.g., Ethereum)
	// and Git SHAs, which are exactly 40 characters long (hex)
	if len(token) == 40 && sigID == "high-entropy-hex" {
		return false
	}
	minAllowed := minLen / 2
	if sigID == "generic-password-key" || sigID == "generic-secret-key" {
		minAllowed = 6
	}
	if len(token) < minAllowed {
		return false
	}
	// Stricter checks for generic rules to eliminate variable name/type/expression leaks
	if strings.HasPrefix(sigID, "generic-") {
		if strings.ContainsAny(token, "${}<>()[]*;|&+=\"!? ") || strings.Contains(token, "::") || strings.Contains(token, "->") {
			return false
		}
		// If it's a property path (contains dot) and it's from a generic rule, reject it
		if strings.Contains(token, ".") {
			return false
		}
		// If a generic API/Secret token consists ONLY of letters (no digits), it's overwhelmingly
		// likely to be a CamelCase/PascalCase variable or class name (e.g. DisjointLeibnizSet), not a real token.
		// We exempt passwords since users often use pure alphabetical words as passwords.
		if !strings.Contains(sigID, "password") {
			isOnlyLetters := true
			for _, r := range token {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
					isOnlyLetters = false
					break
				}
			}
			if isOnlyLetters {
				return false
			}
		}
	}

	// Reject all-uppercase snake_case constants (e.g. CALIBRATION_PROMPTS_FILE)
	// for generic rules and generic entropy rules (hex, base64, high-entropy).
	if strings.HasPrefix(sigID, "generic-") || sigID == "hex" || sigID == "base64" || strings.Contains(sigID, "high-entropy") {
		isAllCapsConstant := true
		hasLetter := false
		for _, r := range token {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				hasLetter = true
			}
			if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
				isAllCapsConstant = false
				break
			}
		}
		if isAllCapsConstant && hasLetter {
			return false
		}
	}
	// Reject function-call expressions (contain parentheses).
	// Real secrets never contain ( or ) — these are code identifiers or calls.
	if strings.ContainsAny(token, "()") {
		return false
	}
	// Reject Rust/C++ path expressions containing the :: separator.
	if strings.Contains(token, "::") {
		return false
	}
	// Reject TextMate grammar scope names: all-lowercase dotted words like
	// "entity.name.type.class" found in editor theme definitions.
	// Real secrets always contain uppercase letters, digits, or special chars.
	if strings.Contains(token, ".") {
		isGrammarScope := true
		for _, r := range token {
			if !((r >= 'a' && r <= 'z') || r == '.' || r == '-') {
				isGrammarScope = false
				break
			}
		}
		if isGrammarScope {
			return false
		}
	}
	// Reject tokens that contain obvious regex syntax (False Positive reduction)
	if strings.Contains(token, "[") && strings.Contains(token, "]") {
		return false
	}
	if strings.Contains(token, "{") && strings.Contains(token, "}") {
		return false
	}
	if strings.Contains(token, "(?:") || strings.Contains(token, ".*") {
		return false
	}
	// Reject tokens that are identical to their prefix (no secret material attached).
	// This prevents false positives on regex signatures or empty mock strings.
	if token == prefix {
		return false
	}
	// Removed bare PEM header rejection because the test expects it and it's needed for single-line matching.
	// For short prefixes, apply stricter checks.
	if len(prefix) > 0 && len(prefix) <= 3 {
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
// This mitigates alert fatigue by squashing multi-line high-entropy strings
// (like JKS keystores or PEM certs) into a single CRITICAL finding.
func aggregateBlobs(findings []Finding) []Finding {
	if len(findings) < 3 {
		return findings
	}
	var result []Finding
	var currentBlob []Finding

	flushBlob := func() {
		if len(currentBlob) >= 3 {
			first := currentBlob[0]
			kind := "Base64"
			if strings.Contains(first.SignatureID, "hex") {
				kind = "Hex"
			}
			result = append(result, Finding{
				FilePath:      first.FilePath,
				Line:          first.Line,
				LineContent:   fmt.Sprintf("[... %d consecutive lines of %s ...]", len(currentBlob), kind),
				Token:         fmt.Sprintf("<%d lines aggregated>", len(currentBlob)),
				Entropy:       first.Entropy,
				DetectionTier: TierTrie,
				SignatureID:   fmt.Sprintf("massive-%s-blob", strings.ToLower(kind)),
				Description:   fmt.Sprintf("Massive %s/Cryptographic Blob Detected (Potential Keystore/Vault)", kind),
				Severity:      "CRITICAL",
			})
		} else {
			result = append(result, currentBlob...)
		}
		currentBlob = nil
	}

	for _, f := range findings {
		if f.SignatureID == "high-entropy-base64" || f.SignatureID == "high-entropy-hex" {
			if len(currentBlob) == 0 {
				currentBlob = append(currentBlob, f)
			} else {
				lastLine := currentBlob[len(currentBlob)-1].Line
				if (f.Line == lastLine+1 || f.Line == lastLine) && f.SignatureID == currentBlob[0].SignatureID {
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

// isSourceCodeFile returns true if the filePath has an extension of a programming language source file.
func isSourceCodeFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".go", ".rb", ".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".scala", ".kt", ".c", ".cpp", ".h", ".cs", ".php", ".pl", ".sh", ".bash", ".zsh":
		return true
	}
	return false
}

func severityWeight(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
