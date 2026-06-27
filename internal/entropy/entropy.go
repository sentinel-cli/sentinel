// Package entropy implements Tier 2 of the Sentinel detection pipeline:
// Shannon entropy analysis for detecting high-randomness strings that escape
// pattern-based detection (e.g., raw hex or Base64-encoded secrets).
package entropy

import (
	"math"
	"regexp"
)

var javaConstantRE = regexp.MustCompile(`^[a-zA-Z\._]+$`)

// ──────────────────────────────────────────────────────────────────────────────
// Character-set classifiers for token extraction
// ──────────────────────────────────────────────────────────────────────────────

// base64Chars is the standard Base64 alphabet (URL-safe variant included).
const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"

// hexChars is the hexadecimal alphabet.
const hexChars = "0123456789abcdefABCDEF"

var (
	base64Set = buildCharSet(base64Chars)
	hexSet    = buildCharSet(hexChars)
)

// buildCharSet returns a 256-element boolean lookup table for O(1) membership
// testing.
func buildCharSet(chars string) [256]bool {
	var table [256]bool
	for _, c := range chars {
		if c < 256 {
			table[c] = true
		}
	}
	return table
}

// ──────────────────────────────────────────────────────────────────────────────
// Shannon entropy calculator
// ──────────────────────────────────────────────────────────────────────────────

// Shannon computes the Shannon entropy (in bits per symbol) of the given byte
// slice.  The result ranges from 0.0 (all bytes identical) to 8.0 (perfectly
// uniform 256-symbol distribution).
func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	n := float64(len(data))
	var h float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// ──────────────────────────────────────────────────────────────────────────────
// Token extraction
// ──────────────────────────────────────────────────────────────────────────────

// EntropyHit records a high-entropy token found on a line.
type EntropyHit struct {
	// Token is the raw string that triggered the entropy check.
	Token string

	// Entropy is the computed Shannon entropy of the token.
	Entropy float64

	// Line is the 1-indexed line number within the scanned content.
	Line int

	// LineContent is the full text of the triggering line (≤512 bytes).
	LineContent string

	// Kind describes the character set: "base64" or "hex".
	Kind string
}

// Analyze scans content line-by-line, extracts candidate tokens from each
// line, and returns all tokens whose Shannon entropy exceeds the threshold and
// whose length is at least minLen.
func Analyze(content []byte, threshold float64, minLen int) []EntropyHit {
	var hits []EntropyHit

	lines := splitLines(content)
	for i, line := range lines {
		lineNum := i + 1
		lineStr := string(line)

		// Extract and score Base64-alphabet tokens.
		for _, tok := range extractTokens(line, base64Set, minLen) {
			if javaConstantRE.MatchString(tok) {
				continue
			}
			e := Shannon([]byte(tok))
			if e >= threshold {
				hits = append(hits, EntropyHit{
					Token:       tok,
					Entropy:     e,
					Line:        lineNum,
					LineContent: truncate(lineStr, 512),
					Kind:        "base64",
				})
			}
		}

		// Extract and score hex-alphabet tokens (must be even length to look
		// like a real hash/key).
		for _, tok := range extractHexTokens(line, minLen) {
			if len(tok)%2 != 0 {
				continue
			}
			if javaConstantRE.MatchString(tok) {
				continue
			}
			e := Shannon([]byte(tok))
			if e >= threshold {
				hits = append(hits, EntropyHit{
					Token:       tok,
					Entropy:     e,
					Line:        lineNum,
					LineContent: truncate(lineStr, 512),
					Kind:        "hex",
				})
			}
		}
	}
	return hits
}

// extractTokens splits a line by the given character set and returns all
// contiguous runs that are entirely within that character set and meet minLen.
func extractTokens(line []byte, charSet [256]bool, minLen int) []string {
	var tokens []string
	start := -1
	for i, b := range line {
		if charSet[b] {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				tok := string(line[start:i])
				if len(tok) >= minLen && !isAllSameChar(tok) {
					tokens = append(tokens, tok)
				}
				start = -1
			}
		}
	}
	if start != -1 {
		tok := string(line[start:])
		if len(tok) >= minLen && !isAllSameChar(tok) {
			tokens = append(tokens, tok)
		}
	}
	return tokens
}

// extractHexTokens is a specialised extractor for lowercase and uppercase hex
// strings.
func extractHexTokens(line []byte, minLen int) []string {
	var tokens []string
	start := -1
	for i, b := range line {
		if hexSet[b] {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				tok := string(line[start:i])
				if len(tok) >= minLen {
					tokens = append(tokens, tok)
				}
				start = -1
			}
		}
	}
	if start != -1 {
		tok := string(line[start:])
		if len(tok) >= minLen {
			tokens = append(tokens, tok)
		}
	}
	return tokens
}

// splitLines splits content on '\n' boundaries.
func splitLines(content []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range content {
		if b == '\n' {
			lines = append(lines, content[start:i])
			start = i + 1
		}
	}
	if start < len(content) {
		lines = append(lines, content[start:])
	}
	return lines
}

// isAllSameChar returns true if every character in s is identical.  Such
// strings (e.g. "AAAAAAAAAA") have zero entropy and are safe to skip.
func isAllSameChar(s string) bool {
	if len(s) == 0 {
		return true
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}



// truncate caps a string at maxLen bytes without breaking multi-byte runes.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// IsBase64Like returns true when more than 75% of characters in s are from the
// Base64 alphabet.  Used as a quick pre-filter before full entropy computation.
func IsBase64Like(s string) bool {
	if len(s) == 0 {
		return false
	}
	count := 0
	for _, b := range []byte(s) {
		if base64Set[b] {
			count++
		}
	}
	return float64(count)/float64(len(s)) >= 0.75
}

// IsHexLike returns true when every character in s is in the hex alphabet.
func IsHexLike(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, b := range []byte(s) {
		if !hexSet[b] {
			return false
		}
	}
	return true
}
