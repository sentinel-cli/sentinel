// Package entropy implements Tier 2 of the Sentinel detection pipeline:
// Shannon entropy analysis for detecting high-randomness strings that escape
// pattern-based detection (e.g., raw hex or Base64-encoded secrets).
package entropy

import (
	"math"
)

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

	lineNum := 1
	start := 0
	for i := 0; i <= len(content); i++ {
		if i == len(content) || content[i] == '\n' {
			if i > start {
				line := content[start:i]

				// Skip lines that are purely a URL — entire line contains a URL so
				// any extracted token will be a URL segment, not a secret.
				if containsURL(line) {
					if i < len(content) {
						lineNum++
						start = i + 1
					}
					continue
				}

				// Extract and score Base64-alphabet tokens.
				extractTokens(line, base64Set, minLen, func(tok []byte) {
					if isJavaConstant(tok) || isAllSameChar(tok) {
						return
					}
					// If the token is entirely hex, let extractHexTokens handle it with the scaled threshold.
					if isHexLikeBytes(tok) {
						return
					}
					e := Shannon(tok)
					if e >= threshold {
						hits = append(hits, EntropyHit{
							Token:       string(tok),
							Entropy:     e,
							Line:        lineNum,
							LineContent: truncateBytes(line, 512),
							Kind:        "base64",
						})
					}
				})

				extractHexTokens(line, minLen, func(tok []byte) {
					if len(tok)%2 != 0 {
						return
					}
					e := Shannon(tok)
					// Hex has max entropy 4.0 (log2(16)), whereas Base64 has max entropy 6.0.
					// Scale the provided threshold proportionally for hex tokens.
					hexThreshold := threshold * (4.0 / 6.0)
					// But never drop below a sane minimum (e.g., 3.0) to avoid false positives.
					if hexThreshold < 3.0 {
						hexThreshold = 3.0
					}
					if e >= hexThreshold {
						hits = append(hits, EntropyHit{
							Token:       string(tok),
							Entropy:     e,
							Line:        lineNum,
							LineContent: truncateBytes(line, 512),
							Kind:        "hex",
						})
					}
				})
			}
			if i < len(content) {
				lineNum++
				start = i + 1
			}
		}
	}
	return hits
}

func isJavaConstant(tok []byte) bool {
	for _, b := range tok {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '.' || b == '_') {
			return false
		}
	}
	return true
}

// containsURL returns true when the line looks like it's a URL string
// (starts with http, https, or //www) so we can skip entropy scoring entirely.
func containsURL(line []byte) bool {
	for i := 0; i < len(line); i++ {
		if line[i] == 'h' {
			if i+7 <= len(line) && line[i+1] == 't' && line[i+2] == 't' && line[i+3] == 'p' && line[i+4] == ':' && line[i+5] == '/' && line[i+6] == '/' {
				return true
			}
			if i+8 <= len(line) && line[i+1] == 't' && line[i+2] == 't' && line[i+3] == 'p' && line[i+4] == 's' && line[i+5] == ':' && line[i+6] == '/' && line[i+7] == '/' {
				return true
			}
		}
		if line[i] == '/' && i+1 < len(line) && line[i+1] == '/' {
			return true
		}
	}
	return false
}

// extractTokens splits a line by the given character set and returns all
// contiguous runs that are entirely within that character set and meet minLen.
func extractTokens(line []byte, charSet [256]bool, minLen int, cb func([]byte)) {
	start := -1
	for i, b := range line {
		if charSet[b] {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				if i-start >= minLen {
					cb(line[start:i])
				}
				start = -1
			}
		}
	}
	if start != -1 && len(line)-start >= minLen {
		cb(line[start:])
	}
}

// extractHexTokens performs the same extraction specifically for hexadecimal strings.
func extractHexTokens(line []byte, minLen int, cb func([]byte)) {
	start := -1
	for i, b := range line {
		if hexSet[b] {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				if i-start >= minLen {
					cb(line[start:i])
				}
				start = -1
			}
		}
	}
	if start != -1 && len(line)-start >= minLen {
		cb(line[start:])
	}
}

// isAllSameChar returns true if every character in s is identical.  Such
// strings (e.g. "AAAAAAAAAA") have zero entropy and are safe to skip.
func isAllSameChar(s []byte) bool {
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

// truncateBytes caps a byte slice at maxLen bytes and returns a string.
func truncateBytes(s []byte, maxLen int) string {
	if len(s) <= maxLen {
		return string(s)
	}
	return string(s[:maxLen])
}

// IsBase64Like returns true when more than 75% of characters in s are from the
// Base64 alphabet.  Used as a quick pre-filter before full entropy computation.
func IsBase64Like(s string) bool {
	if len(s) == 0 {
		return false
	}
	count := 0
	for i := 0; i < len(s); i++ {
		if base64Set[s[i]] {
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
	for i := 0; i < len(s); i++ {
		if !hexSet[s[i]] {
			return false
		}
	}
	return true
}

// isHexLikeBytes returns true when every byte in s is in the hex alphabet.
// Avoids converting slice to string to prevent heap allocations.
func isHexLikeBytes(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	for _, b := range s {
		if !hexSet[b] {
			return false
		}
	}
	return true
}
