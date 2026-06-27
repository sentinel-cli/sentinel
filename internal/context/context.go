// Package context implements Tier 3 of the Sentinel detection pipeline:
// context-aware filtering that eliminates false positives by inspecting
// the surrounding code structure of a potential secret.
//
// This tier distinguishes between:
//   - Real secrets: live credentials in production code
//   - Safe noise: test fixtures, mock values, commented-out code, example
//     variable names like dummy_key, example_secret, placeholder, etc.
package context

import (
	"regexp"
	"strings"
	"unicode"
)

// ──────────────────────────────────────────────────────────────────────────────
// Safe-context classifiers
// ──────────────────────────────────────────────────────────────────────────────

// safeVariableWords are substrings (case-insensitive) that, when found in the
// *variable name portion* of a line, indicate intentionally fake/test data.
// We intentionally do NOT include words like "key", "token", "secret" here
// because those are normal variable names for real credentials.
var safeVariableWords = []string{
	"dummy", "fake", "mock", "placeholder",
	"sample", "fixture", "stub", "lorem", "foobar",
	"your_", "your-", "insert_", "replace_", "changeme",
	"redacted", "sanitized", "censored",
}

// safeCommentPrefixes are line prefixes (after trimming whitespace) that
// indicate a line is commented out and therefore not live code.
var safeCommentPrefixes = []string{
	"//", "#", "*", "/*", "<!--", "--", ";", "%", "!",
}

// safeFileSegments provides O(1) lookups for directory names indicating safe files.
var safeFileSegments = map[string]bool{
	"test": true, "tests": true, "testdata": true, "fixtures": true,
	"__tests__": true, "__mocks__": true, "mock": true, "mocks": true,
	"sample": true, "samples": true, "docs": true, "doc": true,
}

// safeFileSuffixes are filename substrings that indicate the file is a test or doc.
var safeFileSuffixes = []string{
	"_test.go", "_spec.rb", ".test.js", ".spec.js", ".test.ts", ".spec.ts",
	"readme", ".md", ".rst",
}

// ──────────────────────────────────────────────────────────────────────────────
// Compiled regular expressions
// ──────────────────────────────────────────────────────────────────────────────

var (
	// envVarPlaceholder matches shell/docker environment variable placeholder
	// syntax like ${MY_SECRET} or $MY_SECRET.
	envVarPlaceholder = regexp.MustCompile(`^\$\{?[A-Z_][A-Z0-9_]*\}?$`)

	// configPlaceholder matches common config-file placeholder notations.
	configPlaceholder = regexp.MustCompile(`^<[^>]+>$|^\[\[.+\]\]$|^\{\{.+\}\}$`)

	// uuidPattern matches standard UUID v4 format.
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// versionLike matches version strings that are mistaken for hex secrets.
	versionLike = regexp.MustCompile(`^\d+\.\d+\.\d+`)
)

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

// Decision is the result of the context analysis for a single finding.
type Decision int

const (
	// Real indicates the finding should be reported as a genuine secret.
	Real Decision = iota

	// SafeComment indicates the line is commented out — suppressed.
	SafeComment

	// SafeTestFile indicates the file is a test/fixture — suppressed.
	SafeTestFile

	// SafeVariableName indicates the variable name signals mock data — suppressed.
	SafeVariableName

	// SafePlaceholder indicates the value is an environment variable reference
	// or config-system placeholder — suppressed.
	SafePlaceholder

	// SafeUUID indicates the token matched a UUID pattern — suppressed.
	SafeUUID

	// SafeVersionString indicates the token looks like a version number — suppressed.
	SafeVersionString
)

// String returns a human-readable label for a Decision.
func (d Decision) String() string {
	switch d {
	case Real:
		return "real"
	case SafeComment:
		return "safe:comment"
	case SafeTestFile:
		return "safe:test-file"
	case SafeVariableName:
		return "safe:variable-name"
	case SafePlaceholder:
		return "safe:placeholder"
	case SafeUUID:
		return "safe:uuid"
	case SafeVersionString:
		return "safe:version"
	default:
		return "unknown"
	}
}

// Classify inspects the context around a potential secret and returns a
// Decision indicating whether the finding is genuine or a false positive.
//
// Parameters:
//   - filePath: the repo-relative path of the file being scanned
//   - lineContent: the full text of the line on which the secret was found
//   - token: the specific token that triggered the detector
func Classify(filePath, lineContent, token string) Decision {
	// ── Check 1: Safe file path ──────────────────────────────────────────────
	if IsTestFilePath(filePath) {
		return SafeTestFile
	}

	// ── Check 2: Commented-out line ──────────────────────────────────────────
	trimmed := strings.TrimLeftFunc(lineContent, unicode.IsSpace)
	isPEM := strings.HasPrefix(trimmed, "-----BEGIN ")
	for _, prefix := range safeCommentPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			if prefix == "--" && isPEM {
				continue
			}
			return SafeComment
		}
	}

	// ── Check 3: UUID pattern ────────────────────────────────────────────────
	if uuidPattern.MatchString(token) {
		return SafeUUID
	}

	// ── Check 4: Version string ───────────────────────────────────────────────
	if versionLike.MatchString(token) {
		return SafeVersionString
	}

	// ── Check 5: Environment variable placeholder ─────────────────────────────
	if envVarPlaceholder.MatchString(token) {
		return SafePlaceholder
	}

	// ── Check 6: Config placeholder syntax ───────────────────────────────────
	if configPlaceholder.MatchString(token) {
		return SafePlaceholder
	}

	// ── Check 7: Safe variable name ───────────────────────────────────────────
	// Only inspect the *variable name* portion (text to the left of '=' or ':=')
	// to avoid false matches inside the value string itself.
	varName := extractVarName(lineContent, token)
	lowerVarName := strings.ToLower(varName)
	for _, word := range safeVariableWords {
		if strings.Contains(lowerVarName, word) {
			return SafeVariableName
		}
	}

	// ── Check 8: Short pure-alpha token ──────────────────────────────────────
	// Very short (< 12 char) all-letter tokens are dictionary words, not secrets.
	if isAllAlpha(token) && len(token) < 12 {
		return SafeVariableName
	}

	return Real
}

// IsTestFilePath returns true when the file path matches any known test or
// fixture pattern.  This is exported for use by the scanner to skip files
// entirely when appropriate.
func IsTestFilePath(path string) bool {
	lower := strings.ToLower(path)
	
	for _, suffix := range safeFileSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}

	// Normalize path separators
	lower = strings.ReplaceAll(lower, "\\", "/")
	segments := strings.Split(lower, "/")

	for _, seg := range segments {
		if safeFileSegments[seg] {
			return true
		}
	}
	return false
}

// IsSuppressed returns true when the decision is any non-Real value, providing
// a convenient predicate for callers that only care whether a finding was
// suppressed, not the specific reason.
func IsSuppressed(d Decision) bool {
	return d != Real
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

// extractVarName returns the portion of a line that represents the variable
// name immediately preceding the token.
func extractVarName(line, token string) string {
	idx := strings.Index(line, token)
	if idx < 0 {
		return line
	}

	for i := idx - 1; i >= 0; i-- {
		if line[i] == '=' || line[i] == ':' {
			// Find the closest alphanumeric identifier to the left
			end := -1
			for j := i - 1; j >= 0; j-- {
				isAlphaNum := (line[j] >= 'a' && line[j] <= 'z') || 
							  (line[j] >= 'A' && line[j] <= 'Z') || 
							  (line[j] >= '0' && line[j] <= '9') || 
							  line[j] == '_' || line[j] == '-'
				if isAlphaNum && end == -1 {
					end = j
				} else if !isAlphaNum && end != -1 {
					return line[j+1 : end+1]
				}
			}
			if end != -1 {
				return line[0 : end+1]
			}
			return ""
		}
	}
	return line
}

// isAllAlpha returns true when s contains only ASCII letters.
func isAllAlpha(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}
