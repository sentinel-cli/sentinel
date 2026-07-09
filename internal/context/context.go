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
	"path/filepath"
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
	"test", "example", "demo", "alphabet", "charset",
	"digits", "table", "chars",
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
	".test.tsx", ".spec.tsx", ".test.jsx", ".spec.jsx",
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
	configPlaceholder = regexp.MustCompile(`^<[^>]+>$|^\[\[.+\]\]$|^\{\{.+\}\}$|^\$\{\{.+\}\}$`)

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
func Classify(filePath, lineContent, token, sigID string) Decision {
	// ── Check 1: Safe file path ──────────────────────────────────────────────
	if IsTestFilePath(filePath) {
		return SafeTestFile
	}

	// ── Check 2: Commented-out line ──────────────────────────────────────────
	trimmed := strings.TrimLeftFunc(lineContent, unicode.IsSpace)
	isPEM := strings.HasPrefix(trimmed, "-----BEGIN ")
	ext := strings.ToLower(filepath.Ext(filePath))
	isConfigOrEnv := ext == ".npmrc" || ext == ".netrc" || ext == ".env" || ext == ".json" || ext == ".yaml" || ext == ".yml" || strings.HasPrefix(filepath.Base(filePath), ".")
	if !isConfigOrEnv {
		for _, prefix := range safeCommentPrefixes {
			if strings.HasPrefix(trimmed, prefix) {
				if prefix == "--" && isPEM {
					continue
				}
				return SafeComment
			}
		}
	}

	// ── Check 3: UUID pattern ────────────────────────────────────────────────
	if uuidPattern.MatchString(token) {
		lowerSig := strings.ToLower(sigID)
		isCredSig := strings.Contains(lowerSig, "token") || strings.Contains(lowerSig, "password") || strings.Contains(lowerSig, "secret") || strings.Contains(lowerSig, "auth") || strings.Contains(lowerSig, "key")
		lowerLine := strings.ToLower(lineContent)
		isCredentialAssign := isCredSig || strings.Contains(lowerLine, "token") || strings.Contains(lowerLine, "pass") || strings.Contains(lowerLine, "secret") || strings.Contains(lowerLine, "auth") || strings.Contains(lowerLine, "key")
		if !isCredentialAssign {
			return SafeUUID
		}
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

	// ── Check 9: Self-assignment or identical LHS/RHS value ─────────────────
	// If the cleaned variable name is identical to the cleaned token value,
	// then it is a self-assignment/default mapping (e.g. `auth_token: "auth_token"` or `password = "password"`),
	// not a real secret. Also support common token variable suffix patterns like const foo_token = "foo".
	cleanLHS := cleanIdentifier(varName)
	cleanToken := cleanIdentifier(token)
	if cleanLHS != "" {
		if cleanLHS == cleanToken ||
			cleanLHS == cleanToken+"token" ||
			cleanLHS == cleanToken+"key" ||
			cleanLHS == cleanToken+"secret" ||
			cleanLHS == cleanToken+"password" {
			return SafeVariableName
		}
	}

	// ── Check 10: Control flow / Conditional expressions ──────────────────────
	// Reject lines containing Rust "if let " or Go "if " conditional checks,
	// which are code logic rather than hardcoded credentials.
	lowerLine := strings.ToLower(lineContent)
	if strings.Contains(lowerLine, "if let ") || strings.HasPrefix(strings.TrimSpace(lowerLine), "if ") {
		return SafeVariableName
	}

	// ── Check 11: Mock/Test/Fake token values for generic rules ───────────────
	// Reject generic token values that explicitly contain "mock", "test", "fake",
	// or other test-fixture keywords.
	if strings.HasPrefix(sigID, "generic-") {
		lowerToken := strings.ToLower(token)
		if strings.Contains(lowerToken, "mock") || strings.Contains(lowerToken, "fake") ||
			strings.Contains(lowerToken, "placeholder") || strings.Contains(lowerToken, "dummy") ||
			strings.Contains(lowerToken, "example") || strings.Contains(lowerToken, "test-token") ||
			strings.Contains(lowerToken, "test_token") || strings.Contains(lowerToken, "fake-token") ||
			strings.Contains(lowerToken, "fake_token") {
			return SafeVariableName
		}
	}

	// ── Check 12 & 13: High-Entropy false positive checks ────────────────────
	if sigID == "hex" || sigID == "base64" || strings.Contains(sigID, "high-entropy") {
		// ── Check 12: Scientific float / Hex constants without letters a-d/f ────
		if strings.Contains(sigID, "hex") {
			hasOtherHexLetter := false
			for i := 0; i < len(token); i++ {
				c := token[i] | 0x20
				if (c >= 'a' && c <= 'd') || c == 'f' {
					hasOtherHexLetter = true
					break
				}
			}
			if !hasOtherHexLetter {
				return SafeVersionString
			}
		}

		// ── Check 13: Sequential characters (alphabets, character sets) ──────────
		if isSequential(token) {
			return SafeVersionString
		}
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

	for i, seg := range segments {
		if safeFileSegments[seg] {
			return true
		}
		// Match directory names containing mock, fixture, testdata (e.g. mock-policy-server)
		if strings.Contains(seg, "mock") || strings.Contains(seg, "fixture") || strings.Contains(seg, "testdata") {
			return true
		}
		// Match segment containing "test" (e.g. testWorkspace) but avoid matching package names containing test (e.g. "testing")
		// ONLY check this for directory segments (not the last segment/filename)!
		if i < len(segments)-1 {
			if strings.Contains(seg, "test") && seg != "testing" {
				return true
			}
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
	idx := strings.LastIndex(line, token)
	if idx < 0 {
		return ""
	}

	// Search backwards from the token's start to find the closest assignment operator
	opIdx := -1
	for i := idx - 1; i >= 0; i-- {
		if line[i] == '=' || line[i] == ':' {
			// Check if it is a double comparison like == or !=
			if line[i] == '=' {
				if i > 0 && (line[i-1] == '=' || line[i-1] == '!' || line[i-1] == '<' || line[i-1] == '>') {
					continue
				}
				if i+1 < len(line) && line[i+1] == '=' {
					continue
				}
			}
			opIdx = i
			break
		}
	}

	if opIdx >= 0 {
		// LHS is everything to the left of the operator on that line
		lhs := strings.TrimSpace(line[:opIdx])
		
		// If the operator was :=, make sure we strip the colon if it wasn't already stripped
		if line[opIdx] == '=' && opIdx > 0 && line[opIdx-1] == ':' {
			lhs = strings.TrimSpace(line[:opIdx-1])
		}

		// Clean up common language keywords/declaration prefixes
		for _, prefix := range []string{"let ", "const ", "var ", "local ", "ref ", "ref", "mut "} {
			if strings.HasPrefix(strings.ToLower(lhs), prefix) {
				lhs = lhs[len(prefix):]
			}
		}
		
		lhs = strings.TrimSpace(lhs)
		end := -1
		for i := len(lhs) - 1; i >= 0; i-- {
			c := lhs[i]
			isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
			if isAlphaNum && end == -1 {
				end = i
			} else if !isAlphaNum && end != -1 {
				return lhs[i+1 : end+1]
			}
		}
		if end != -1 {
			return lhs[:end+1]
		}
		return lhs
	}

	return ""
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

// cleanIdentifier returns a lowercased version of s containing only letters and digits.
func cleanIdentifier(s string) string {
	s = strings.ToLower(s)
	var sb strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// isSequential returns true when the token contains long runs of sequential characters,
// which indicates it is an alphabet or character set definition rather than a secret.
func isSequential(s string) bool {
	if len(s) < 6 {
		return false
	}
	// Lowercase and remove consecutive duplicates
	var cleaned []rune
	for _, r := range strings.ToLower(s) {
		if len(cleaned) == 0 || r != cleaned[len(cleaned)-1] {
			cleaned = append(cleaned, r)
		}
	}
	if len(cleaned) < 6 {
		return false
	}
	maxRun := 1
	currentRun := 1
	for i := 1; i < len(cleaned); i++ {
		diff := int(cleaned[i]) - int(cleaned[i-1])
		if diff == 1 || diff == -1 {
			currentRun++
			if currentRun > maxRun {
				maxRun = currentRun
			}
		} else {
			currentRun = 1
		}
	}
	return maxRun >= 12
}
