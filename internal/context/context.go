// Package context implements Tier 3 of the Crenox detection pipeline:
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
	"spec": true, "specs": true, "seed": true, "seeds": true,
}

// safeFileSuffixes are filename substrings that indicate the file is a test or doc.
var safeFileSuffixes = []string{
	"_test.go", "_spec.rb", ".test.js", ".spec.js", ".test.ts", ".spec.ts",
	".test.tsx", ".spec.tsx", ".test.jsx", ".spec.jsx",
	"_spec.js", "_spec.ts", "_spec.tsx", "_spec.jsx",
	"readme", ".md", ".rst", ".supp", ".po", ".pot", ".mo", ".xliff",
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

	// windowsPathRE matches Windows absolute paths like C:\ — pre-compiled to
	// avoid rebuilding inside the Classify hot path on every call.
	windowsPathRE = regexp.MustCompile(`^[a-zA-Z]:\\`)

	// codeVarConcatRE detects code variable concatenation expressions like
	// identifier+identifier inside a token, indicating it is code not a secret.
	codeVarConcatRE = regexp.MustCompile(`[a-zA-Z0-9_]\+[a-zA-Z0-9_]`)
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

	// SafeFilePath indicates the token looks like a file path — suppressed.
	SafeFilePath
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
	case SafeFilePath:
		return "safe:file-path"
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
	lowerLine := strings.ToLower(lineContent)
	isCredAssignment := (strings.Contains(lowerLine, "password") ||
		strings.Contains(lowerLine, "secret") ||
		strings.Contains(lowerLine, "token") ||
		strings.Contains(lowerLine, "auth") ||
		strings.Contains(lowerLine, "key")) &&
		(strings.Contains(lowerLine, "=") || strings.Contains(lowerLine, ":"))

	// ── Check 0A: Non-ASCII characters in token ──────────────────────────────
	// Real API keys, secrets, base64, and hex strings are purely ASCII.
	// Non-ASCII strings (like translation texts or comments) are safe.
	for _, r := range token {
		if r > 127 {
			return SafePlaceholder
		}
	}

	// ── Check 0B: npm-auth-key scope check ───────────────────────────────────
	// npm registry _auth configurations are only valid inside .npmrc files.
	if sigID == "npm-auth-key" {
		base := strings.ToLower(filepath.Base(filePath))
		if base != ".npmrc" && base != "npmrc" {
			return SafeVariableName
		}
	}

	// ── Check 0C: MIME type suppression ──────────────────────────────────────
	// MIME types (like application/x-authorware-seg) are not secrets.
	lowerToken := strings.ToLower(token)
	if strings.Contains(lowerToken, "application/") || strings.Contains(lowerToken, "image/") ||
		strings.Contains(lowerToken, "text/") || strings.Contains(lowerToken, "audio/") ||
		strings.Contains(lowerToken, "video/") {
		return SafePlaceholder
	}

	// ── Check 0D: Git commit SHA / reference in workflows ────────────────────
	if strings.Contains(lineContent, "@"+token) {
		return SafeVersionString
	}

	// ── Check 0E: Obvious placeholder values and safe constants ─────────────
	commonPlaceholders := []string{
		"your-key", "your-token", "your-actual", "your-api", "your-secret",
		"your-discord", "your-glm", "your-baidu", "actual-key", "actual-openai",
		"actual-anthropic", "secret-token", "bot-token", "xxx",
		"not-a-real", "changeme", "lorem", "your-password", "your-secret-token",
		"your_secret_token", "demo-",
	}
	for _, ph := range commonPlaceholders {
		if strings.Contains(lowerToken, ph) {
			return SafePlaceholder
		}
	}
	if strings.HasSuffix(lowerToken, "-xxx") || strings.HasPrefix(lowerToken, "sk-proj-key") || strings.HasPrefix(lowerToken, "sk-ant-key") {
		return SafePlaceholder
	}

	commonSafeConstants := map[string]bool{
		"no_credentials":       true,
		"invalid_credential":   true,
		"not_handled":          true,
		"internal_error":       true,
		"invalid_api_key":      true,
		"missing_api_key":      true,
		"expired_token":        true,
		"github-token":         true,
		"auth_selection_model": true,
		"authenticate":         true,
		"client_credentials":   true,
		"authorization_code":   true,
		"password":             true,
		"secret":               true,
		"token":                true,
		"current-password":     true,
		"new-password":         true,
	}
	if commonSafeConstants[lowerToken] {
		return SafePlaceholder
	}

	// ── Check 0G: Token IS a canonical config key name (not a value) ─────────
	// Catches cases where a YAML key like "api-key:" has no value and the parser
	// returns the key name itself. Key names are short, lowercase, hyphenated.
	canonicalKeyNames := map[string]bool{
		"api-key": true, "api_key": true, "auth-key": true, "auth_key": true,
		"auth-password": true, "auth_password": true, "access-key": true, "access_key": true,
		"secret-key": true, "secret_key": true, "private-key": true, "private_key": true,
		"api-token": true, "api_token": true, "auth-token": true, "auth_token": true,
		"access-token": true, "access_token": true, "secret-token": true, "secret_token": true,
		"client-id": true, "client_id": true, "client-secret": true, "client_secret": true,
		"app-key": true, "app_key": true, "app-secret": true, "app_secret": true,
		"webhook-secret": true, "webhook_secret": true, "signing-key": true, "signing_key": true,
	}
	if canonicalKeyNames[lowerToken] {
		return SafePlaceholder
	}

	// ── Check 0H: CamelCase + digit code identifier ───────────────────────────
	// Catches alphanumeric function/method names like tencentCloudHmacsha256.
	// Criteria: all chars alphanumeric, has BOTH upper and lower case letters,
	// and has ≥4 consecutive lowercase letters (Go/Java camelCase pattern).
	// GUARD: Do NOT suppress when the line is an explicit credential assignment
	// (e.g. `password := "myRealComplexPassword123!"`). In that case the token
	// is a value, not an identifier, even if it looks like camelCase.
	if strings.Contains(sigID, "entropy") || strings.Contains(sigID, "base64") {
		// A credential assignment has a cred word on the LHS AND an explicit
		// assignment operator. Stricter than the outer isCredAssignment because
		// we need a quoted value (e.g. password := "value") not just any colon.
		isCredAssignmentStrict := isCredAssignment &&
			(strings.Contains(lowerLine, ":=") || strings.Contains(lowerLine, " = ") ||
				strings.Contains(lowerLine, "= \"") || strings.Contains(lowerLine, "=\""))
		if !isCredAssignmentStrict {
			isAllAlphanumeric := true
			hasUpper := false
			hasLower := false
			for _, r := range token {
				if r >= 'a' && r <= 'z' {
					hasLower = true
				} else if r >= 'A' && r <= 'Z' {
					hasUpper = true
				} else if r >= '0' && r <= '9' || r == '_' {
					// digits and underscores are OK in identifiers
				} else {
					isAllAlphanumeric = false
					break
				}
			}
			if isAllAlphanumeric && hasUpper && hasLower {
				maxConsecLower, cur := 0, 0
				for _, r := range token {
					if r >= 'a' && r <= 'z' {
						cur++
						if cur > maxConsecLower {
							maxConsecLower = cur
						}
					} else {
						cur = 0
					}
				}
				if maxConsecLower >= 4 {
					return SafeVariableName
				}
			}
		}
	}

	// ── Check 0I: Kebab/Snake case generic identifiers ────────────────────────
	// Generic signatures often capture variable names, HTML attributes, or default
	// key names (e.g. "current-password", "memos_access_token") as secrets.
	// If a generic token is ONLY lowercase letters and separators, it is almost
	// certainly an English-word identifier, not a real random secret.
	// We skip this check for passwords, as "correct-horse-battery-staple"
	// is a valid passphrase pattern.
	if strings.HasPrefix(sigID, "generic-") && !strings.Contains(sigID, "password") && !strings.Contains(sigID, "pass-key") {
		isKebabSnake := true
		for _, r := range token {
			if !((r >= 'a' && r <= 'z') || r == '-' || r == '_') {
				isKebabSnake = false
				break
			}
		}
		if isKebabSnake {
			return SafeVariableName
		}
	}

	// ── Check 0F: Programming keywords in high-entropy strings ────────────────
	if sigID == "hex" || sigID == "base64" || strings.Contains(sigID, "entropy") {
		safeWords := []string{
			"callback", "url", "offline", "download", "decision", "instant",
			"retry", "cooldown", "switch", "procedure", "metadata", "selection",
			"provider", "registrar", "executor", "applier",
		}
		for _, sw := range safeWords {
			if strings.Contains(lowerToken, sw) {
				return SafePlaceholder
			}
		}
	}

	// ── Check 1: Safe file path ──────────────────────────────────────────────
	if IsTestFilePath(filePath) {
		return SafeTestFile
	}

	// ── Check 1B: Base64 data image / URI suppression ───────────────────────
	if strings.Contains(lowerLine, "data:image/") || strings.Contains(lowerLine, "data:application/") ||
		strings.Contains(lowerLine, "data:audio/") || strings.Contains(lowerLine, "data:video/") ||
		strings.Contains(lowerLine, "data:font/") {
		return SafePlaceholder
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

	// ── Check 9B: Variable Reference ─────────────────────────────────────────
	// If the token is a pure-alphabetic variable reference like autoPassword or mySecretToken,
	// suppress it as a variable reference rather than a hardcoded secret.
	if isVariableReference(token) {
		return SafeVariableName
	}

	// ── Check 10: Control flow / Conditional expressions ──────────────────────
	// Reject lines containing Rust "if let " or Go "if " conditional checks,
	// which are code logic rather than hardcoded credentials.
	if strings.Contains(lowerLine, "if let ") || strings.HasPrefix(strings.TrimSpace(lowerLine), "if ") {
		return SafeVariableName
	}

	// ── Check 11: Mock/Test/Fake token values ────────────────────────────────
	if sigID == "hex" || sigID == "base64" || strings.Contains(sigID, "high-entropy") {
		if !isCredAssignment {
			if strings.Contains(lowerToken, "mock") || strings.Contains(lowerToken, "fake") ||
				strings.Contains(lowerToken, "placeholder") || strings.Contains(lowerToken, "dummy") ||
				strings.Contains(lowerToken, "example") || strings.Contains(lowerToken, "test-token") ||
				strings.Contains(lowerToken, "test_token") || strings.Contains(lowerToken, "mocktoken") ||
				strings.Contains(lowerToken, "notareal") || strings.Contains(lowerToken, "not-a-real") {
				return SafeVariableName
			}

			// ── Check 11B: Sequential Mock Patterns ──────────────────────────────────
			// Reject tokens containing obvious placeholder digit/letter runs like 1234567890, abcdefabcdef.
			if strings.Contains(lowerToken, "1234567890") || strings.Contains(lowerToken, "abcdefabcdef") ||
				strings.Contains(lowerToken, "qwertyqwerty") || strings.Contains(lowerToken, "asdfghasdfgh") {
				return SafeVariableName
			}
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

	// ── Check 14: File path pattern suppression ──────────────────────────────
	lowerToken = strings.ToLower(token)
	if strings.HasPrefix(lowerToken, "/root/") || strings.HasPrefix(lowerToken, "/home/") ||
		strings.HasPrefix(lowerToken, "/usr/") || strings.HasPrefix(lowerToken, "/tmp/") ||
		strings.HasPrefix(lowerToken, "/etc/") || strings.HasPrefix(lowerToken, "/var/") ||
		strings.HasPrefix(lowerToken, "/opt/") || strings.HasPrefix(lowerToken, "/bin/") ||
		strings.HasPrefix(lowerToken, "/lib/") || windowsPathRE.MatchString(token) {
		return SafeFilePath
	}
	// Env-var based paths: $XDG_DATA_HOME/..., $HOME/..., $USER/..., etc.
	// Entropy strips the leading '$', so also match without it.
	if strings.HasPrefix(token, "$XDG_") || strings.HasPrefix(token, "$HOME/") ||
		strings.HasPrefix(token, "$USER/") || strings.HasPrefix(token, "$LOCALAPPDATA") ||
		strings.HasPrefix(token, "$APPDATA") || strings.HasPrefix(token, "${XDG_") ||
		strings.HasPrefix(token, "${HOME}") ||
		strings.HasPrefix(token, "XDG_DATA") || strings.HasPrefix(token, "XDG_CONFIG") ||
		strings.HasPrefix(token, "XDG_CACHE") || strings.HasPrefix(token, "XDG_RUNTIME") ||
		strings.HasPrefix(token, "LOCALAPPDATA") || strings.HasPrefix(token, "APPDATA") {
		return SafeFilePath
	}
	// Also catch when the raw line contains an env-var path reference
	if strings.Contains(lineContent, "$XDG_") || strings.Contains(lineContent, "$HOME/") {
		if strings.Contains(token, "/") {
			return SafeFilePath
		}
	}
	if (strings.Count(token, "/") >= 2 || strings.Count(token, "\\") >= 2) &&
		(strings.HasSuffix(lowerToken, "png") || strings.HasSuffix(lowerToken, "jpg") ||
			strings.HasSuffix(lowerToken, "jpeg") || strings.HasSuffix(lowerToken, "gif") ||
			strings.HasSuffix(lowerToken, "svg") || strings.HasSuffix(lowerToken, "json") ||
			strings.HasSuffix(lowerToken, "yaml") || strings.HasSuffix(lowerToken, "yml") ||
			strings.HasSuffix(lowerToken, "txt") || strings.HasSuffix(lowerToken, "html") ||
			strings.HasSuffix(lowerToken, "css") || strings.HasSuffix(lowerToken, "js") ||
			strings.HasSuffix(lowerToken, "ts") || strings.HasSuffix(lowerToken, "py") ||
			strings.HasSuffix(lowerToken, "sh") || strings.HasSuffix(lowerToken, "go")) {
		return SafeFilePath
	}

	// ── Check 15: XSRF/CSRF token suppression ────────────────────────────────
	if strings.Contains(lowerVarName, "xsrf") || strings.Contains(lowerVarName, "csrf") {
		return SafeVariableName
	}

	// ── Check 16: Input prompts and read commands ─────────────────────────────
	// Reject lines containing standard shell/programming input prompt constructs.
	if strings.Contains(lowerLine, "read -p ") || strings.Contains(lowerLine, "read -r ") ||
		strings.Contains(lowerLine, "read -s ") || strings.HasPrefix(strings.TrimSpace(lowerLine), "read ") ||
		strings.Contains(lowerLine, "input(") || strings.Contains(lowerLine, "raw_input(") ||
		strings.Contains(lowerLine, "scanln(") || strings.Contains(lowerLine, "scanf(") {
		return SafeVariableName
	}

	// ── Check 17: Constant IDs, UUIDs, and Hashes ─────────────────────────────
	// Reject generic entropy matches when the variable name indicates it is an ID,
	// UUID, GUID, hash, or message identifier, or points to a path/link/email.
	if sigID == "hex" || sigID == "base64" || strings.Contains(sigID, "high-entropy") {
		if strings.Contains(lowerVarName, "id") || strings.Contains(lowerVarName, "uuid") ||
			strings.Contains(lowerVarName, "guid") || strings.Contains(lowerVarName, "hash") ||
			strings.Contains(lowerVarName, "md5") || strings.Contains(lowerVarName, "sha") ||
			strings.Contains(lowerVarName, "sha256") || strings.Contains(lowerVarName, "sha512") ||
			strings.Contains(lowerVarName, "sha1") || strings.Contains(lowerVarName, "checksum") ||
			strings.Contains(lowerVarName, "fingerprint") || strings.Contains(lowerVarName, "digest") ||
			strings.Contains(lowerVarName, "workspace") || strings.Contains(lowerVarName, "path") ||
			strings.Contains(lowerVarName, "dir") || strings.Contains(lowerVarName, "folder") ||
			strings.Contains(lowerVarName, "url") || strings.Contains(lowerVarName, "uri") ||
			strings.Contains(lowerVarName, "host") || strings.Contains(lowerVarName, "link") ||
			strings.Contains(lowerVarName, "email") || strings.Contains(lowerVarName, "useragent") ||
			strings.Contains(lowerVarName, "user_agent") || strings.Contains(lowerVarName, "ua") ||
			strings.Contains(lowerVarName, "device") || strings.Contains(lowerVarName, "model") {
			return SafeVariableName
		}
	}

	// ── Check 18: C++ Mangled Symbols ──────────────────────────────────────────
	// Mangled C++ symbols (e.g. starting with _ZN or _ZNK) are long alphanumeric
	// strings that look like high-entropy base64, but are just compiled function names.
	if strings.HasPrefix(token, "_ZN") || strings.HasPrefix(token, "_ZNK") ||
		strings.HasPrefix(token, "_ZTI") || strings.HasPrefix(token, "_ZTV") ||
		strings.HasPrefix(token, "_ZTS") {
		return SafeVariableName
	}

	// ── Check 19: Base64 Character Set Diversity ──────────────────────────────
	// A real Base64-encoded random secret has high character diversity.
	// If a Base64 entropy token contains ONLY lowercase letters or ONLY uppercase letters
	// (no digits, no mixed case), it is mathematically a false positive.
	if sigID == "base64" || strings.Contains(sigID, "high-entropy-base64") {
		hasUpper := false
		hasLower := false
		hasDigitOrSymbol := false
		for i := 0; i < len(token); i++ {
			c := token[i]
			if c >= 'a' && c <= 'z' {
				hasLower = true
			} else if c >= 'A' && c <= 'Z' {
				hasUpper = true
			} else if (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '_' || c == '-' {
				hasDigitOrSymbol = true
			}
		}
		if !hasDigitOrSymbol && (!hasUpper || !hasLower) {
			return SafeVariableName
		}
	}

	// ── Check 20: Mozilla SOPS Encrypted Values ──────────────────────────────
	// Ignore values encrypted by Mozilla SOPS (wrapped in ENC[AES256_GCM,...])
	if strings.Contains(lineContent, "ENC[") {
		return SafePlaceholder
	}

	// ── Check 21: Apple Entitlements / Plist Keys ────────────────────────────
	// Reject generic entropy tokens inside .plist files or raw content if they
	// contain Apple bundle identifiers, capability names, or domain strings.
	if ext == ".plist" || strings.Contains(filePath, "entitlements") {
		if strings.HasPrefix(lowerToken, "com.apple.") || strings.Contains(lowerToken, "allow-unsigned") ||
			strings.Contains(lowerToken, "security.cs.") || strings.Contains(lowerToken, "entitlement") {
			return SafeVariableName
		}
	}

	// ── Check 22: URL Route / API Path / Code Concatenation ──────────────────
	// Reject high-entropy base64/hex tokens that look like API routes/endpoints
	// (contain multiple slashes, start with a slash) or contain code variable concatenations.
	if sigID == "base64" || sigID == "hex" || strings.Contains(sigID, "high-entropy") {
		if !isCredAssignment {
			if strings.HasPrefix(token, "/") || (strings.Count(token, "/") >= 2 && !strings.Contains(token, "://")) {
				return SafeFilePath
			}
		}
		if strings.Contains(token, "+") {
			if codeVarConcatRE.MatchString(token) {
				return SafeVariableName
			}
		}
	}

	// ── Check 23: Multipart form boundaries ──────────────────────────────────
	// Ignore tokens matching multipart form boundaries (e.g. WebKitFormBoundary...)
	if strings.Contains(lowerToken, "webkitformboundary") || strings.HasPrefix(lowerToken, "formboundary") {
		return SafePlaceholder
	}

	return Real
}

// ClassifyWithPrev performs additional context classification using the previous
// line content. This handles multiline constructs such as C #define macros where
// the variable name is on one line and the value (hash) is on the next line.
//
// Example (C kernel driver):
//
//	#define HF_L3_FRAME_PLAN_SHA256 \       ← previous line
//	    "b4422b629310b822..."               ← current line (token detected here)
//
// In this case the variable name contains "SHA256" but it is on the previous line,
// not the current one, so the regular Classify cannot see it.
func ClassifyWithPrev(filePath, lineContent, prevLineContent, token, sigID string) Decision {
	if sigID != "hex" && sigID != "base64" && !strings.Contains(sigID, "high-entropy") {
		return Real
	}

	prevTrimmed := strings.TrimSpace(prevLineContent)
	lowerPrev := strings.ToLower(prevTrimmed)

	// ── Check A: C/C++ #define multiline SHA/hash macro ───────────────────────
	// Handles: #define HF_L3_FRAME_PLAN_SHA256 \
	//              "b4422b..."  ← detected here
	if strings.HasPrefix(prevTrimmed, "#define ") || strings.HasSuffix(prevTrimmed, "\\") {
		if strings.Contains(lowerPrev, "sha256") || strings.Contains(lowerPrev, "sha512") ||
			strings.Contains(lowerPrev, "sha1") || strings.Contains(lowerPrev, "sha_") ||
			strings.Contains(lowerPrev, "_sha") || strings.Contains(lowerPrev, "hash") ||
			strings.Contains(lowerPrev, "checksum") || strings.Contains(lowerPrev, "digest") ||
			strings.Contains(lowerPrev, "fingerprint") || strings.Contains(lowerPrev, "hmac") {
			return SafeVariableName
		}
	}

	// ── Check B: Previous line CONTAINS a SHA/hash/commit keyword anywhere ────
	// Covers Python/shell list entries where the previous element names a hash:
	//   "#define HF_L3_FRAME_PLAN_SHA256",   ← previous (Python string)
	//   "b4422b629310..."                    ← current (token detected)
	// Also covers git commit SHAs listed after frame_hash, commit_sha, etc.
	if strings.Contains(lowerPrev, "sha256") || strings.Contains(lowerPrev, "sha512") ||
		strings.Contains(lowerPrev, "sha1") || strings.Contains(lowerPrev, "_sha") ||
		strings.Contains(lowerPrev, "sha_") || strings.Contains(lowerPrev, "hash") ||
		strings.Contains(lowerPrev, "commit") || strings.Contains(lowerPrev, "checksum") ||
		strings.Contains(lowerPrev, "digest") || strings.Contains(lowerPrev, "fingerprint") {
		return SafeVariableName
	}

	// ── Check C: 40-char hex git commit SHA on current line ───────────────────
	// A 40-char hex string that is pure SHA1 length — most likely a git commit.
	if (sigID == "hex" || strings.Contains(sigID, "high-entropy")) && len(token) == 40 {
		lowerLine := strings.ToLower(lineContent)
		if strings.Contains(lowerLine, "hash") || strings.Contains(lowerLine, "commit") ||
			strings.Contains(lowerLine, "sha") || strings.Contains(lowerLine, "rev") ||
			strings.Contains(lowerLine, "parent") || strings.Contains(lowerLine, "blame") {
			return SafeVariableName
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
	// If the token itself contains '=' or ':', it is a tight assignment (e.g. key=val)
	firstOp := strings.IndexAny(token, "=:")
	if firstOp > 0 && firstOp < len(token)-1 {
		lhs := strings.TrimSpace(token[:firstOp])
		for _, prefix := range []string{"let ", "const ", "var ", "local ", "ref ", "ref", "mut "} {
			if strings.HasPrefix(strings.ToLower(lhs), prefix) {
				lhs = lhs[len(prefix):]
			}
		}
		return strings.TrimSpace(lhs)
	}

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
	// Fast path: if the string is already lowercase alphanumeric, return it directly
	isClean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			isClean = false
			break
		}
	}
	if isClean {
		return s
	}

	s = strings.ToLower(s)
	var sb strings.Builder
	sb.Grow(len(s)) // Pre-allocate buffer to prevent intermediate allocations
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			sb.WriteByte(c) // WriteByte is faster than WriteRune (ASCII-only)
		}
	}
	return sb.String()
}

// isSequential returns true when the token contains long runs of sequential characters,
// which indicates it is an alphabet or character set definition rather than a secret.
// It checks sequentiality both in ASCII space and in alphanumeric range (handling '9' -> 'a').
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

	const alphanumeric = "0123456789abcdefghijklmnopqrstuvwxyz"

	maxRun := 1
	currentRun := 1
	for i := 1; i < len(cleaned); i++ {
		r1 := cleaned[i-1]
		r2 := cleaned[i]

		// Check sequential in ASCII table
		diffASCII := int(r2) - int(r1)
		isSeqASCII := diffASCII == 1 || diffASCII == -1

		// Check sequential in custom alphanumeric alphabet
		idx1 := strings.IndexRune(alphanumeric, r1)
		idx2 := strings.IndexRune(alphanumeric, r2)
		isSeqAlpha := false
		if idx1 >= 0 && idx2 >= 0 {
			diffAlpha := idx2 - idx1
			isSeqAlpha = diffAlpha == 1 || diffAlpha == -1
		}

		if isSeqASCII || isSeqAlpha {
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

// isVariableReference returns true if the token looks like a code variable identifier
// rather than a hardcoded secret.
func isVariableReference(token string) bool {
	if !isAllAlpha(token) {
		return false
	}
	lower := strings.ToLower(token)
	// If it is just a common variable suffix word
	if lower == "password" || lower == "token" || lower == "secret" || lower == "key" || lower == "auth" {
		return true
	}
	// Common variable prefixes combined with credential suffixes
	prefixes := []string{
		"auto", "default", "temp", "mock", "user", "admin", "db", "config", "sys", "old", "new",
		"test", "fake", "dummy", "local", "client", "server", "raw", "read", "write", "get", "set",
		"current", "next", "prev", "var", "const", "let", "my", "our", "their", "your",
	}
	suffixes := []string{"password", "token", "secret", "key", "auth"}
	for _, p := range prefixes {
		for _, s := range suffixes {
			if lower == p+s || lower == p+"_"+s || lower == p+"-"+s {
				return true
			}
		}
	}
	return false
}
