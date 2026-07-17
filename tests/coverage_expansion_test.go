package tests

import (
	"bytes"
	"testing"
	"time"

	crenoxcontext "github.com/crenoxhq/crenox/v2/internal/context"
	"github.com/crenoxhq/crenox/v2/internal/reporter"
	"github.com/crenoxhq/crenox/v2/internal/scanner"
	"github.com/crenoxhq/crenox/v2/internal/trie"
)

// 1. Context tests
func TestContext_Suppression(t *testing.T) {
	if !crenoxcontext.IsSuppressed(crenoxcontext.SafeComment) {
		t.Error("expected SafeComment to be suppressed")
	}
	if crenoxcontext.IsSuppressed(crenoxcontext.Real) {
		t.Error("expected Real to NOT be suppressed")
	}

	// String representation of Decision
	decisions := []crenoxcontext.Decision{
		crenoxcontext.Real,
		crenoxcontext.SafeComment,
		crenoxcontext.SafeTestFile,
		crenoxcontext.SafeVariableName,
		crenoxcontext.SafePlaceholder,
		crenoxcontext.SafeUUID,
		crenoxcontext.SafeVersionString,
	}
	for _, d := range decisions {
		if d.String() == "" {
			t.Errorf("expected non-empty string for decision %v", d)
		}
	}
}

// 2. Reporter tests
func TestReporter_Outputs(t *testing.T) {
	var buf bytes.Buffer
	rep := reporter.New(&buf, reporter.FormatPlain)

	findings := []scanner.Finding{
		{
			FilePath:      "main.go",
			Line:          10,
			LineContent:   `password := "secret"`,
			Token:         "secret",
			DetectionTier: scanner.TierTrie,
			SignatureID:   "generic-password-key",
			Description:   "Generic Password Key",
			Severity:      "HIGH",
		},
		{
			FilePath:      "config.go",
			Line:          5,
			LineContent:   `api_key := "abcdef1234567890"`,
			Token:         "abcdef1234567890",
			DetectionTier: scanner.TierEntropy,
			SignatureID:   "high-entropy-hex",
			Description:   "High entropy hex string",
			Severity:      "LOW",
		},
		{
			FilePath:      "key.pem",
			Line:          1,
			LineContent:   `-----BEGIN RSA PRIVATE KEY-----`,
			Token:         "-----BEGIN RSA PRIVATE KEY-----",
			DetectionTier: scanner.TierTrie,
			SignatureID:   "rsa-private-key",
			Description:   "RSA Private Key",
			Severity:      "CRITICAL",
		},
		{
			FilePath:      "api.py",
			Line:          3,
			LineContent:   `token = "abc"`,
			Token:         "abc",
			DetectionTier: scanner.TierTrie,
			SignatureID:   "generic-token",
			Description:   "Token",
			Severity:      "MEDIUM",
		},
		{
			FilePath:      "unknown.txt",
			Line:          1,
			LineContent:   `unknown = "xyz"`,
			Token:         "xyz",
			DetectionTier: scanner.TierTrie,
			SignatureID:   "unknown",
			Description:   "Unknown",
			Severity:      "UNKNOWN",
		},
	}

	rep.PrintHeader()
	rep.PrintFindings(findings)
	rep.PrintSummary(findings, time.Second, 10)
	rep.PrintClean(time.Second, 10)
	rep.PrintSkipped("file.zip", "excluded extension")

	out := buf.String()
	if len(out) == 0 {
		t.Error("expected reporter output to be non-empty")
	}

	// JSON format
	buf.Reset()
	repJSON := reporter.New(&buf, reporter.FormatJSON)
	repJSON.PrintHeader()
	repJSON.PrintFindings(findings)
	repJSON.PrintSummary(findings, time.Second, 10)
	repJSON.PrintClean(time.Second, 10)
	repJSON.PrintSkipped("file.zip", "excluded extension")
	if len(buf.String()) == 0 {
		t.Error("expected JSON reporter output to be non-empty")
	}

	// SARIF format
	buf.Reset()
	repSARIF := reporter.New(&buf, reporter.FormatSARIF)
	repSARIF.PrintHeader()
	repSARIF.PrintFindings(findings)
	repSARIF.PrintSummary(findings, time.Second, 10)
	repSARIF.PrintClean(time.Second, 10)
	repSARIF.PrintSkipped("file.zip", "excluded extension")
	if len(buf.String()) == 0 {
		t.Error("expected SARIF reporter output to be non-empty")
	}

	// Pretty format
	buf.Reset()
	repPretty := reporter.New(&buf, reporter.FormatPretty)
	repPretty.PrintHeader()
	repPretty.PrintFindings(findings)
	repPretty.PrintSummary(findings, time.Second, 10)
	repPretty.PrintClean(time.Second, 10)
	repPretty.PrintSkipped("file.zip", "excluded extension")
	if len(buf.String()) == 0 {
		t.Error("expected Pretty reporter output to be non-empty")
	}

	// ParseFormat checking
	if reporter.ParseFormat("invalid") != reporter.FormatPretty {
		t.Error("expected default format to be pretty for invalid strings")
	}
	if reporter.ParseFormat("json") != reporter.FormatJSON {
		t.Error("expected json format")
	}

	// Default reporter
	defRep := reporter.Default()
	if defRep == nil {
		t.Error("expected non-nil default reporter")
	}
}

// 3. Scanner Edge Cases
func TestScanner_EdgeCasesAdditional(t *testing.T) {
	// IsBinary helper
	if !scanner.IsBinary(append([]byte("hello"), 0x00)) {
		t.Error("expected string with null byte to be binary")
	}
	if scanner.IsBinary([]byte("hello world")) {
		t.Error("expected plain text string to NOT be binary")
	}

	// Create larger text to test IsBinary 8KB limit
	largeText := make([]byte, 10000)
	for i := range largeText {
		largeText[i] = 'a'
	}
	if scanner.IsBinary(largeText) {
		t.Error("expected pure alpha text > 8KB to NOT be binary")
	}
	largeText[5000] = 0x00
	if !scanner.IsBinary(largeText) {
		t.Error("expected text > 8KB containing null byte to be binary")
	}

	// matchesPathComponent check on empty pattern
	s := defaultScanner()
	findings := s.ScanContent("test.go", []byte("xyz"))
	if len(findings) != 0 {
		t.Error("expected 0 findings for xyz")
	}

	// isLogIndicator testing
	logIndicators := []string{
		`[INFO] 2026-07-08 bearer="12345"`,
		`DEBUG: auth="12345"`,
		`WARN: authorization: token`,
		`127.0.0.1 - - [08/Jul/2026] "GET / HTTP/1.1" 200 4567 "token"`,
		`password=123`,
	}
	// Call scan to test log lines internally
	for _, l := range logIndicators {
		s.ScanContent("log.txt", []byte(l))
	}
}

func TestScanner_GiantComprehensiveSuite(t *testing.T) {
	a := trie.Build(trie.BuiltinSignatures)
	s := scanner.New(a, scanner.Options{
		EntropyThreshold: 3.5,
		MinSecretLength:  20,
	})

	// 1. Excluded paths and extensions validation (Dist, Build, lock files, pb.go, min.js, map)
	t.Run("Exclusions", func(t *testing.T) {
		// dist directory
		findings := s.ScanContent("dist/app.js", []byte(`const secret = "ghp_REALTOKEN1234567890abcdef";`))
		if len(findings) == 0 {
			t.Error("expected finding for dist/app.js since ScanContent doesn't check path exclusions directly")
		}
		// Note: scan content itself doesn't check cfg.ExcludePaths directly inside ScanContent, 
		// but ScanContent checks isKnownSafeFile which skips .pb.go and others!
		// Let's verify isKnownSafeFile exclusions:
		findingsPB := s.ScanContent("model.pb.go", []byte(`const token = "ghp_REALTOKEN1234567890abcdef";`))
		if len(findingsPB) != 0 {
			t.Errorf("expected 0 findings for model.pb.go, got %d", len(findingsPB))
		}

		findingsHCL := s.ScanContent(".terraform.lock.hcl", []byte(`h1:abcdef1234567890abcdef1234567890`))
		if len(findingsHCL) != 0 {
			t.Errorf("expected 0 findings for .terraform.lock.hcl, got %d", len(findingsHCL))
		}

		// Also check MatchesExcludePath helper for paths and extensions
		excludePaths := []string{
			"dist/**", "build/**", "out/**", "target/**", "bin/**",
			"**/*.min.js", "**/*.min.css",
		}
		if !scanner.MatchesExcludePath("dist/app.js", excludePaths) {
			t.Error("expected dist/app.js to be excluded")
		}
		if !scanner.MatchesExcludePath("build/main.py", excludePaths) {
			t.Error("expected build/main.py to be excluded")
		}
		if !scanner.MatchesExcludePath("assets/main.min.js", excludePaths) {
			t.Error("expected assets/main.min.js to be excluded")
		}
		if !scanner.HasExcludedExtension("main.map", []string{".map"}) {
			t.Error("expected main.map to be excluded by extension")
		}
		if !scanner.HasExcludedExtension("main.gen.go", []string{".gen.go"}) {
			t.Error("expected main.gen.go to be excluded by extension")
		}
	})

	// 2. Variable assignments validation (autoPassword, defaultToken, etc.)
	t.Run("VariableAssignments", func(t *testing.T) {
		cases := []struct {
			line string
			safe bool
		}{
			{`const password = autoPassword;`, true},
			{`const token = defaultToken;`, true},
			{`const key = mySecretKey;`, true},
			{`const client_secret = mockSecret;`, true},
			{`password := "myRealComplexPassword123!"`, false},
			{`token = "ghp_123456789012345678901234567890123456"`, false},
			{`password = "simple"`, true}, // simple/short dictionary word
		}

		for i, c := range cases {
			findings := s.ScanContent("app.go", []byte(c.line))
			isSafe := len(findings) == 0
			if isSafe != c.safe {
				t.Errorf("case %d (%s): expected safe=%t, got safe=%t", i, c.line, c.safe, isSafe)
			}
		}
	})

	// 3. Base64 character diversity validation
	t.Run("Base64Diversity", func(t *testing.T) {
		// Pure uppercase base64-like (high entropy but no diversity, rejected)
		findingsUpper := s.ScanContent("file.txt", []byte(`KEY = "AAAAAAABBBBBBBCCCCCCCDDDDDDDEEEEEEE"`))
		if len(findingsUpper) != 0 {
			t.Errorf("expected 0 findings for all-uppercase base64 token, got %d", len(findingsUpper))
		}

		// Pure lowercase base64-like (high entropy but no diversity, rejected)
		findingsLower := s.ScanContent("file.txt", []byte(`KEY = "aaaaaaabbbbbbbcccccccdddddddeeeeeee"`))
		if len(findingsLower) != 0 {
			t.Errorf("expected 0 findings for all-lowercase base64 token, got %d", len(findingsLower))
		}
	})

	// 4. File path suppressions
	t.Run("PathSuppressions", func(t *testing.T) {
		findingsRoot := s.ScanContent("config.py", []byte(`path = "/root/sentinel/internal/config.go"`))
		if len(findingsRoot) != 0 {
			t.Errorf("expected 0 findings for absolute linux path, got %d", len(findingsRoot))
		}

		findingsWin := s.ScanContent("config.py", []byte(`win_path = "C:\\Windows\\System32\\cmd.exe"`))
		if len(findingsWin) != 0 {
			t.Errorf("expected 0 findings for windows path, got %d", len(findingsWin))
		}

		findingsEnv := s.ScanContent("config.py", []byte(`env_path = "$HOME/.crenox.yaml"`))
		if len(findingsEnv) != 0 {
			t.Errorf("expected 0 findings for env path, got %d", len(findingsEnv))
		}
	})

	// 5. OCI digests and hashes (sha256:...)
	t.Run("DigestsAndHashes", func(t *testing.T) {
		findingsSHA := s.ScanContent("Dockerfile", []byte(`FROM alpine@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`))
		if len(findingsSHA) != 0 {
			t.Errorf("expected 0 findings for OCI digest, got %d", len(findingsSHA))
		}

		findingsClient := s.ScanContent("config.json", []byte(`"client_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`))
		if len(findingsClient) != 0 {
			t.Errorf("expected 0 findings for client_id hash, got %d", len(findingsClient))
		}
	})
}

func TestScanner_SameLineDeduplication(t *testing.T) {
	a := trie.Build(trie.BuiltinSignatures)
	s := scanner.New(a, scanner.Options{
		EntropyThreshold: 3.5,
		MinSecretLength:  20,
	})

	// 1. Verify same token on different lines is NOT deduplicated (both reported)
	content := []byte("password = \"ghp_REALTOKEN1234567890abcdef\"\nother = \"ghp_REALTOKEN1234567890abcdef\"")
	findings := s.ScanContent("test.go", content)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings for duplicate tokens on different lines, got %d", len(findings))
	}
	if findings[0].Line != 1 || findings[1].Line != 2 {
		t.Errorf("expected lines 1 and 2, got %d and %d", findings[0].Line, findings[1].Line)
	}

	// 2. Verify same token on the same line is deduplicated (only 1 reported)
	contentSame := []byte("password = \"ghp_REALTOKEN1234567890abcdef\" token = \"ghp_REALTOKEN1234567890abcdef\"")
	findingsSame := s.ScanContent("test.go", contentSame)
	if len(findingsSame) != 1 {
		t.Errorf("expected 1 finding for duplicate tokens on the same line, got %d", len(findingsSame))
	}
}

