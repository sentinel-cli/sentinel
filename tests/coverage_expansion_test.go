package tests

import (
	"bytes"
	"testing"
	"time"

	sentinelcontext "github.com/sentinel-cli/sentinel/v2/internal/context"
	"github.com/sentinel-cli/sentinel/v2/internal/reporter"
	"github.com/sentinel-cli/sentinel/v2/internal/scanner"
)

// 1. Context tests
func TestContext_Suppression(t *testing.T) {
	if !sentinelcontext.IsSuppressed(sentinelcontext.SafeComment) {
		t.Error("expected SafeComment to be suppressed")
	}
	if sentinelcontext.IsSuppressed(sentinelcontext.Real) {
		t.Error("expected Real to NOT be suppressed")
	}

	// String representation of Decision
	decisions := []sentinelcontext.Decision{
		sentinelcontext.Real,
		sentinelcontext.SafeComment,
		sentinelcontext.SafeTestFile,
		sentinelcontext.SafeVariableName,
		sentinelcontext.SafePlaceholder,
		sentinelcontext.SafeUUID,
		sentinelcontext.SafeVersionString,
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
