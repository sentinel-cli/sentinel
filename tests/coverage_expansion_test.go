//go:build dashboard

package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crenoxhq/crenox/v2/internal/config"
	crenoxcontext "github.com/crenoxhq/crenox/v2/internal/context"
	"github.com/crenoxhq/crenox/v2/internal/entropy"
	"github.com/crenoxhq/crenox/v2/internal/git"
	"github.com/crenoxhq/crenox/v2/internal/reporter"
	"github.com/crenoxhq/crenox/v2/internal/scanner"
	"github.com/crenoxhq/crenox/v2/internal/trie"
	"github.com/crenoxhq/crenox/v2/internal/updater"
	"github.com/crenoxhq/crenox/v2/internal/web"
	"github.com/crenoxhq/crenox/v2/pkg/version"
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
		crenoxcontext.SafeFilePath,
		crenoxcontext.Decision(99),
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

	s := defaultScanner()
	findings := s.ScanContent("test.go", []byte("xyz"))
	if len(findings) != 0 {
		t.Error("expected 0 findings for xyz")
	}
}

func TestScanner_GiantComprehensiveSuite(t *testing.T) {
	a := trie.Build(trie.BuiltinSignatures)
	s := scanner.New(a, scanner.Options{
		EntropyThreshold: 3.5,
		MinSecretLength:  20,
	})

	t.Run("Exclusions", func(t *testing.T) {
		findingsPB := s.ScanContent("model.pb.go", []byte(`const token = "ghp_REALTOKEN1234567890abcdef";`))
		if len(findingsPB) != 0 {
			t.Errorf("expected 0 findings for model.pb.go, got %d", len(findingsPB))
		}

		findingsHCL := s.ScanContent(".terraform.lock.hcl", []byte(`h1:abcdef1234567890abcdef1234567890`))
		if len(findingsHCL) != 0 {
			t.Errorf("expected 0 findings for .terraform.lock.hcl, got %d", len(findingsHCL))
		}

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
}

// 4. Entropy tests
func TestEntropy_PackageSuite(t *testing.T) {
	if got := entropy.Shannon(nil); got != 0 {
		t.Errorf("Shannon(nil) = %v; want 0", got)
	}
	if got := entropy.Shannon([]byte("AAAAAA")); got != 0 {
		t.Errorf("Shannon(AAAAAA) = %v; want 0", got)
	}

	content := []byte("base64_hit = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\nhex_hit = \"a3f8c2d1e4b5a6f7c8d9e0f1a2b3c4d5\"")
	hits := entropy.Analyze(content, 3.0, 20)
	if len(hits) == 0 {
		t.Fatalf("expected hits from entropy.Analyze, got 0")
	}

	if !entropy.IsBase64Like("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") {
		t.Errorf("IsBase64Like valid = false")
	}
	if !entropy.IsHexLike("a3f8c2d1e4b5a6f7") {
		t.Errorf("IsHexLike valid = false")
	}
}

// 5. Config tests
func TestConfig_PackageSuite(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, ".crenox.yaml")
	yamlContent := `
entropy_threshold: 5.0
min_secret_length: 15
max_file_size_bytes: 1048576
`
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("config.Load returned error: %v", err)
	}
	if cfg.EntropyThreshold != 5.0 {
		t.Errorf("EntropyThreshold = %v; want 5.0", cfg.EntropyThreshold)
	}
}

// 6. Git tests
func TestGit_PackageSuite(t *testing.T) {
	if !git.IsInsideWorkTree() {
		t.Errorf("IsInsideWorkTree = false; expected true")
	}

	diff := []byte(`
diff --git a/test.go b/test.go
--- a/test.go
+++ b/test.go
+func newFunc() {}
`)
	added := git.FilterAddedLines(diff)
	if !bytes.Contains(added, []byte("func newFunc() {}")) {
		t.Errorf("FilterAddedLines failed: %s", string(added))
	}
}

// 7. Updater & Version tests
func TestUpdaterAndVersion_PackageSuite(t *testing.T) {
	ua := version.UserAgent()
	if len(ua) < 5 {
		t.Errorf("UserAgent() invalid format: %s", ua)
	}

	ch := updater.CheckForUpdateAsync()
	select {
	case <-ch:
	case <-time.After(1 * time.Second):
	}
}

// 8. Web & Server tests
func TestWeb_PackageSuite(t *testing.T) {
	db, err := web.NewDB()
	if err != nil || db == nil {
		t.Fatalf("web.NewDB failed: %v", err)
	}

	srv, _ := web.NewServer(db)
	if srv == nil {
		t.Fatalf("web.NewServer returned nil")
	}

	web.AddSystemLog("Test system log %s", "info")
}
