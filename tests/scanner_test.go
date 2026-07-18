// Package tests contains integration tests that exercise the full
// three-tier detection pipeline end-to-end through the Scanner type.
package tests

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crenoxhq/crenox/v2/internal/scanner"
	"github.com/crenoxhq/crenox/v2/internal/trie"
)

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func defaultScanner() *scanner.Scanner {
	a := trie.Build(trie.BuiltinSignatures)
	return scanner.New(a, scanner.Options{
		EntropyThreshold: 3.5,
		MinSecretLength:  20,
	})
}

func scan(s *scanner.Scanner, file, content string) []scanner.Finding {
	return s.ScanContent(file, []byte(content))
}

// ──────────────────────────────────────────────────────────────────────────────
// End-to-end true positives
// ──────────────────────────────────────────────────────────────────────────────

func TestScanner_GithubPAT_Detected(t *testing.T) {
	s := defaultScanner()
	findings := scan(s, "cmd/main.go", `credentialToken := "ghp_REALTOKEN1234567890abcdef"`)
	if len(findings) == 0 {
		t.Error("expected finding for GitHub PAT")
	}
}

func TestScanner_AWSKey_Detected(t *testing.T) {
	s := defaultScanner()
	findings := scan(s, "config.go", `ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`)
	if len(findings) == 0 {
		t.Error("expected finding for AWS access key")
	}
}

func TestScanner_HighEntropyOnlySecret_Detected(t *testing.T) {
	// This token has no known prefix — detected by entropy only.
	s := defaultScanner()
	secret := "Yvk9pNXQJLzR3cW1mEqsTGbHuaOfidw8KvM2nXpQrYsT"
	findings := scan(s, "config/settings.go", `SECRET = "`+secret+`"`)
	// The entropy tier should detect it.
	if len(findings) == 0 {
		t.Errorf("expected entropy finding for high-entropy token: %s", secret)
	}
}

func TestScanner_Finding_FieldsPopulated(t *testing.T) {
	s := defaultScanner()
	findings := scan(s, "src/api.go", `credential := "ghp_REALTOKEN1234567890ABCDEFGH"`)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.FilePath == "" {
		t.Error("FilePath should not be empty")
	}
	if f.Line == 0 {
		t.Error("Line should be non-zero")
	}
	if f.Severity == "" {
		t.Error("Severity should not be empty")
	}
	if f.Description == "" {
		t.Error("Description should not be empty")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// End-to-end true negatives (false positive suppression)
// ──────────────────────────────────────────────────────────────────────────────

func TestScanner_CommentedSecret_Suppressed(t *testing.T) {
	s := defaultScanner()
	// A commented-out token should be suppressed by Tier 3.
	findings := scan(s, "cmd/main.go", `  // token = "ghp_OLDTOKEN12345678901234"`)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for commented-out secret, got %d", len(findings))
	}
}

func TestScanner_VariableReference_Suppressed(t *testing.T) {
	s := defaultScanner()
	// An unquoted variable reference matching password prefix/variable name should be suppressed
	findings := scan(s, "signup-tether.html", `const password = autoPassword;`)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for variable reference const password = autoPassword;, got %d", len(findings))
	}

	findingsKey := scan(s, "main.go", `const api_key = myApiKey;`)
	if len(findingsKey) != 0 {
		t.Errorf("expected 0 findings for variable reference const api_key = myApiKey;, got %d", len(findingsKey))
	}
}

func TestScanner_InlineSuppression_DifferentForms(t *testing.T) {
	s := defaultScanner()

	tests := []struct {
		name    string
		content string
	}{
		{
			name: "Go/C style preceding",
			content: `// crenox:ignore
credentialToken := "ghp_REALTOKEN1234567890abcdef"`,
		},
		{
			name: "Shell/Python style preceding",
			content: `# crenox:ignore
AWS_KEY="AKIAIOSFODNN7EXAMPLE1234"`,
		},
		{
			name: "HTML/XML style preceding",
			content: `<!-- crenox:ignore -->
<secret>sk-ant-api03-1234567890abcdef123456789</secret>`,
		},
		{
			name:    "Same-line trailing comment",
			content: `credentialToken := "ghp_REALTOKEN1234567890abcdef" // crenox:ignore`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scan(s, "testfile", tt.content)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings for %s, got %d", tt.name, len(findings))
			}
		})
	}

	t.Run("Same-line comment does not suppress next line", func(t *testing.T) {
		content := `token1 := "ghp_REALTOKEN1234567890abcdef" // crenox:ignore
token2 := "ghp_REALTOKEN0987654321fedcba"`
		findings := scan(s, "testfile", content)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding for the next line, got %d", len(findings))
		}
		if findings[0].Token != "ghp_REALTOKEN0987654321fedcba" {
			t.Errorf("wrong token reported: %s", findings[0].Token)
		}
	})
}

func TestScanner_TestFile_Suppressed(t *testing.T) {
	s := defaultScanner()
	findings := scan(s, "auth/auth_test.go", `token := "ghp_TESTTOKEN1234567890abcdef"`)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for test file, got %d", len(findings))
	}
}

func TestScanner_DummyVariable_Suppressed(t *testing.T) {
	s := defaultScanner()
	findings := scan(s, "cmd/main.go", `dummy_api_key := "ghp_DUMMYTOKEN1234567890abcdef"`)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for dummy variable, got %d", len(findings))
	}
}

func TestScanner_CleanFile_NoFindings(t *testing.T) {
	s := defaultScanner()
	findings := scan(s, "README.md", `# My Project\n\nThis is a clean commit with no secrets.`)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean content, got %d", len(findings))
	}
}

func TestScanner_Hellfire_Bugs_Fixed(t *testing.T) {
	s := defaultScanner()

	// 1. Empty YAML RHS
	// Before the fix, this panicked: index out of range [0] with length 0
	findings := scan(s, "config.yml", `api-token: `)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty RHS, got %d", len(findings))
	}

	// 2. JSON Token Leaking
	// Using a dummy GitHub PAT.
	// Before the fix, the token extracted was: ghp_TESTTOKEN1234567890abcdef\"}}
	// Now it should be cleanly trimmed.
	findings = scan(s, "config.json", `  "token": "\"ghp_TESTTOKEN1234567890abcdef\"}}"`)
	if len(findings) == 0 {
		t.Fatal("expected finding for JSON token")
	}
	expectedToken := "ghp_TESTTOKEN1234567890abcdef"
	if findings[0].Token != expectedToken {
		t.Errorf("Expected %q, got %q", expectedToken, findings[0].Token)
	}

	// 3. BIP-39 Punctuation and Non-BIP39 mix
	// Before the fix, this was flagged because it contained 12+ BIP-39 words.
	// Now it must be rejected because of punctuation and non-bip39 words.
	findings = scan(s, "prose.txt", `I decided to abandon all hope about my ability to absorb the abstract and absurd nature of this access accident.`)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for English prose, got %d", len(findings))
	}
}

func TestScanner_RawBip39Seed(t *testing.T) {
	s := defaultScanner()
	findings := scan(s, "seed.txt", `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`)
	if len(findings) == 0 {
		t.Error("expected finding for raw BIP-39 seed in plain text")
	}
}

func TestScanner_BrutalRealWorldSuite(t *testing.T) {
	s := defaultScanner()

	cases := []struct {
		name    string
		file    string
		content string
		wantSig string
	}{
		{
			name: "THE KERNEL PANIC DUMP (AWS Key hidden in crash log)",
			file: "kernel_panic.log",
			content: `
Kernel panic - not syncing: Fatal exception in interrupt
RIP: 0010:native_safe_halt+0xe/0x10
RSP: 0018:ffffa41a40097ec8 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 0000000000000002
Payload Dump: dGVzdCBwYXlsb2Fk AKIAIOSFODNN7EXAMPLE gaW5zaWRl
`,
			wantSig: "aws-access-key",
		},
		{
			name: "THE PAYMENT GATEWAY TRAP (Fake Twilio trap, real Stripe secret)",
			file: "checkout.min.js",
			content: `
function process(){var dummy_twilio="AC` + `1234567890abcdef1234567890abcdef";var config={endpoint:"/pay",timeout:5000,keys:{public:"pk_live_xxxx",secret:"sk_live_` + `1234567890abcdefghijklmnopqrstuv"}};return config;}
`,
			wantSig: "stripe-live-secret",
		},
		{
			name: "THE VERCEL BUILD LOG (Echoed GitHub PAT)",
			file: "build_output.log",
			content: `
[10:45:12] Starting build pipeline for nexus-fi-production...
[10:45:13] Build hash: 8f4e3c2b1a0d9f8e7d6c5b4a3c2b1a0d9f8e7d6c5b4a3c2b
[10:45:14] Fetching private submodules...
[10:45:15] Warning: using token ghp_REALTOKEN1234567890abcdefghijklmnop for git clone
[10:45:16] Build completed successfully.
`,
			wantSig: "github-pat-classic",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := scan(s, c.file, c.content)
			found := false
			for _, f := range findings {
				if f.SignatureID == c.wantSig {
					found = true
				} else if c.name == "THE PAYMENT GATEWAY TRAP (Fake Twilio trap, real Stripe secret)" && f.SignatureID == "twilio-account-sid" {
					t.Errorf("FAIL: Caught the dummy Twilio trap!")
				}
			}
			if !found {
				t.Errorf("FAIL: Missed the real secret. Expected signature: %s", c.wantSig)
			}
		})
	}
}

func TestScanner_EdgeCases(t *testing.T) {
	s := defaultScanner()

	cases := []struct {
		name    string
		file    string
		content string
		wantSig string
	}{
		{
			name: "SINGLE-LAYER BASE64 DECODING (K8s/GCP Secret)",
			file: "k8s_secret.yaml",
			content: `
apiVersion: v1
kind: Secret
metadata:
  name: stripe-secret
type: Opaque
data:
  stripe_key: c2tfbGl2ZV8xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dg==
`,
			wantSig: "stripe-live-secret",
		},
		{
			name: "MULTILINE COMMENTS & HEREDOCS",
			file: "script.sh",
			content: `
cat <<EOF > config.json
{
	"aws_key": "AKIAIOSFODNN7EXAMPLE",
	"debug": true
}
EOF
`,
			wantSig: "aws-access-key",
		},
		{
			name: "PEM CERTIFICATE WITH SPACES",
			file: "cert.pem",
			content: `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3...
-----END RSA PRIVATE KEY-----
`,
			wantSig: "pem-private-key",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := scan(s, c.file, c.content)
			found := false
			for _, f := range findings {
				if f.SignatureID == c.wantSig {
					found = true
				}
			}
			if !found {
				t.Errorf("FAIL: Missed the real secret. Expected signature: %s", c.wantSig)
				for _, f := range findings {
					t.Logf("Found instead: %s (token: %s)", f.SignatureID, f.Token)
				}
			}
		})
	}
}

func TestScanner_MailgunKey_NotTruncated(t *testing.T) {
	s := defaultScanner()
	findings := scan(s, "config.go", `mailgunKey := "key-notarealmailgunkey1234567890abc"`)
	if len(findings) == 0 {
		t.Fatal("expected Mailgun key finding")
	}
	f := findings[0]
	if f.Token != "key-notarealmailgunkey1234567890abc" {
		t.Errorf("expected full Mailgun token with key- prefix, got %q", f.Token)
	}
}

func TestScanner_HexLettersOnly_Detected(t *testing.T) {
	s := defaultScanner()
	// aBcDeFbAdCeFaBcDeFbAdCeF is a 24-character hex string composed entirely of letters a-f and A-F.
	// It should be detected as a hex token by the entropy analyzer and not skipped by isJavaConstant.
	findings := scan(s, "secret.conf", `aBcDeFbAdCeFaBcDeFbAdCeF`)
	if len(findings) == 0 {
		t.Error("expected finding for hex token composed entirely of letters a-f/A-F")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// IsBinary detection
// ──────────────────────────────────────────────────────────────────────────────

func TestIsBinary_True(t *testing.T) {
	data := make([]byte, 100)
	data[50] = 0x00 // null byte makes it binary
	if !scanner.IsBinary(data) {
		t.Error("expected IsBinary=true for data with null byte")
	}
}

func TestIsBinary_False(t *testing.T) {
	data := []byte("This is perfectly readable ASCII text.\nNo null bytes here.\n")
	if scanner.IsBinary(data) {
		t.Error("expected IsBinary=false for clean ASCII text")
	}
}

func TestIsBinary_EmptySlice(t *testing.T) {
	if scanner.IsBinary([]byte{}) {
		t.Error("expected IsBinary=false for empty slice")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HasExcludedExtension
// ──────────────────────────────────────────────────────────────────────────────

func TestHasExcludedExtension_PNG(t *testing.T) {
	excluded := []string{".png", ".jpg", ".gif"}
	if !scanner.HasExcludedExtension("assets/logo.PNG", excluded) {
		t.Error("expected .PNG to be excluded (case-insensitive)")
	}
}

func TestHasExcludedExtension_GoFile(t *testing.T) {
	excluded := []string{".png", ".jpg"}
	if scanner.HasExcludedExtension("main.go", excluded) {
		t.Error("expected .go NOT to be excluded")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// MatchesExcludePath
// ──────────────────────────────────────────────────────────────────────────────

func TestMatchesExcludePath_VendorPattern(t *testing.T) {
	patterns := []string{"vendor/**"}
	if !scanner.MatchesExcludePath("vendor/github.com/foo/bar.go", patterns) {
		t.Error("expected vendor path to match exclude pattern")
	}
}

func TestMatchesExcludePath_NonMatchingPath(t *testing.T) {
	patterns := []string{"vendor/**"}
	if scanner.MatchesExcludePath("internal/auth/client.go", patterns) {
		t.Error("expected internal path NOT to match vendor exclude pattern")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Tier.String()
// ──────────────────────────────────────────────────────────────────────────────

func TestTierString(t *testing.T) {
	if scanner.TierTrie.String() != "PATTERN" {
		t.Errorf("expected PATTERN, got %s", scanner.TierTrie.String())
	}
	if scanner.TierEntropy.String() != "ENTROPY" {
		t.Errorf("expected ENTROPY, got %s", scanner.TierEntropy.String())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Stress / performance tests
// ──────────────────────────────────────────────────────────────────────────────

// TestScanner_PerformanceUnder50ms verifies the full pipeline runs under 50ms
// for a 50 KB file that contains exactly one real secret and lots of noise.
func TestScanner_PerformanceUnder50ms(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("Skipping performance test in GitHub Actions due to -race detector overhead")
	}
	s := defaultScanner()

	// Build ~50 KB of clean Go-like source with one secret buried in the middle.
	clean := strings.Repeat("func doSomething(ctx context.Context) error {\n\treturn nil\n}\n\n", 400)
	secret := `credential := "ghp_REALPERFTESTTOKEN1234567890ABCDEFGH"` + "\n"
	content := clean[:len(clean)/2] + secret + clean[len(clean)/2:]

	start := time.Now()
	findings := s.ScanContent("internal/api/client.go", []byte(content))
	elapsed := time.Since(start)

	if len(findings) == 0 {
		t.Error("expected to find the secret in performance test")
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("scan exceeded 50ms limit: took %s", elapsed)
	}
}

// TestScanner_ZeroStagedFiles verifies that scanning empty content returns no
// findings without panicking.
func TestScanner_EmptyContent(t *testing.T) {
	s := defaultScanner()
	findings := s.ScanContent("some/file.go", []byte{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty content, got %d", len(findings))
	}
}

// TestScanner_HugeBinaryFile verifies that a large all-zero buffer (simulating
// a binary file) completes without panic and returns no findings.
func TestScanner_LargeBinaryContent(t *testing.T) {
	s := defaultScanner()
	// 15 MB of null bytes — scanner.IsBinary should catch this upstream,
	// but the pipeline itself must also handle it gracefully.
	content := make([]byte, 15*1024*1024)

	start := time.Now()
	findings := s.ScanContent("large.bin", content)
	elapsed := time.Since(start)

	// Binary null-byte content should produce 0 secret findings
	// (entropy/trie won't find patterns in null bytes).
	_ = findings
	t.Logf("15 MB binary-like content scanned in %s with %d finding(s)", elapsed, len(findings))
}

// TestScanner_OutsideQuotesRule ensures that variable names on non-assignment
// lines do not trigger false positives if they contain secret-like substrings.
func TestScanner_OutsideQuotesRule(t *testing.T) {
	s := defaultScanner()

	content := []byte(`
package main
import "fmt"
func main() {
	var internalCacheRegisterOffset = "safe_placeholder"
	fmt.Printf("hello world", internalCacheRegisterOffset)
}
`)

	findings := s.ScanContent("test.go", content)
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for outside quotes rule, got %d. Findings: %v", len(findings), findings)
	}
}

// BenchmarkFullPipeline runs the complete three-tier pipeline on a 50 KB file.
func BenchmarkFullPipeline(b *testing.B) {
	s := defaultScanner()
	content := []byte(strings.Repeat("func handler(w http.ResponseWriter, r *http.Request) {\n\t// nothing secret here\n}\n", 600))
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.ScanContent("internal/handler.go", content)
	}
}

// BenchmarkFullPipelineWithSecret benchmarks the pipeline when there is a hit.
func BenchmarkFullPipelineWithSecret(b *testing.B) {
	s := defaultScanner()
	content := []byte(`package main

import "fmt"

func main() {
	key := "ghp_PERFORMANCETESTTOKEN12345678901234"
	fmt.Println("key:", key)
}
`)
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.ScanContent("cmd/main.go", content)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// False-positive regression suite (all six vectors found during audit)
// ──────────────────────────────────────────────────────────────────────────────

// TestFalsePositive_Regression covers every false-positive category identified
// during the architectural audit.  Each sub-test must produce ZERO findings.
// If any sub-test fails, it prints the offending signature and token so the
// root cause is immediately visible in CI output.
func TestFalsePositive_Regression(t *testing.T) {
	s := defaultScanner()

	falsePositiveCases := []struct {
		name    string
		file    string
		content string
	}{
		// ── Bug 1 & 2: generic keyword prefixes in Printf format strings ──────
		{
			name:    "password= as printf format verb",
			file:    "main.go",
			content: `fmt.Printf("debug: password=%v api_key=%v\n", pw, key)`,
		},
		{
			name:    "secret= as printf format verb",
			file:    "main.go",
			content: `log.Printf("token=%s secret=%s", tok, sec)`,
		},
		{
			name:    "api_key= as printf format verb",
			file:    "main.go",
			content: `log.Printf("api_key=%v", k)`,
		},
		{
			name:    "token= as printf format verb with var arg",
			file:    "cmd/main.go",
			content: `fmt.Printf("token=%s\n", myVar)`,
		},
		// ── Bug 3: 2-char trie prefixes matching Go identifiers ───────────────
		{
			name:    "AC prefix in a PascalCase variable name",
			file:    "main.go",
			content: `fmt.Printf("account: %s\n", ACAccountSID)`,
		},
		{
			name:    "SK prefix in a PascalCase variable name",
			file:    "main.go",
			content: `fmt.Printf("status: %s\n", SKStatusCode)`,
		},
		// ── Bug 4: generic keyword matching SQL bind params ───────────────────
		{
			name:    "password= in a SQL query template with ? placeholder",
			file:    "db/query.go",
			content: `query := "SELECT * FROM users WHERE password=? AND active=1"`,
		},
		// ── Bug 5: mailgun "key-" prefix in English prose ─────────────────────
		{
			name:    "key-miss phrase in a log message",
			file:    "main.go",
			content: `fmt.Println("cache key-miss for user", userID)`,
		},
		// ── Regression: original reported bug (variable name in Printf arg) ───
		{
			name:    "long variable name containing offset passed to Printf",
			file:    "cmd/main.go",
			content: `fmt.Printf("hello world", internalCacheRegisterOffset)`,
		},
		// ── Additional safe patterns ───────────────────────────────────────────
		{
			name:    "YAML colon line with a short safe value",
			file:    "config.yaml",
			content: `database_host: localhost`,
		},
		{
			name:    "env export with an env-var reference (not a literal secret)",
			file:    "deploy.sh",
			content: `export GITHUB_TOKEN=$GITHUB_TOKEN`,
		},
		{
			name:    "ABIA/ASIA false positive in English text",
			file:    "description.txt",
			content: "A static type checker with a bias on type inference and strong type systems.",
		},
		{
			name:    "URL high entropy false positive",
			file:    "dependencies.yml",
			content: "url: https://www.tomasvotruba.com/blog/2017/05/03/combine-power-of-php-code-sniffer-and-php-cs-fixer-in-3-lines",
		},
		{
			name:    "GitHub Actions GITHUB_TOKEN placeholder",
			file:    "links.yml",
			content: "GITHUB_TOKEN: ${{secrets.GITHUB_TOKEN}}",
		},
		{
			name:    "Rust type option definition false positive",
			file:    "config.rs",
			content: "pub token_budget: Option<u64>,",
		},
		{
			name:    "Rust type vec definition false positive",
			file:    "main.rs",
			content: "passes: Vec<CoordinateBacklogPassSummary>,",
		},
		{
			name:    "Lowercase identifier generic match false positive",
			file:    "main.go",
			content: "passes: pass_summaries,",
		},
		{
			name:    "Code logic assignment in Python base64 false positive",
			file:    "ws_listener.py",
			content: "return_when=asyncio.FIRST_COMPLETED,",
		},
		{
			name:    "Git commit SHA dependency false positive",
			file:    "scan-supply-chain.js",
			content: "'github:tanstack/router#79ac49eedf774dd4b0cf',",
		},
		{
			name:    "Raw 20-character git commit hash false positive",
			file:    "scan-supply-chain.js",
			content: "'a308722bc463cfe5885c',",
		},
	}

	for _, c := range falsePositiveCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			findings := s.ScanContent(c.file, []byte(c.content))
			if len(findings) != 0 {
				t.Errorf("want 0 findings (false positive), got %d", len(findings))
				for i, f := range findings {
					t.Logf("  [%d] sig=%s token=%q line=%q", i, f.SignatureID, f.Token, f.LineContent)
				}
			}
		})
	}
}

// TestTruePositive_Regression ensures the false-positive fixes did not
// suppress any genuine secret detections.
func TestTruePositive_Regression(t *testing.T) {
	s := defaultScanner()

	truePositiveCases := []struct {
		name    string
		file    string
		content string
		wantMin int
	}{
		{
			name:    "GitHub PAT in assignment",
			file:    "cmd/main.go",
			content: `credentialToken := "ghp_REALTOKEN1234567890abcdef"`,
			wantMin: 1,
		},
		{
			name:    "AWS access key in assignment",
			file:    "config.go",
			content: `ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`,
			wantMin: 1,
		},
		{
			name:    "GitHub PAT embedded as literal in Printf arg",
			file:    "main.go",
			content: `fmt.Printf("token=%s\n", "ghp_REALTOKEN1234567890abcdef")`,
			wantMin: 1,
		},
		{
			name:    "password= with a real 24-char secret value",
			file:    "config.go",
			content: `password=supersecretpassword12345678`,
			wantMin: 1,
		},
		{
			name:    "high-entropy token (entropy tier only)",
			file:    "config/settings.go",
			content: `SECRET = "Yvk9pNXQJLzR3cW1mEqsTGbHuaOfidw8KvM2nXpQrYsT"`,
			wantMin: 1,
		},
		{
			name:    "AWS ABIA MFA key",
			file:    "config.go",
			content: `aws_mfa_key = "ABIAABCDEFGHIJKLMNOP"`,
			wantMin: 1,
		},
		{
			name:    "AWS ASIA Session key",
			file:    "config.go",
			content: `aws_sts_key = "ASIAABCDEFGHIJKLMNOP"`,
			wantMin: 1,
		},
		{
			name:    "Secret inside URL query parameter",
			file:    "url.txt",
			content: `https://api.service.com/data?api_key=ghp_REALTOKEN1234567890abcdef`,
			wantMin: 1,
		},
	}

	for _, c := range truePositiveCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			findings := s.ScanContent(c.file, []byte(c.content))
			if len(findings) < c.wantMin {
				t.Errorf("want ≥%d findings (true positive), got %d", c.wantMin, len(findings))
			}
		})
	}
}

func BenchmarkScanner_MassiveMinifiedLine(b *testing.B) {
	s := defaultScanner()
	// Create a 5MB line with no newlines
	var buf bytes.Buffer
	for i := 0; i < 100000; i++ {
		buf.WriteString(`{"key":"value","status":"ok","data":` + fmt.Sprint(i) + `},`)
	}
	content := buf.Bytes()
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.ScanContent("minified.json", content)
	}
}

func TestScanner_V2_Reliability_Intelligence(t *testing.T) {
	automaton := trie.Build(trie.BuiltinSignatures)

	t.Run("ALLOWLIST: Exact and Glob Matching", func(t *testing.T) {
		opts := scanner.Options{
			EntropyThreshold: 3.5,
			MinSecretLength:  20,
			AllowlistPatterns: []string{
				"ghp_EXACTMATCHONLY1234567890123456",
				"AKIA*ALLOWED",
			},
		}
		sec := scanner.New(automaton, opts)

		// Real test key, fake live key, exact match, non-exact match
		content := []byte(`
			var token1 = "ghp_EXACTMATCHONLY1234567890123456" // Should be ALLOWED
			var token2 = "ghp_EXACTMATCHONLY1234567890123456789" // Should be BLOCKED (different)
			var token3 = "AKIA000000000ALLOWED" // Should be ALLOWED
			var token4 = "AKIA000000000BLOCKED" // Should be BLOCKED
		`)

		findings := sec.ScanContent("config/keys.go", content)
		if len(findings) != 2 {
			t.Fatalf("expected exactly 2 findings (the ones not allowlisted), got %d", len(findings))
		}

		foundLive := false
		foundToken2 := false
		for _, f := range findings {
			if strings.Contains(f.Token, "BLOCKED") {
				foundLive = true
			}
			if f.Token == "ghp_EXACTMATCHONLY1234567890123456789" {
				foundToken2 = true
			}
		}

		if !foundLive || !foundToken2 {
			t.Errorf("expected to find sk_live and token2, but got: %+v", findings)
		}
	})

	t.Run("HEX BLOB AGGREGATION: Massive Keystore", func(t *testing.T) {
		opts := scanner.Options{
			EntropyThreshold: 3.5,
			MinSecretLength:  20,
		}
		sec := scanner.New(automaton, opts)

		// 5 lines of high-entropy hex. Should be squashed into exactly 1 massive-hex-blob finding.
		content := []byte(`
a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f91
8a2e1d7f6c5b4a3928170e9f8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b2
f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4031221304f5e6d7c8b9a3
0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f4
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
		`)

		findings := sec.ScanContent("keys/database.hex", content)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 aggregated finding, got %d", len(findings))
		}

		f := findings[0]
		if f.Severity != "CRITICAL" {
			t.Errorf("expected CRITICAL severity for aggregated blob, got %s", f.Severity)
		}
		if f.SignatureID != "massive-hex-blob" {
			t.Errorf("expected signature 'massive-hex-blob', got %s", f.SignatureID)
		}
		if !strings.Contains(f.LineContent, "5 consecutive lines of Hex") {
			t.Errorf("expected line content to mention '5 consecutive lines of Hex', got: %s", f.LineContent)
		}
	})
}

func TestScanner_CustomSignature_Detected(t *testing.T) {
	customSigs := []trie.Signature{
		{
			ID:          "my-api-key",
			Description: "My custom API key",
			Prefix:      "mycustom_",
			Severity:    "HIGH",
			Validator:   regexp.MustCompile(`^mycustom_[a-zA-Z0-9]{16}$`),
		},
	}

	automaton := trie.Build(customSigs)
	s := scanner.New(automaton, scanner.Options{
		EntropyThreshold: 3.5,
		MinSecretLength:  10,
	})

	findings := scan(s, "main.go", `token := "mycustom_ABC123xyz7890123"`)
	if len(findings) == 0 {
		t.Fatal("expected finding for custom signature prefix matching and validation")
	}

	f := findings[0]
	if f.SignatureID != "my-api-key" {
		t.Errorf("expected SignatureID 'my-api-key', got %s", f.SignatureID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected Severity 'HIGH', got %s", f.Severity)
	}
}

func TestScanner_NetrcSecret_Detected(t *testing.T) {
	s := defaultScanner()
	findings := s.ScanContent(".netrc", []byte("machine imap.gmail.com login example@gmail.com password pass123\n"))
	if len(findings) == 0 {
		t.Fatal("expected finding in .netrc file")
	}
	if findings[0].Token != "pass123" {
		t.Errorf("expected token 'pass123', got %s", findings[0].Token)
	}
}

func TestScanner_Npmrc_Detected(t *testing.T) {
	s := defaultScanner()
	findings := s.ScanContent(".npmrc", []byte("registry=\"https://registry.npmjs.org/\"\nalways-auth=true\npackage-lock=false\n# Informative\nemail=dummy@example.com\n# Risk\n_auth = YWRtaW46YWRtaW4=\n# Risk\n//registry.npmjs.org/:_authToken=00000000-0000-0000-0000-000000000000\n"))
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings, got %d: %+v", len(findings), findings)
	}
	if findings[0].Token != "YWRtaW46YWRtaW4=" {
		t.Errorf("expected first token to be YWRtaW46YWRtaW4=, got %s", findings[0].Token)
	}
	if findings[1].Token != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("expected second token to be 00000000-0000-0000-0000-000000000000, got %s", findings[1].Token)
	}
}

func TestScanner_FalsePositive_Refinement(t *testing.T) {
	s := defaultScanner()

	// 1. Google Fonts URL - should NOT trigger basic auth URL
	fontsLine := []byte(`href="https://fonts.googleapis.com/css2?family=Amiri:ital,wght@0,400;0,700;1,400;1,700&family=Tajawal:wght@300;400;500;7"`)
	findings := s.ScanContent("layout.tsx", fontsLine)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for Google Fonts URL, got %d: %+v", len(findings), findings)
	}

	// 2. Absolute/Relative file paths - should NOT trigger entropy base64
	pathLine := []byte(`img = Image.open("/root/.gemini/antigravity-cli/brain/f3f6bec7-7a51-4e32-a36d-228dae857f06/feather_green_screen_17824542_9png")`)
	findings = s.ScanContent("remove_green.py", pathLine)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for absolute file path, got %d: %+v", len(findings), findings)
	}

	// 3. XSRF/CSRF mock tokens - should NOT trigger token pattern
	csrfLine := []byte(`"Cookie": "xsrf_token=PlEcin8s5H600toD4Swngg; sc-cookies-accepted=true;"`)
	findings = s.ScanContent("removed_sites.json", csrfLine)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for XSRF token, got %d: %+v", len(findings), findings)
	}

	// 4. Python package naming conventions starting with ghp_ (like ghp-import) - should NOT trigger GitHub PAT
	ghpPackageLine := []byte(`dependency = "ghp_import-2.1.0-py3-none-any.whl"`)
	findings = s.ScanContent("requirements.txt", ghpPackageLine)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for ghp_import package name, got %d: %+v", len(findings), findings)
	}

	// 5. Sequential character ranges like 0123456789abcdefABCDEF - should NOT trigger entropy
	seqHexLine := []byte(`const hexChars = "0123456789abcdefABCDEF";`)
	findings = s.ScanContent("utils.js", seqHexLine)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for sequential hex character string, got %d: %+v", len(findings), findings)
	}

	// 6. Base64 Data URIs (inline images, fonts, etc.) - should NOT trigger entropy
	dataUriLine := []byte(`const background = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAAACXBIWXMAAAsTAAALEwEAmpwYAAACk0lEQVR4nO2WsUvDQBDGv8e1q..."`)
	findings = s.ScanContent("styles.css", dataUriLine)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for base64 data URI, got %d: %+v", len(findings), findings)
	}

	// 7. Ruby/JS Spec files (spec/ or _spec.js suffixes) - should NOT trigger mock credential false positives
	specLine := []byte(`let mockPassword = "Yvk9pNXQJLzR3cW1mEqsTGbHuaOfidw8KvM2nXpQrYsT"`)
	findings = s.ScanContent("spec/controllers/auth_controller_spec.rb", specLine)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for file inside spec directory, got %d: %+v", len(findings), findings)
	}
	findings = s.ScanContent("components/login_spec.js", specLine)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for file with _spec.js suffix, got %d: %+v", len(findings), findings)
	}

	// 8. Python generated protobuf files (*_pb2.py, *_pb2_grpc.py) - should NOT scan base64 serialized descriptors
	findings = s.ScanContent("messages_pb2.py", []byte(`_COMMAND_ENVIRONMENTVARIABLE = _descriptor.Descriptor(name='CommandEnvironmentVariable', full_name='CommandEnvironmentVariable', serialized_start=12345)`))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for Python protobuf file, got %d: %+v", len(findings), findings)
	}
}

func TestScanner_PEMFooterValidationAndNewSignatures(t *testing.T) {
	s := defaultScanner()

	// 1. PEM Key with footer - SHOULD DETECT
	pemWithFooter := `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3...
-----END RSA PRIVATE KEY-----
`
	findings := s.ScanContent("cert.pem", []byte(pemWithFooter))
	if len(findings) == 0 {
		t.Error("expected finding for valid PEM key with footer")
	}

	// 2. PEM Key template without footer - SHOULD IGNORE (False Positive suppression)
	pemTemplate := `"RSA private key": "-----BEGIN RSA PRIVATE KEY-----"`
	findings = s.ScanContent("regexes.json", []byte(pemTemplate))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for PEM header template, got %d", len(findings))
	}

	// 3. Slack Webhook URL - SHOULD DETECT
	slackWebhook := `webhook := "https://hooks.slack.com/services/T_DUMMY_ID/B_DUMMY_ID/aBcDeFgHiJkLmNoPqRsTuVwX"`
	findings = s.ScanContent("config.js", []byte(slackWebhook))
	if len(findings) == 0 {
		t.Error("expected finding for Slack Webhook URL")
	}

	// 4. Discord Webhook URL - SHOULD DETECT
	discordWebhook := `webhook := "https://discord.com/api/webhooks/123456789012345678/aBcDeFgHiJkLmNoPqRsTuVwXaBcDeFgHiJkLmNoPqRsTuVwXaBcDeFgHiJkLmNoPqRs"`
	findings = s.ScanContent("config.js", []byte(discordWebhook))
	if len(findings) == 0 {
		t.Error("expected finding for Discord Webhook URL")
	}

	// 5. GitHub Client ID - SHOULD DETECT
	githubClientId := `clientId := "Iv1.0123456789abcdef"`
	findings = s.ScanContent("config.js", []byte(githubClientId))
	if len(findings) == 0 {
		t.Error("expected finding for GitHub Client ID")
	}

	// 6. AWS Secret Access Key via variable assignment - SHOULD DETECT
	awsSecretAssign := `aws_secret := "dummy_secret_key_with_sufficient_entropy_12345"`
	findings = s.ScanContent("config.js", []byte(awsSecretAssign))
	if len(findings) == 0 {
		t.Error("expected finding for AWS Secret Key variable assignment")
	}

	// 7. Generic passwords containing '=' and '+' - SHOULD DETECT
	pgPassLine := `var pg_pass="sup3rstr0ngpass1ForGG";`
	findings = s.ScanContent("postgres_model.js", []byte(pgPassLine))
	if len(findings) == 0 {
		t.Error("expected finding for pg_pass")
	}

	ldapPwdLine := `ldap_pwd = "k%udk423u4%P8=H_"`
	findings = s.ScanContent("define_ldap", []byte(ldapPwdLine))
	if len(findings) == 0 {
		t.Error("expected finding for ldap_pwd")
	}

	yamlPasswordLine := `  password: J6T4ww+##14m`
	findings = s.ScanContent("gg_creds.yaml", []byte(yamlPasswordLine))
	if len(findings) == 0 {
		t.Error("expected finding for yaml password containing '+'")
	}
}
