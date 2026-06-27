// Package tests contains unit, boundary, and benchmark tests for the
// Shannon entropy analysis engine (Tier 2).
package tests

import (
	"math"
	"strings"
	"testing"

	"github.com/sentinel-cli/sentinel/internal/entropy"
)

// ──────────────────────────────────────────────────────────────────────────────
// Shannon entropy unit tests
// ──────────────────────────────────────────────────────────────────────────────

func TestShannon_ZeroEntropyAllSame(t *testing.T) {
	e := entropy.Shannon([]byte("AAAAAAAAAAAAAAAA"))
	if e != 0.0 {
		t.Errorf("expected 0.0 entropy for all-same bytes, got %.6f", e)
	}
}

func TestShannon_MaxEntropyUniform(t *testing.T) {
	// 256 distinct bytes — maximum possible entropy = 8.0 bits.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	e := entropy.Shannon(data)
	if math.Abs(e-8.0) > 0.001 {
		t.Errorf("expected ~8.0 entropy for uniform distribution, got %.6f", e)
	}
}

func TestShannon_EmptyInput(t *testing.T) {
	e := entropy.Shannon([]byte{})
	if e != 0.0 {
		t.Errorf("expected 0.0 entropy for empty input, got %.6f", e)
	}
}

func TestShannon_RealBase64Secret(t *testing.T) {
	// A 32-byte cryptographically random secret, Base64-encoded.
	secret := "Yvk9pNXQJLzR3cW1mEqsTGbHuaOfidw8"
	e := entropy.Shannon([]byte(secret))
	if e < 4.0 {
		t.Errorf("expected high entropy (>4.0) for random secret, got %.6f", e)
	}
}

func TestShannon_LowEntropyWord(t *testing.T) {
	// A plain dictionary word — should have low entropy.
	e := entropy.Shannon([]byte("password"))
	if e > 3.5 {
		t.Errorf("expected low entropy (<3.5) for 'password', got %.6f", e)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Analyze — true positives (should be detected)
// ──────────────────────────────────────────────────────────────────────────────

func TestAnalyze_DetectsHighEntropyBase64(t *testing.T) {
	content := []byte(`SECRET_KEY = "Yvk9pNXQJLzR3cW1mEqsTGbHuaOfidw8KvM2nXpQrYsT"`)
	hits := entropy.Analyze(content, 3.5, 20)
	if len(hits) == 0 {
		t.Error("expected entropy hit for high-entropy Base64 string")
	}
}

func TestAnalyze_DetectsHighEntropyHex(t *testing.T) {
	// 64-char hex string — looks like a SHA-256 key.
	hexKey := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
	content := []byte("hash = " + hexKey)
	hits := entropy.Analyze(content, 3.5, 20)
	if len(hits) == 0 {
		t.Errorf("expected entropy hit for 64-char hex key: %s", hexKey)
	}
}

func TestAnalyze_DetectsAWSSecretKeyPattern(t *testing.T) {
	// AWS secret access keys are 40-char Base64-ish strings.
	awsSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	content := []byte("AWS_SECRET_ACCESS_KEY=" + awsSecret)
	hits := entropy.Analyze(content, 3.5, 20)
	if len(hits) == 0 {
		t.Errorf("expected entropy hit for AWS-like secret key")
	}
}

func TestAnalyze_MultipleHitsOnMultipleLines(t *testing.T) {
	content := []byte(
		"key1 = \"Yvk9pNXQJLzR3cW1mEqsTGbHuaOfidw8\"\n" +
			"key2 = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEX\"\n",
	)
	hits := entropy.Analyze(content, 3.5, 20)
	if len(hits) < 2 {
		t.Errorf("expected at least 2 entropy hits, got %d", len(hits))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Analyze — true negatives (should NOT be detected)
// ──────────────────────────────────────────────────────────────────────────────

func TestAnalyze_IgnoresShortTokens(t *testing.T) {
	// "tok" is 3 chars — too short for the default minLen of 20.
	content := []byte(`token = "tok"`)
	hits := entropy.Analyze(content, 3.5, 20)
	if len(hits) != 0 {
		t.Errorf("expected 0 hits for token below minLen, got %d", len(hits))
	}
}

func TestAnalyze_IgnoresLowEntropyStrings(t *testing.T) {
	// A repeated pattern — low entropy despite length.
	content := []byte(`key = "ABABABABABABABABABABABABABABABABAB"`)
	hits := entropy.Analyze(content, 3.5, 20)
	// ABAB... has very low entropy.
	for _, h := range hits {
		if h.Token == "ABABABABABABABABABABABABABABABABAB" {
			t.Errorf("should not have flagged low-entropy ABAB pattern")
		}
	}
}

func TestAnalyze_IgnoresVersionStrings(t *testing.T) {
	content := []byte(`version: "1.23.456-beta"`)
	// Version strings are short and low-entropy — should not fire.
	hits := entropy.Analyze(content, 3.5, 20)
	if len(hits) != 0 {
		t.Logf("Note: got %d hit(s); checking if any are the version string", len(hits))
		for _, h := range hits {
			if strings.Contains(h.Token, "1.23.456") {
				t.Errorf("version string should not be flagged as a secret")
			}
		}
	}
}

func TestAnalyze_EmptyContent(t *testing.T) {
	hits := entropy.Analyze([]byte{}, 3.5, 20)
	if len(hits) != 0 {
		t.Errorf("expected 0 hits on empty content, got %d", len(hits))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// IsBase64Like / IsHexLike helpers
// ──────────────────────────────────────────────────────────────────────────────

func TestIsBase64Like_True(t *testing.T) {
	if !entropy.IsBase64Like("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") {
		t.Error("expected IsBase64Like=true for full Base64 alphabet")
	}
}

func TestIsBase64Like_False(t *testing.T) {
	if entropy.IsBase64Like("hello world!@#$%") {
		t.Error("expected IsBase64Like=false for non-Base64 string")
	}
}

func TestIsHexLike_True(t *testing.T) {
	if !entropy.IsHexLike("deadbeef0123456789abcdef") {
		t.Error("expected IsHexLike=true for valid hex string")
	}
}

func TestIsHexLike_False(t *testing.T) {
	if entropy.IsHexLike("xyz123") {
		t.Error("expected IsHexLike=false for string with non-hex chars")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkShannonSmall benchmarks entropy calculation on a 32-byte input.
func BenchmarkShannonSmall(b *testing.B) {
	data := []byte("Yvk9pNXQJLzR3cW1mEqsTGbHuaOfidw8")
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entropy.Shannon(data)
	}
}

// BenchmarkShannonLarge benchmarks entropy calculation on a 4 KB input.
func BenchmarkShannonLarge(b *testing.B) {
	data := []byte(strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entropy.Shannon(data)
	}
}

// BenchmarkAnalyze benchmarks the full Analyze pipeline on a 100-line file.
func BenchmarkAnalyze(b *testing.B) {
	content := []byte(strings.Repeat(
		`normal_var = "justanormalvalue"`+"\n"+
			`key = "Yvk9pNXQJLzR3cW1mEqsTGbHuaOfidw8KvM2nXpQrYsT"`+"\n",
		50))
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entropy.Analyze(content, 3.5, 20)
	}
}
