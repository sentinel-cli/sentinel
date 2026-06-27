// Package tests contains exhaustive unit, boundary, and stress tests for
// the Sentinel detection pipeline components.
package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/sentinel-cli/sentinel/internal/trie"
)

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// buildDefaultAutomaton returns an automaton built from the production
// signature set.
func buildDefaultAutomaton() *trie.Automaton {
	return trie.Build(trie.BuiltinSignatures)
}

// search is a convenience wrapper.
func search(a *trie.Automaton, content string) []trie.Match {
	return a.Search([]byte(content))
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests — true positives
// ──────────────────────────────────────────────────────────────────────────────

func TestTrie_GithubPATClassic(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"`)
	assertAtLeastOneMatch(t, matches, "github-pat-classic")
}

func TestTrie_GithubPATFineGrained(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `export GITHUB_TOKEN=github_pat_11ABCDE_longrandombitshere`)
	assertAtLeastOneMatch(t, matches, "github-pat-fine")
}

func TestTrie_GitLabPAT(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `GITLAB_TOKEN=glpat-xXyYzZaAbBcC`)
	assertAtLeastOneMatch(t, matches, "gitlab-pat")
}

func TestTrie_AWSAccessKey(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`)
	assertAtLeastOneMatch(t, matches, "aws-access-key")
}

func TestTrie_AWSSTSKey(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `key: "ASIAIOSFODNN7EXAMPLE"`)
	assertAtLeastOneMatch(t, matches, "aws-sts")
}

func TestTrie_RSAPrivateKey(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...")
	assertAtLeastOneMatch(t, matches, "rsa-private-key")
}

func TestTrie_OpenSSHPrivateKey(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=")
	assertAtLeastOneMatch(t, matches, "openssh-private-key")
}

func TestTrie_OpenAIKey(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `openai_key = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"`)
	assertAtLeastOneMatch(t, matches, "openai-project-key")
}

func TestTrie_SlackBotToken(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `SLACK_BOT_TOKEN = "xoxb-12345-67890-abcdefghijklmnop"`)
	assertAtLeastOneMatch(t, matches, "slack-bot-token")
}

func TestTrie_StripeLiveKey(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `stripe.Key = "sk_live_fake_key_for_testing_purposes"`)
	assertAtLeastOneMatch(t, matches, "stripe-live-secret")
}

func TestTrie_HuggingFaceToken(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd`)
	assertAtLeastOneMatch(t, matches, "huggingface-token")
}

func TestTrie_VaultToken(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `VAULT_TOKEN=hvs.CAESINmit8yOJGZNY2dnYjhsU`)
	assertAtLeastOneMatch(t, matches, "vault-token")
}

func TestTrie_PostgresDSN(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `DSN="postgresql://user:supersecret@localhost/mydb"`)
	assertAtLeastOneMatch(t, matches, "postgres-dsn")
}

func TestTrie_CaseInsensitive(t *testing.T) {
	a := buildDefaultAutomaton()
	// "GHP_" in uppercase — should still match because the trie is case-insensitive.
	matches := search(a, `TOKEN = "GHP_ABCDEFGHabcdefgh123456789012"`)
	assertAtLeastOneMatch(t, matches, "github-pat-classic")
}

func TestTrie_MultipleMatchesSameLine(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, `x="ghp_abc123" and y="xoxb-12345-abc"`)
	if len(matches) < 2 {
		t.Errorf("expected at least 2 matches, got %d", len(matches))
	}
}

func TestTrie_MultipleMatchesMultipleLines(t *testing.T) {
	a := buildDefaultAutomaton()
	content := "line1=ghp_TOKEN123\nline2=xoxb-SLACKTOKEN\nline3=AKIAIOSFODNN7"
	matches := search(a, content)
	if len(matches) < 3 {
		t.Errorf("expected at least 3 matches across 3 lines, got %d", len(matches))
	}
}

func TestTrie_LineNumberTracking(t *testing.T) {
	a := buildDefaultAutomaton()
	content := "nothing here\ntoken=ghp_ABCDEFGH12345678\nmore stuff"
	matches := search(a, content)
	if len(matches) == 0 {
		t.Fatal("expected a match on line 2")
	}
	for _, m := range matches {
		if m.Sig.ID == "github-pat-classic" {
			if m.Line != 2 {
				t.Errorf("expected line 2, got %d", m.Line)
			}
			return
		}
	}
	t.Error("github-pat-classic match not found")
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests — true negatives (should NOT trigger)
// ──────────────────────────────────────────────────────────────────────────────

func TestTrie_NoMatchOnCleanContent(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := search(a, "Hello, world! This is a normal commit message.")
	count := 0
	for _, m := range matches {
		if m.Sig.ID != "bip39-word" {
			count++
		}
	}
	if count != 0 {
		t.Errorf("expected 0 matches on clean content, got %d", count)
	}
}

func TestTrie_NoMatchOnEmptyContent(t *testing.T) {
	a := buildDefaultAutomaton()
	matches := a.Search([]byte{})
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on empty content, got %d", len(matches))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Boundary tests
// ──────────────────────────────────────────────────────────────────────────────

func TestTrie_LargeInput(t *testing.T) {
	a := buildDefaultAutomaton()
	// 5 MB of random-looking text with one secret buried in the middle.
	chunk := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz\n", 10000)
	content := chunk[:len(chunk)/2] + "ghp_SECRETTOKEN1234567890123456" + chunk[len(chunk)/2:]

	start := time.Now()
	matches := a.Search([]byte(content))
	elapsed := time.Since(start)

	if len(matches) == 0 {
		t.Error("expected to find the secret in large input")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("large-input scan too slow: %s (limit: 500ms)", elapsed)
	}
}

func TestTrie_BinaryLikeInput(t *testing.T) {
	a := buildDefaultAutomaton()
	// Binary-like content with embedded secret.
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	// Embed a pattern.
	copy(buf[2000:], []byte("ghp_TESTTOKEN1234567890"))
	matches := a.Search(buf)
	if len(matches) == 0 {
		t.Error("should find secret even in byte-soup content")
	}
}

func TestTrie_PrefixAtEndOfInput(t *testing.T) {
	a := buildDefaultAutomaton()
	// Secret prefix at the very end of the buffer — no segfault.
	matches := a.Search([]byte("some padding ghp_"))
	// A partial match at EOF — may or may not fire depending on completeness.
	// The important thing is no panic.
	_ = matches
}

// ──────────────────────────────────────────────────────────────────────────────
// Performance benchmark
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkAutomatonBuild measures how fast the automaton is constructed.
func BenchmarkAutomatonBuild(b *testing.B) {
	for i := 0; i < b.N; i++ {
		trie.Build(trie.BuiltinSignatures)
	}
}

// BenchmarkSearch measures scan throughput for a 100 KB clean file.
func BenchmarkSearch(b *testing.B) {
	a := buildDefaultAutomaton()
	content := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog.\n", 2500))
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.Search(content)
	}
}

// BenchmarkSearchWithHit measures scan throughput when there is one match.
func BenchmarkSearchWithHit(b *testing.B) {
	a := buildDefaultAutomaton()
	base := strings.Repeat("normal code line here\n", 2500)
	content := []byte(base + "token=ghp_TESTTOKEN1234567890abcdef\n")
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.Search(content)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Assertion helpers
// ──────────────────────────────────────────────────────────────────────────────

func assertAtLeastOneMatch(t *testing.T, matches []trie.Match, sigID string) {
	t.Helper()
	for _, m := range matches {
		if m.Sig.ID == sigID {
			return
		}
	}
	t.Errorf("expected match with signature ID %q but got %d matches: %v",
		sigID, len(matches), matchIDs(matches))
}

func matchIDs(matches []trie.Match) []string {
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.Sig.ID
	}
	return ids
}
