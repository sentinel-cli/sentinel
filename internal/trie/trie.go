// Package trie implements Tier 1 of the Sentinel detection pipeline:
// an Aho-Corasick automaton for ultra-fast, O(n) multi-pattern matching
// of known secret signatures across arbitrary byte streams.
//
// The automaton is built once at startup from the compiled signature set and
// then reused across all scanned files, making it allocation-free during the
// hot scan path.
package trie

import (
	"regexp"
	"strings"
)

// ──────────────────────────────────────────────────────────────────────────────
// Signature catalogue
// ──────────────────────────────────────────────────────────────────────────────

// Signature describes a known secret pattern.
type Signature struct {
	// ID is a unique, machine-readable identifier (e.g. "github-pat").
	ID string

	// Description is a human-readable label shown in the report.
	Description string

	// Prefix is the literal byte sequence that triggers a Tier 1 hit.
	Prefix string

	// Severity is one of "CRITICAL", "HIGH", "MEDIUM", "LOW".
	Severity string

	// Validator is an optional regex to strictly validate the extracted token.
	Validator *regexp.Regexp
}

// BuiltinSignatures is the exhaustive catalogue of known secret prefixes that
// Sentinel detects via the Aho-Corasick automaton.
var BuiltinSignatures = []Signature{
	// ── GitHub ────────────────────────────────────────────────────────────────
	{ID: "github-pat-classic", Description: "GitHub Personal Access Token (classic)", Prefix: "ghp_", Severity: "CRITICAL"},
	{ID: "github-oauth", Description: "GitHub OAuth Token", Prefix: "gho_", Severity: "CRITICAL"},
	{ID: "github-app-install", Description: "GitHub App Installation Token", Prefix: "ghs_", Severity: "CRITICAL"},
	{ID: "github-refresh", Description: "GitHub Refresh Token", Prefix: "ghr_", Severity: "CRITICAL"},
	{ID: "github-pat-fine", Description: "GitHub Fine-grained PAT", Prefix: "github_pat_", Severity: "CRITICAL"},

	// ── GitLab ────────────────────────────────────────────────────────────────
	{ID: "gitlab-pat", Description: "GitLab Personal Access Token", Prefix: "glpat-", Severity: "CRITICAL"},
	{ID: "gitlab-pipeline", Description: "GitLab Pipeline Trigger Token", Prefix: "glptt-", Severity: "HIGH"},
	{ID: "gitlab-runner", Description: "GitLab Runner Registration Token", Prefix: "GR1348941", Severity: "HIGH"},

	// ── AWS ───────────────────────────────────────────────────────────────────
	{ID: "aws-access-key", Description: "AWS Access Key ID", Prefix: "AKIA", Severity: "CRITICAL", Validator: regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`)},
	{ID: "aws-mfa-key", Description: "AWS MFA Device Serial", Prefix: "ABIA", Severity: "CRITICAL"},
	{ID: "aws-sts", Description: "AWS STS Temporary Access Key", Prefix: "ASIA", Severity: "CRITICAL"},

	// ── Google Cloud ──────────────────────────────────────────────────────────
	{ID: "gcp-service-account", Description: "GCP Service Account Key (JSON)", Prefix: "\"type\": \"service_account\"", Severity: "CRITICAL"},
	{ID: "gcp-api-key", Description: "Google API Key", Prefix: "AIzaSy", Severity: "HIGH"},
	{ID: "gcp-oauth-client", Description: "Google OAuth Client ID suffix", Prefix: ".apps.googleusercontent.com", Severity: "MEDIUM"},

	// ── Slack ─────────────────────────────────────────────────────────────────
	{ID: "slack-bot-token", Description: "Slack Bot Token", Prefix: "xoxb-", Severity: "CRITICAL"},
	{ID: "slack-user-token", Description: "Slack User Token", Prefix: "xoxp-", Severity: "CRITICAL"},
	{ID: "slack-workspace-token", Description: "Slack Workspace Access Token", Prefix: "xoxa-", Severity: "HIGH"},
	{ID: "slack-refresh-token", Description: "Slack Refresh Token", Prefix: "xoxr-", Severity: "HIGH"},

	// ── Stripe ────────────────────────────────────────────────────────────────
	{ID: "stripe-live-secret", Description: "Stripe Live Secret Key", Prefix: "sk_live_", Severity: "CRITICAL"},
	{ID: "stripe-live-restricted", Description: "Stripe Live Restricted Key", Prefix: "rk_live_", Severity: "CRITICAL"},
	{ID: "stripe-test-secret", Description: "Stripe Test Secret Key", Prefix: "sk_test_", Severity: "LOW"},

	// ── OpenAI ────────────────────────────────────────────────────────────────
	{ID: "openai-key", Description: "OpenAI API Key", Prefix: "sk-", Severity: "HIGH"},
	{ID: "openai-project-key", Description: "OpenAI Project API Key", Prefix: "sk-proj-", Severity: "CRITICAL"},

	// ── Anthropic ─────────────────────────────────────────────────────────────
	{ID: "anthropic-key", Description: "Anthropic API Key", Prefix: "sk-ant-", Severity: "CRITICAL"},

	// ── Twilio ────────────────────────────────────────────────────────────────
	{ID: "twilio-account-sid", Description: "Twilio Account SID", Prefix: "AC", Severity: "MEDIUM", Validator: regexp.MustCompile(`\bAC[a-f0-9]{32}\b`)},
	{ID: "twilio-auth-token", Description: "Twilio Auth Token prefix", Prefix: "SK", Severity: "MEDIUM", Validator: regexp.MustCompile(`^SK[a-zA-Z0-9]{32}$`)},

	// ── SendGrid ──────────────────────────────────────────────────────────────
	{ID: "sendgrid-key", Description: "SendGrid API Key", Prefix: "SG.", Severity: "HIGH", Validator: regexp.MustCompile(`^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$`)},

	// ── Mailgun ───────────────────────────────────────────────────────────────
	{ID: "mailgun-key", Description: "Mailgun API Key", Prefix: "key-", Severity: "MEDIUM"},

	// ── NPM ───────────────────────────────────────────────────────────────────
	{ID: "npm-token", Description: "npm Automation/Publish Token", Prefix: "npm_", Severity: "HIGH"},

	// ── JWT ───────────────────────────────────────────────────────────────────
	// eyJ is the base64url encoding of '{"' — the start of every JWT header.
	// Strict 3-part dot-separated validator prevents false positives.
	{ID: "jwt", Description: "JSON Web Token (JWT)", Prefix: "eyJ", Severity: "HIGH",
		Validator: regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{10,250}\.[A-Za-z0-9_-]{10,500}\.[A-Za-z0-9_-]{10,250}$`)},

	// ── Private Keys ──────────────────────────────────────────────────────────
	{ID: "rsa-private-key", Description: "RSA Private Key (PEM)", Prefix: "-----BEGIN RSA PRIVATE KEY-----", Severity: "CRITICAL"},
	{ID: "ec-private-key", Description: "EC Private Key (PEM)", Prefix: "-----BEGIN EC PRIVATE KEY-----", Severity: "CRITICAL"},
	{ID: "openssh-private-key", Description: "OpenSSH Private Key", Prefix: "-----BEGIN OPENSSH PRIVATE KEY-----", Severity: "CRITICAL"},
	{ID: "pkcs8-private-key", Description: "PKCS#8 Private Key (PEM)", Prefix: "-----BEGIN PRIVATE KEY-----", Severity: "CRITICAL"},
	{ID: "pgp-private-key", Description: "PGP Private Key Block", Prefix: "-----BEGIN PGP PRIVATE KEY BLOCK-----", Severity: "CRITICAL"},
	{ID: "dsa-private-key", Description: "DSA Private Key (PEM)", Prefix: "-----BEGIN DSA PRIVATE KEY-----", Severity: "CRITICAL"},

	// ── Database Credentials ─────────────────────────────────────────────────
	{ID: "postgres-dsn", Description: "PostgreSQL DSN with credentials", Prefix: "postgresql://", Severity: "HIGH"},
	{ID: "mysql-dsn", Description: "MySQL DSN with credentials", Prefix: "mysql://", Severity: "HIGH"},
	{ID: "mongodb-dsn", Description: "MongoDB connection string", Prefix: "mongodb+srv://", Severity: "HIGH"},
	{ID: "mongodb-dsn-plain", Description: "MongoDB connection string (plain)", Prefix: "mongodb://", Severity: "HIGH"},
	{ID: "redis-dsn", Description: "Redis connection string with password", Prefix: "redis://:@", Severity: "MEDIUM"},

	// ── HashiCorp Vault ───────────────────────────────────────────────────────
	{ID: "vault-token", Description: "HashiCorp Vault Token", Prefix: "hvs.", Severity: "CRITICAL"},
	{ID: "vault-batch-token", Description: "HashiCorp Vault Batch Token", Prefix: "hvb.", Severity: "CRITICAL"},

	// ── Vercel ────────────────────────────────────────────────────────────────
	{ID: "vercel-token", Description: "Vercel API Token", Prefix: "vercel_", Severity: "HIGH"},

	// ── Cloudflare ────────────────────────────────────────────────────────────
	{ID: "cloudflare-api-token", Description: "Cloudflare API Token", Prefix: "CF_", Severity: "MEDIUM"},

	// ── DigitalOcean ─────────────────────────────────────────────────────────
	{ID: "digitalocean-token", Description: "DigitalOcean Personal Access Token", Prefix: "dop_v1_", Severity: "CRITICAL"},

	// ── HuggingFace ──────────────────────────────────────────────────────────
	{ID: "huggingface-token", Description: "HuggingFace API Token", Prefix: "hf_", Severity: "HIGH"},

	// ── Shopify ──────────────────────────────────────────────────────────────
	{ID: "shopify-custom-token", Description: "Shopify Custom App Token", Prefix: "shpca_", Severity: "HIGH"},
	{ID: "shopify-private-token", Description: "Shopify Private App Token", Prefix: "shppa_", Severity: "HIGH"},
	{ID: "shopify-access-token", Description: "Shopify App Access Token", Prefix: "shpat_", Severity: "CRITICAL"},

	// ── Generic password indicators ───────────────────────────────────────────
	{ID: "generic-password-key", Description: "Hardcoded password assignment", Prefix: "password=", Severity: "MEDIUM"},
	{ID: "generic-secret-key", Description: "Hardcoded secret assignment", Prefix: "secret=", Severity: "MEDIUM"},
	{ID: "generic-api-key", Description: "Hardcoded api_key assignment", Prefix: "api_key=", Severity: "MEDIUM"},
	{ID: "generic-token-key", Description: "Hardcoded token assignment", Prefix: "token=", Severity: "MEDIUM"},

	// ── Certificates / Private Keys ───────────────────────────────────────────
	{ID: "pem-private-key", Description: "PEM Formatted Private Key", Prefix: "-----BEGIN ", Validator: regexp.MustCompile(`(?i)^-----BEGIN [A-Z ]*PRIVATE KEY-----`), Severity: "CRITICAL"},
}

// ──────────────────────────────────────────────────────────────────────────────
// Aho-Corasick Automaton
// ──────────────────────────────────────────────────────────────────────────────

const alphabetSize = 256

// acNode is a single state in the Aho-Corasick automaton.
type acNode struct {
	children [alphabetSize]*acNode
	fail     *acNode
	output   []*Signature // signatures that end at this state
}

// Automaton is the compiled, immutable Aho-Corasick search machine.
type Automaton struct {
	root *acNode
}

// Match records a single pattern hit found during a scan.
type Match struct {
	// Sig is the Signature that triggered.
	Sig *Signature

	// Offset is the byte position of the end of the match within the scanned
	// slice.
	Offset int

	// Line is the 1-indexed line number of the match within the scanned content.
	Line int

	// LineContent is the full text of the matching line (up to 512 bytes).
	LineContent []byte
}

// Build constructs an Aho-Corasick automaton from the given signatures.
// It lowercases prefixes so that matching is case-insensitive.
func Build(sigs []Signature) *Automaton {
	root := &acNode{}

	// Phase 1: insert all prefixes into the trie.
	for i := range sigs {
		sig := &sigs[i]
		cur := root
		for _, b := range []byte(strings.ToLower(sig.Prefix)) {
			if cur.children[b] == nil {
				cur.children[b] = &acNode{}
			}
			cur = cur.children[b]
		}
		cur.output = append(cur.output, sig)
	}

	// Phase 2: BFS to compute failure links (classic Aho-Corasick construction).
	queue := make([]*acNode, 0, 256)
	for c := 0; c < alphabetSize; c++ {
		if root.children[c] != nil {
			root.children[c].fail = root
			queue = append(queue, root.children[c])
		} else {
			root.children[c] = root // loop back to root for mismatches
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for c := 0; c < alphabetSize; c++ {
			child := cur.children[c]
			if child == nil {
				// Shortcut: redirect miss to the failure-link's child.
				cur.children[c] = cur.fail.children[c]
				continue
			}
			child.fail = cur.fail.children[c]
			// Merge output of failure link into child.
			child.output = append(child.output, child.fail.output...)
			queue = append(queue, child)
		}
	}

	return &Automaton{root: root}
}

// Search scans content and returns all Matches.  The scan is O(n + m) where n
// is the content length and m is the number of matches.
func (a *Automaton) Search(content []byte) []Match {
	var matches []Match

	lineNum := 1
	lineStart := 0

	cur := a.root
	for i, b := range content {
		if b == '\n' {
			lineNum++
			lineStart = i + 1
		}
		c := toLower(b)
		cur = cur.children[c]
		if len(cur.output) > 0 {
			// Find the end of the line for LineContent
			end := i
			for end < len(content) && content[end] != '\n' {
				end++
			}
			
			lineContent := content[lineStart:end]
			if len(lineContent) > 512 {
				lineContent = lineContent[:512]
			}

			for _, sig := range cur.output {
				matches = append(matches, Match{
					Sig:         sig,
					Offset:      i,
					Line:        lineNum,
					LineContent: lineContent,
				})
			}
		}
	}
	return matches
}



// toLower converts an ASCII byte to lowercase without a branch table.
func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
