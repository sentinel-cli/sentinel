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

	// IsAssignmentOrKeyword is pre-calculated to speed up parsing.
	IsAssignmentOrKeyword bool
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
	{ID: "aws-mfa-key", Description: "AWS MFA Device Serial", Prefix: "ABIA", Severity: "CRITICAL", Validator: regexp.MustCompile(`^ABIA[0-9A-Z]{16}$`)},
	{ID: "aws-sts", Description: "AWS STS Temporary Access Key", Prefix: "ASIA", Severity: "CRITICAL", Validator: regexp.MustCompile(`^ASIA[0-9A-Z]{16}$`)},

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

	{ID: "mailgun-key", Description: "Mailgun API Key", Prefix: "key-", Severity: "MEDIUM", Validator: regexp.MustCompile(`(?i)^key-[0-9a-f]{32}$`)},

	// ── NPM ───────────────────────────────────────────────────────────────────
	// Real npm automation/publish tokens: npm_ followed by 36+ alphanumeric chars.
	// Icon filenames like npm_icon.png, npm_ignored.png are rejected by the short length.
	{ID: "npm-token", Description: "npm Automation/Publish Token", Prefix: "npm_", Severity: "HIGH",
		Validator: regexp.MustCompile(`^npm_[a-zA-Z0-9]{36,}$`)},

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
	// Real Vercel API tokens contain lowercase letters.
	// ALL_UPPERCASE variables (e.g. VERCEL_OUTPUT_DIR) are rejected.
	{ID: "vercel-token", Description: "Vercel API Token", Prefix: "vercel_", Severity: "HIGH",
		Validator: regexp.MustCompile(`[a-z]`)},

	// ── Cloudflare ────────────────────────────────────────────────────────────
	// Real Cloudflare API tokens always contain at least one lowercase letter.
	// ALL_UPPERCASE C macros (e.g. IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) are rejected.
	{ID: "cloudflare-api-token", Description: "Cloudflare API Token", Prefix: "CF_", Severity: "MEDIUM",
		Validator: regexp.MustCompile(`(?i)^CF_[a-z0-9]+$`)},

	// ── DigitalOcean ─────────────────────────────────────────────────────────
	{ID: "digitalocean-token", Description: "DigitalOcean Personal Access Token", Prefix: "dop_v1_", Severity: "CRITICAL",
		Validator: regexp.MustCompile(`^dop_v1_[a-fA-F0-9]{64}$`)},

	// ── HuggingFace ──────────────────────────────────────────────────────────
	{ID: "huggingface-token", Description: "HuggingFace API Token", Prefix: "hf_", Severity: "HIGH",
		Validator: regexp.MustCompile(`^hf_[a-zA-Z0-9]{34}$`)},

	// ── Shopify ──────────────────────────────────────────────────────────────
	{ID: "shopify-custom-token", Description: "Shopify Custom App Token", Prefix: "shpca_", Severity: "HIGH",
		Validator: regexp.MustCompile(`^shpca_[a-fA-F0-9]{32}$`)},
	{ID: "shopify-private-token", Description: "Shopify Private App Token", Prefix: "shppa_", Severity: "HIGH",
		Validator: regexp.MustCompile(`^shppa_[a-fA-F0-9]{32}$`)},
	{ID: "shopify-access-token", Description: "Shopify App Access Token", Prefix: "shpat_", Severity: "CRITICAL",
		Validator: regexp.MustCompile(`^shpat_[a-fA-F0-9]{32}$`)},

	// ── Generic indicators ────────────────────────────────────────────────────
	{ID: "generic-password-key", Description: "Hardcoded password assignment", Prefix: "password", Severity: "MEDIUM"},
	{ID: "generic-secret-key", Description: "Hardcoded secret assignment", Prefix: "secret", Severity: "MEDIUM"},
	{ID: "generic-api-key", Description: "Hardcoded api_key assignment", Prefix: "api_key", Severity: "MEDIUM"},
	{ID: "generic-token-key", Description: "Hardcoded token assignment", Prefix: "token", Severity: "MEDIUM"},
	{ID: "generic-auth-key", Description: "Hardcoded auth credential assignment", Prefix: "auth", Severity: "MEDIUM"},
	{ID: "npm-auth-token", Description: "npm registry authentication token", Prefix: "_authToken", Severity: "CRITICAL",
		Validator: regexp.MustCompile(`^[A-Za-z0-9+/=_-]{20,}$`)},
	// npm-auth-key matches "_auth" in .npmrc files. Real npm _auth values are
	// pure base64 strings (letters, digits, +, /, =) with NO underscores.
	// Variable names like _AUTH_HIER_FENCE_RE contain underscores and uppercase,
	// so we reject tokens that have underscores OR are all-uppercase identifiers.
	{ID: "npm-auth-key", Description: "npm registry authentication credential", Prefix: "_auth", Severity: "HIGH",
		Validator: regexp.MustCompile(`^[A-Za-z0-9+/=]{8,}={0,2}$`)},

	// ── Framework specific secret keys ────────────────────────────────────────
	{ID: "django-secret-key", Description: "Django SECRET_KEY assignment", Prefix: "SECRET_KEY =", Severity: "HIGH"},
	{ID: "wordpress-auth-key", Description: "WordPress AUTH_KEY definition", Prefix: "AUTH_KEY", Severity: "HIGH"},
	{ID: "wordpress-secure-auth-key", Description: "WordPress SECURE_AUTH_KEY definition", Prefix: "SECURE_AUTH_KEY", Severity: "HIGH"},
	{ID: "wordpress-logged-in-key", Description: "WordPress LOGGED_IN_KEY definition", Prefix: "LOGGED_IN_KEY", Severity: "HIGH"},
	{ID: "wordpress-nonce-key", Description: "WordPress NONCE_KEY definition", Prefix: "NONCE_KEY", Severity: "HIGH"},
	{ID: "wordpress-auth-salt", Description: "WordPress AUTH_SALT definition", Prefix: "AUTH_SALT", Severity: "HIGH"},
	{ID: "wordpress-secure-auth-salt", Description: "WordPress SECURE_AUTH_SALT definition", Prefix: "SECURE_AUTH_SALT", Severity: "HIGH"},
	{ID: "wordpress-logged-in-salt", Description: "WordPress LOGGED_IN_SALT definition", Prefix: "LOGGED_IN_SALT", Severity: "HIGH"},
	{ID: "wordpress-nonce-salt", Description: "WordPress NONCE_SALT definition", Prefix: "NONCE_SALT", Severity: "HIGH"},

	// ── Certificates / Private Keys ───────────────────────────────────────────
	{ID: "pem-private-key", Description: "PEM Formatted Private Key", Prefix: "-----BEGIN ", Validator: regexp.MustCompile(`(?i)^-----BEGIN [A-Z ]*PRIVATE KEY-----`), Severity: "CRITICAL"},

	// ── Additional High-Value Signatures ──────────────────────────────────────
	{ID: "pypi-token", Description: "PyPI Upload Token", Prefix: "pypi-", Severity: "CRITICAL", Validator: regexp.MustCompile(`(?i)^pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,100}$`)},
	{ID: "google-client-secret", Description: "Google OAuth Client Secret", Prefix: "GOCSPX-", Severity: "CRITICAL", Validator: regexp.MustCompile(`^GOCSPX-[A-Za-z0-9-_]{24,40}$`)},
	{ID: "gitlab-runner-token", Description: "GitLab Runner Token", Prefix: "glrt-", Severity: "HIGH", Validator: regexp.MustCompile(`^glrt-[A-Za-z0-9-_]{20}$`)},
	{ID: "square-access-token", Description: "Square Access Token", Prefix: "sq0atp-", Severity: "CRITICAL", Validator: regexp.MustCompile(`^sq0atp-[A-Za-z0-9-_]{22}$`)},
	{ID: "putty-private-key", Description: "PuTTY Private Key", Prefix: "PuTTY-User-Key-File-", Severity: "CRITICAL"},
	{ID: "postgres-dsn", Description: "Postgres Connection String with Password", Prefix: "postgres://", Severity: "HIGH", Validator: regexp.MustCompile(`(?i)^postgres(?:ql)?://[^:\s/?#]+:[^@\s/?#]+@`)},
	{ID: "postgresql-dsn", Description: "Postgres Connection String with Password", Prefix: "postgresql://", Severity: "HIGH", Validator: regexp.MustCompile(`(?i)^postgres(?:ql)?://[^:\s/?#]+:[^@\s/?#]+@`)},
	{ID: "redis-dsn", Description: "Redis Connection String with Password", Prefix: "redis://", Severity: "HIGH", Validator: regexp.MustCompile(`(?i)^redis://[^:\s/?#]*:[^@\s/?#]+@`)},
	{ID: "mysql-dsn", Description: "MySQL Connection String with Password", Prefix: "mysql://", Severity: "HIGH", Validator: regexp.MustCompile(`(?i)^mysql://[^:\s/?#]+:[^@\s/?#]+@`)},
	{ID: "amqp-dsn", Description: "AMQP Connection String with Password", Prefix: "amqp://", Severity: "HIGH", Validator: regexp.MustCompile(`(?i)^amqps?://[^:\s/?#]+:[^@\s/?#]+@`)},
	{ID: "amqps-dsn", Description: "AMQP Connection String with Password", Prefix: "amqps://", Severity: "HIGH", Validator: regexp.MustCompile(`(?i)^amqps?://[^:\s/?#]+:[^@\s/?#]+@`)},
	{ID: "url-basic-auth", Description: "URL with Basic Auth Credentials", Prefix: "https://", Severity: "HIGH", Validator: regexp.MustCompile(`(?i)^https?://[^:\s/?#]+:[^@\s/?#]+@[a-zA-Z0-9.-]+`)},
	{ID: "url-basic-auth-http", Description: "URL with Basic Auth Credentials", Prefix: "http://", Severity: "HIGH", Validator: regexp.MustCompile(`(?i)^https?://[^:\s/?#]+:[^@\s/?#]+@[a-zA-Z0-9.-]+`)},
}

// ──────────────────────────────────────────────────────────────────────────────
// Aho-Corasick Automaton
// ──────────────────────────────────────────────────────────────────────────────

const alphabetSize = 128

// acNode is a single state in the Aho-Corasick automaton.
type acNode struct {
	children [alphabetSize]uint16
	fail     uint16
	output   []*Signature // signatures that end at this state
}

// Automaton is the compiled, immutable Aho-Corasick search machine.
type Automaton struct {
	nodes []acNode
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
	// Pre-allocate a reasonable capacity to avoid re-allocations
	nodes := make([]acNode, 1, 2048) // Index 0 is root

	// Phase 1: insert all prefixes into the trie.
	for i := range sigs {
		sig := &sigs[i]
		sig.IsAssignmentOrKeyword = isAssignmentOrKeyword(sig.Prefix)
		cur := uint16(0)
		for _, b := range []byte(strings.ToLower(sig.Prefix)) {
			if b >= alphabetSize {
				continue // Skip non-ASCII characters in prefixes if any exist
			}
			if nodes[cur].children[b] == 0 {
				nodes = append(nodes, acNode{})
				nodes[cur].children[b] = uint16(len(nodes) - 1)
			}
			cur = nodes[cur].children[b]
		}
		nodes[cur].output = append(nodes[cur].output, sig)
	}

	// Phase 2: BFS to compute failure links (classic Aho-Corasick construction).
	queue := make([]uint16, 0, alphabetSize)
	for c := 0; c < alphabetSize; c++ {
		if child := nodes[0].children[c]; child != 0 {
			nodes[child].fail = 0
			queue = append(queue, child)
		} else {
			nodes[0].children[c] = 0 // loop back to root for mismatches
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for c := 0; c < alphabetSize; c++ {
			child := nodes[cur].children[c]
			if child == 0 {
				// Shortcut: redirect miss to the failure-link's child.
				nodes[cur].children[c] = nodes[nodes[cur].fail].children[c]
				continue
			}
			nodes[child].fail = nodes[nodes[cur].fail].children[c]
			// Merge output of failure link into child.
			nodes[child].output = append(nodes[child].output, nodes[nodes[child].fail].output...)
			queue = append(queue, child)
		}
	}

	return &Automaton{nodes: nodes}
}

// Search scans content and returns all Signature matches found.
// It operates in O(n) time. The returned Match values contain Sig and Offset
// only — the caller is responsible for line-number tracking.
func (a *Automaton) Search(content []byte) []Match {
	var matches []Match
	cur := uint16(0)
	for i := 0; i < len(content); i++ {
		c := toLower(content[i])
		if c >= alphabetSize {
			cur = 0 // reset on non-ASCII characters
			continue
		}
		cur = a.nodes[cur].children[c]
		if len(a.nodes[cur].output) > 0 {
			for _, sig := range a.nodes[cur].output {
				matches = append(matches, Match{
					Sig:    sig,
					Offset: i,
				})
			}
		}
	}
	return matches
}

// toLower converts an ASCII byte to lowercase without a branch table.
// If b >= 128, it returns it as-is, which will be caught by the loop bounds check.
func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// isAssignmentOrKeyword checks case-insensitively if prefix contains '=' or ':',
// or matches one of the WordPress custom key/salt definitions,
// or is one of the generic keywords.
func isAssignmentOrKeyword(s string) bool {
	upper := strings.ToUpper(s)
	if upper == "PASSWORD" || upper == "SECRET" || upper == "API_KEY" || upper == "TOKEN" || upper == "AUTH" {
		return true
	}
	if strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "AUTH") {
		return true
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '=' || b == ':' {
			// Skip if it is part of a URL scheme separator (://)
			if b == ':' && i+2 < len(s) && s[i+1] == '/' && s[i+2] == '/' {
				continue
			}
			return true
		}
	}
	// Check for exact WordPress config keywords (case-insensitive)
	return strings.Contains(upper, "AUTH_KEY") ||
		strings.Contains(upper, "LOGGED_IN_KEY") ||
		strings.Contains(upper, "NONCE_KEY") ||
		strings.Contains(upper, "AUTH_SALT") ||
		strings.Contains(upper, "LOGGED_IN_SALT") ||
		strings.Contains(upper, "NONCE_SALT")
}
