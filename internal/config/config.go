// Package config defines the Sentinel configuration schema, default values,
// and the loader that merges the on-disk YAML with per-repo overrides.
package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// DefaultConfigFileName is the filename Sentinel looks for in the repository
// root and in the user's home directory.
const DefaultConfigFileName = ".sentinel.yaml"

// DefaultEntropyThreshold is the Shannon entropy value (bits per symbol)
// above which an alphanumeric string is flagged as a potential secret.
// Set to 4.5 to reduce false positives from dashed strings like 'dynamic-routing-mesh'.
const DefaultEntropyThreshold = 4.5

// DefaultMinSecretLength is the minimum token length before entropy analysis
// is applied.  Shorter tokens produce noisy entropy scores.
const DefaultMinSecretLength = 20

// DefaultMaxFileSizeBytes is the upper bound on a single file size that
// Sentinel will fully scan.  Files exceeding this are skipped with a warning.
const DefaultMaxFileSizeBytes = 10 * 1024 * 1024 // 10 MB

// Config is the top-level Sentinel configuration structure.
type Config struct {
	// EntropyThreshold overrides DefaultEntropyThreshold when set.
	EntropyThreshold float64 `yaml:"entropy_threshold"`

	// MinSecretLength overrides DefaultMinSecretLength when set.
	MinSecretLength int `yaml:"min_secret_length"`

	// MaxFileSizeBytes overrides DefaultMaxFileSizeBytes when set.
	MaxFileSizeBytes int64 `yaml:"max_file_size_bytes"`

	// ExcludePaths is a list of glob patterns (relative to repo root) that
	// Sentinel will never scan.  Useful for vendored code, fixtures, etc.
	ExcludePaths []string `yaml:"exclude_paths"`

	// ExcludeExtensions lists file extensions (including the dot) that are
	// always skipped.
	ExcludeExtensions []string `yaml:"exclude_extensions"`

	// AllowlistPatterns is a list of exact-match or glob patterns of string
	// values that are whitelisted even when they trigger detection.  Use with
	// extreme care.
	AllowlistPatterns []string `yaml:"allowlist_patterns"`

	// DisableTiers lets operators turn off specific detection tiers.
	DisableTiers DisableTiersConfig `yaml:"disable_tiers"`

	// Verbose enables debug-level output on stderr.
	Verbose bool `yaml:"verbose"`

	// FailFast stops scanning after the first finding (faster CI fail-loop).
	FailFast bool `yaml:"fail_fast"`

	// ScanBinaryFiles controls whether Sentinel attempts to scan binary files
	// after magic-byte detection.  Defaults to false (skip binaries).
	ScanBinaryFiles bool `yaml:"scan_binary_files"`

	// CustomSignatures lists user-defined Aho-Corasick matching rules.
	CustomSignatures []CustomSignature `yaml:"custom_signatures"`
}

// CustomSignature defines a user-specified signature loaded from config.
type CustomSignature struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Prefix      string `yaml:"prefix"`
	Severity    string `yaml:"severity"`
	Regex       string `yaml:"regex"`
}

// DisableTiersConfig gives operators fine-grained control over which tiers run.
type DisableTiersConfig struct {
	Trie    bool `yaml:"trie"`
	Entropy bool `yaml:"entropy"`
	Context bool `yaml:"context"`
}

// defaultConfig returns a Config populated with all production-safe defaults.
func defaultConfig() Config {
	return Config{
		EntropyThreshold: DefaultEntropyThreshold,
		MinSecretLength:  DefaultMinSecretLength,
		MaxFileSizeBytes: DefaultMaxFileSizeBytes,
		ExcludePaths: []string{
			"vendor/**",
			"node_modules/**",
			"*.lock",
			"go.sum",
			"package-lock.json",
		},
		ExcludeExtensions: []string{
			".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
			".woff", ".woff2", ".ttf", ".eot",
			".mp4", ".webm", ".mp3", ".ogg",
			".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
			".pdf", ".doc", ".docx", ".xls", ".xlsx",
			".exe", ".dll", ".so", ".dylib", ".a", ".o",
		},
		AllowlistPatterns: []string{},
		DisableTiers:      DisableTiersConfig{},
		Verbose:           false,
		FailFast:          false,
		ScanBinaryFiles:   false,
	}
}

// Load reads configuration from the given path, merging it on top of the
// built-in defaults.  If path is empty, Load searches the repository root
// (current directory) and the user home directory in that order.
// If no config file is found, the defaults are returned without error.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()

	candidate := path
	if candidate == "" {
		candidate = findConfigFile()
	}

	if candidate == "" {
		// No config file — pure defaults.
		return &cfg, nil
	}

	data, err := os.ReadFile(candidate)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &cfg, nil
		}
		return nil, err
	}

	// Unmarshal over the defaults so omitted fields keep their default values.
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return cfg.validate()
}

// findConfigFile searches the current working directory and the home directory.
func findConfigFile() string {
	cwd, err := os.Getwd()
	if err == nil {
		p := filepath.Join(cwd, DefaultConfigFileName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	home, err := os.UserHomeDir()
	if err == nil {
		p := filepath.Join(home, DefaultConfigFileName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// validate returns an error if the configuration contains impossible values,
// and clamps edge-case values to sane bounds.
func (c *Config) validate() (*Config, error) {
	if c.EntropyThreshold < 0 || c.EntropyThreshold > math.Log2(256) {
		return nil, errors.New("entropy_threshold must be between 0 and 8")
	}
	if c.MinSecretLength < 1 {
		c.MinSecretLength = 1
	}
	if c.MaxFileSizeBytes < 0 {
		c.MaxFileSizeBytes = DefaultMaxFileSizeBytes
	}

	// Validate custom user signatures
	for _, cs := range c.CustomSignatures {
		if cs.ID == "" {
			return nil, errors.New("custom signature 'id' cannot be empty")
		}
		if cs.Prefix == "" {
			return nil, errors.New("custom signature 'prefix' cannot be empty")
		}
		if cs.Regex != "" {
			if _, err := regexp.Compile(cs.Regex); err != nil {
				return nil, fmt.Errorf("custom signature %q has invalid regex: %w", cs.ID, err)
			}
		}
		switch cs.Severity {
		case "", "CRITICAL", "HIGH", "MEDIUM", "LOW":
			// Valid
		default:
			return nil, fmt.Errorf("custom signature %q has invalid severity (must be CRITICAL, HIGH, MEDIUM, or LOW)", cs.ID)
		}
	}

	return c, nil
}
