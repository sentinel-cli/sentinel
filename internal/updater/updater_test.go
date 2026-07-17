package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crenoxhq/crenox/v2/pkg/version"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest  string
		current string
		want    bool
	}{
		{"v1.2.3", "v1.2.2", true},
		{"v1.3.0", "v1.2.9", true},
		{"v2.0.0", "v1.9.9", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.2", "v1.2.3", false},
		{"1.0.1", "1.0.0", true},
		{"v1.1", "v1.0", true},
		{"", "v1.0.0", false},
		{"v2.0.0", "dev", false}, // dev builds don't show update prompts
	}

	for _, tc := range cases {
		if got := isNewer(tc.latest, tc.current); got != tc.want {
			t.Errorf("isNewer(%q, %q) = %v; want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}

func TestCheckForUpdateAsync(t *testing.T) {
	// Set custom version to test update notification
	origVersion := version.Version
	version.Version = "1.0.0"
	defer func() { version.Version = origVersion }()

	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Create a valid cache file with a timestamp from 1 hour ago
	cacheDir := filepath.Join(tempDir, ".config", "crenox")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}

	cachePath := filepath.Join(cacheDir, "last_check.json")
	cache := cacheData{
		LastCheck:     time.Now().Add(-1 * time.Hour),
		LatestVersion: "2.0.0", // newer than 1.0.0
	}
	data, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("failed to marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}

	ch := CheckForUpdateAsync()
	select {
	case msg := <-ch:
		expected := "Notice: Crenox update (2.0.0) is available! Run 'crenox update' to upgrade."
		if msg != expected {
			t.Errorf("expected msg %q, got %q", expected, msg)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for update check result")
	}
}
