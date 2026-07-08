package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sentinel-cli/sentinel/v2/pkg/version"
)

const (
	repoURL   = "https://api.github.com/repos/sentinel-cli/sentinel/releases/latest"
	cacheFile = ".config/sentinel/last_check.json"
)

type cacheData struct {
	LastCheck     time.Time `json:"last_check"`
	LatestVersion string    `json:"latest_version"`
}

func CheckForUpdateAsync() <-chan string {
	res := make(chan string, 1)
	go func() {
		defer close(res)

		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		cachePath := filepath.Join(home, cacheFile)

		var cache cacheData
		if data, err := os.ReadFile(cachePath); err == nil {
			_ = json.Unmarshal(data, &cache)
		}

		now := time.Now()
		if now.Sub(cache.LastCheck) < 24*time.Hour {
			if isNewer(cache.LatestVersion, version.Version) {
				res <- fmt.Sprintf("Notice: Sentinel update (%s) is available! Run 'sentinel update' to upgrade.", cache.LatestVersion)
			}
			return
		}

		client := &http.Client{Timeout: 500 * time.Millisecond}
		resp, err := client.Get(repoURL)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return
		}

		var release struct {
			TagName string `json:"tag_name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			return
		}

		cache.LastCheck = now
		cache.LatestVersion = release.TagName

		os.MkdirAll(filepath.Dir(cachePath), 0755)
		data, _ := json.Marshal(cache)
		os.WriteFile(cachePath, data, 0644)

		if isNewer(cache.LatestVersion, version.Version) {
			res <- fmt.Sprintf("Notice: Sentinel update (%s) is available! Run 'sentinel update' to upgrade.", cache.LatestVersion)
		}
	}()
	return res
}

func isNewer(latest, current string) bool {
	if latest == "" || current == "dev" || strings.HasPrefix(current, "dev-") || strings.Contains(current, "dirty") {
		return false
	}
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")

	// Helper to extract numeric part before any hyphen
	getNum := func(part string) int {
		if idx := strings.IndexByte(part, '-'); idx != -1 {
			part = part[:idx]
		}
		n, _ := strconv.Atoi(part)
		return n
	}

	lParts := strings.Split(latest, ".")
	cParts := strings.Split(current, ".")

	for i := 0; i < 3; i++ {
		l := 0
		c := 0
		if i < len(lParts) {
			l = getNum(lParts[i])
		}
		if i < len(cParts) {
			c = getNum(cParts[i])
		}
		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}
	
	// If the major.minor.patch are equal, check if current is a pre-release and latest is stable
	// e.g. latest = "2.0.5", current = "2.0.5-beta"
	if !strings.Contains(latest, "-") && strings.Contains(current, "-") {
		return true
	}
	
	return false
}
