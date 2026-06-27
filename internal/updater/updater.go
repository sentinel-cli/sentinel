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

	"github.com/sentinel-cli/sentinel/pkg/version"
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
				res <- fmt.Sprintf("⚠️ Notice: Sentinel update (%s) is available! Run 'sentinel update' to upgrade.", cache.LatestVersion)
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
			res <- fmt.Sprintf("⚠️ Notice: Sentinel update (%s) is available! Run 'sentinel update' to upgrade.", cache.LatestVersion)
		}
	}()
	return res
}

func isNewer(latest, current string) bool {
	if latest == "" || current == "dev" {
		return false
	}
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")
	
	lParts := strings.Split(latest, ".")
	cParts := strings.Split(current, ".")
	
	for i := 0; i < 3; i++ {
		l := 0
		c := 0
		if i < len(lParts) {
			l, _ = strconv.Atoi(lParts[i])
		}
		if i < len(cParts) {
			c, _ = strconv.Atoi(cParts[i])
		}
		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}
	return false
}
