// Package version exposes build-time metadata injected via ldflags.
// Build with:
//
//	go build -ldflags "-X github.com/sentinel-cli/sentinel/pkg/version.Version=v1.0.0 \
//	                    -X github.com/sentinel-cli/sentinel/pkg/version.Commit=$(git rev-parse --short HEAD) \
//	                    -X github.com/sentinel-cli/sentinel/pkg/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
package version

import (
	"runtime/debug"
)

// Version is the semantic version string, injected at link time.
var Version = "dev"

// Commit is the short git commit SHA, injected at link time.
var Commit = "unknown"

// Date is the build timestamp, injected at link time.
var Date = "unknown"

func init() {
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				Version = info.Main.Version
			}
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" {
					Commit = s.Value
					if len(Commit) > 7 {
						Commit = Commit[:7]
					}
				}
				if s.Key == "vcs.time" {
					Date = s.Value
				}
			}
		}
	}
}

// UserAgent returns a formatted user-agent string for HTTP calls (if any future
// remote telemetry opt-in is added).
func UserAgent() string {
	return "sentinel/" + Version + " (" + Commit + "; " + Date + ")"
}
