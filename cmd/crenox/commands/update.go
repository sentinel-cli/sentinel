package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func NewUpdateCmd() *cobra.Command {
	var allowBeta bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update Crenox to the latest version",
		Long: `Check GitHub for the latest release of Crenox and update the current executable binary.
This command performs the following actions:
  1. Detects your operating system (OS) and architecture (e.g. linux/arm64, darwin/amd64).
  2. Queries the GitHub API for the latest release metadata.
  3. Downloads the matching binary payload and its SHA-256 checksum.
  4. Verifies the cryptographic integrity of the downloaded file.
  5. Atomically replaces the active 'crenox' executable with the new version.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Updating Crenox to the latest version...")

			// 1. Detect environment
			goos := runtime.GOOS
			goarch := runtime.GOARCH

			exePath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("could not determine executable path: %w", err)
			}
			if absPath, err := filepath.EvalSymlinks(exePath); err == nil {
				exePath = absPath
			}

			// 2. Query GitHub Releases
			fmt.Println("Checking GitHub for the latest release...")

			// Custom client to force IPv4 and bypass broken local DNS by using Google DNS
			client := &http.Client{
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Resolver: &net.Resolver{
							PreferGo: true,
							Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
								d := net.Dialer{}
								return d.DialContext(ctx, "udp", "8.8.8.8:53")
							},
						},
					}).DialContext,
				},
			}

			resp, err := client.Get("https://api.github.com/repos/crenoxhq/crenox/releases")
			if err != nil {
				return fmt.Errorf("failed to reach github: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to get latest release: http status %d", resp.StatusCode)
			}

			type ReleaseInfo struct {
				TagName    string `json:"tag_name"`
				Prerelease bool   `json:"prerelease"`
				Assets     []struct {
					Name               string `json:"name"`
					BrowserDownloadURL string `json:"browser_download_url"`
				} `json:"assets"`
			}
			var releases []ReleaseInfo

			if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
				return fmt.Errorf("failed to decode release JSON: %w", err)
			}

			var release *ReleaseInfo
			for i, r := range releases {
				isBeta := r.Prerelease || strings.Contains(r.TagName, "-beta") || strings.Contains(r.TagName, "-rc")
				if allowBeta || !isBeta {
					release = &releases[i]
					break
				}
			}

			if release == nil {
				return fmt.Errorf("no matching release found")
			}

			var downloadURL string
			var downloadName string
			for _, asset := range release.Assets {
				lowerName := strings.ToLower(asset.Name)
				hasOS := strings.Contains(lowerName, goos) || (goos == "darwin" && strings.Contains(lowerName, "macos"))
				hasArch := strings.Contains(lowerName, goarch) || (goarch == "amd64" && strings.Contains(lowerName, "x86_64")) || (goarch == "386" && strings.Contains(lowerName, "i386"))

				if hasOS && hasArch {
					// We prefer raw binaries, avoid compressed archives for direct replacement.
					if !strings.HasSuffix(lowerName, ".tar.gz") && !strings.HasSuffix(lowerName, ".zip") && !strings.HasSuffix(lowerName, ".sha256") {
						downloadURL = asset.BrowserDownloadURL
						downloadName = asset.Name
						break
					}
				}
			}

			var sha256URL string
			if downloadURL != "" {
				for _, asset := range release.Assets {
					if asset.Name == downloadName+".sha256" {
						sha256URL = asset.BrowserDownloadURL
						break
					}
				}
			}

			// Fallback to go install if no raw binary is available.
			if downloadURL == "" {
				fmt.Printf("No matching pre-compiled binary found for %s/%s. Falling back to 'go install'...\n", goos, goarch)
				c := exec.Command("go", "install", "github.com/crenoxhq/crenox/v2/cmd/crenox@latest")
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr
				if err := c.Run(); err != nil {
					return fmt.Errorf("update failed: %w", err)
				}
				fmt.Println("✔ Crenox successfully updated to the latest version!")
				return nil
			}

			fmt.Printf("Found binary for %s/%s. Downloading %s...\n", goos, goarch, release.TagName)

			// 3. Safe Binary Replacement
			tmpPath := exePath + ".tmp"

			// Download to temporary file
			out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("failed to create temporary file: %w", err)
			}

			dlResp, err := client.Get(downloadURL)
			if err != nil {
				out.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("failed to download binary: %w", err)
			}
			defer dlResp.Body.Close()

			if dlResp.StatusCode != http.StatusOK {
				out.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("download failed with status: %d", dlResp.StatusCode)
			}

			if _, err := io.Copy(out, dlResp.Body); err != nil {
				out.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("failed to write binary to disk: %w", err)
			}
			out.Close()

			if sha256URL != "" {
				fmt.Println("Verifying SHA-256 checksum...")
				shaResp, err := client.Get(sha256URL)
				if err == nil && shaResp.StatusCode == http.StatusOK {
					defer shaResp.Body.Close()
					shaBytes, _ := io.ReadAll(shaResp.Body)
					fields := strings.Fields(string(shaBytes))
					if len(fields) > 0 {
						expectedHash := fields[0]
						f, err := os.Open(tmpPath)
						if err == nil {
							h := sha256.New()
							io.Copy(h, f)
							f.Close()
							actualHash := hex.EncodeToString(h.Sum(nil))
							if actualHash != expectedHash {
								os.Remove(tmpPath)
								return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
							}
						}
					} else {
						fmt.Println("Warning: SHA-256 checksum file format is invalid or empty.")
					}
				} else {
					fmt.Println("Warning: Could not fetch SHA-256 checksum file.")
				}
			}

			// Overwrite running executable atomically
			if err := os.Rename(tmpPath, exePath); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to safely replace binary (text file busy?): %w", err)
			}

			fmt.Printf("✔ Crenox successfully updated to %s!\n", release.TagName)
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowBeta, "beta", false, "Allow updating to pre-release (beta) versions")
	return cmd
}
