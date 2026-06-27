package commands

import (
	"context"
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
	return &cobra.Command{
		Use:   "update",
		Short: "Update Sentinel to the latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Updating Sentinel to the latest version...")

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
			
			resp, err := client.Get("https://api.github.com/repos/sentinel-cli/sentinel/releases/latest")
			if err != nil {
				return fmt.Errorf("failed to reach github: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to get latest release: http status %d", resp.StatusCode)
			}

			var release struct {
				TagName string `json:"tag_name"`
				Assets  []struct {
					Name               string `json:"name"`
					BrowserDownloadURL string `json:"browser_download_url"`
				} `json:"assets"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
				return fmt.Errorf("failed to decode release JSON: %w", err)
			}

			var downloadURL string
			for _, asset := range release.Assets {
				lowerName := strings.ToLower(asset.Name)
				hasOS := strings.Contains(lowerName, goos) || (goos == "darwin" && strings.Contains(lowerName, "macos"))
				hasArch := strings.Contains(lowerName, goarch) || (goarch == "amd64" && strings.Contains(lowerName, "x86_64")) || (goarch == "386" && strings.Contains(lowerName, "i386"))
				
				if hasOS && hasArch {
					// We prefer raw binaries, avoid compressed archives for direct replacement.
					if !strings.HasSuffix(lowerName, ".tar.gz") && !strings.HasSuffix(lowerName, ".zip") && !strings.HasSuffix(lowerName, ".sha256") {
						downloadURL = asset.BrowserDownloadURL
						break
					}
				}
			}

			// Fallback to go install if no raw binary is available.
			if downloadURL == "" {
				fmt.Printf("No matching pre-compiled binary found for %s/%s. Falling back to 'go install'...\n", goos, goarch)
				c := exec.Command("go", "install", "github.com/sentinel-cli/sentinel/cmd/sentinel@latest")
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr
				if err := c.Run(); err != nil {
					return fmt.Errorf("update failed: %w", err)
				}
				fmt.Println("✅ Sentinel successfully updated to the latest version!")
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

			// Overwrite running executable atomically
			if err := os.Rename(tmpPath, exePath); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to safely replace binary (text file busy?): %w", err)
			}

			fmt.Printf("✅ Sentinel successfully updated to %s!\n", release.TagName)
			return nil
		},
	}
}
