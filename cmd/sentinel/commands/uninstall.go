package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

func NewUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Completely remove Sentinel from the system",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Uninstalling Sentinel...")

			// a) Unset global hooks path
			exec.Command("git", "config", "--global", "--unset", "core.hooksPath").Run()

			// b) Remove the binary itself
			removedBin := false
			exePath, err := os.Executable()
			if err == nil {
				// Ensure absolute path
				absPath, err := filepath.EvalSymlinks(exePath)
				if err == nil {
					exePath = absPath
				}
				if err := os.Remove(exePath); err == nil {
					removedBin = true
					fmt.Printf("Removed binary: %s\n", exePath)
				}
			}
			
			if !removedBin {
				fmt.Printf("Could not automatically remove the sentinel binary. You may need to remove it manually from your PATH.\n")
			}

			// c) Remove global hooks directory
			homeDir, err := os.UserHomeDir()
			if err == nil {
				os.RemoveAll(filepath.Join(homeDir, ".config", "sentinel"))
			}

			// c) Remove local pre-commit hook
			os.Remove(".git/hooks/pre-commit")

			fmt.Println("✅ Sentinel has been completely uprooted from the system.")
			return nil
		},
	}
}
