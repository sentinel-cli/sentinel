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
		Long: `Completely remove Sentinel, its pre-commit hooks, and global configurations from your system.
This command performs the following cleanup steps:
  1. Unsets the global git config 'core.hooksPath' if it was configured for Sentinel.
  2. Deletes the 'sentinel' executable binary from your system path.
  3. Removes the global configuration and hook folder located at '~/.config/sentinel'.
  4. Deletes the local pre-commit hook file '.git/hooks/pre-commit' in the current working directory.`,
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

			fmt.Println("✔ Sentinel has been completely uprooted from the system.")
			return nil
		},
	}
}
