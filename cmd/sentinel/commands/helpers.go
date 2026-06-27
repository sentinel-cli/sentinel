package commands

import (
	"fmt"
	"os"
	"os/exec"
)

// runCommand is a small helper shared across install.go and other commands
// that need to shell out without all the git-package scaffolding.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command %q failed: %w", name, err)
	}
	return nil
}
