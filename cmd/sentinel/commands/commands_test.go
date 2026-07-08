package commands

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewVersionCmd(t *testing.T) {
	cmd := NewVersionCmd()

	if cmd.Use != "version" {
		t.Errorf("expected Use 'version', got %q", cmd.Use)
	}

	if cmd.Short == "" || cmd.Long == "" {
		t.Errorf("expected Short and Long descriptions to be populated")
	}

	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	// Execute the command without arguments
	cmd.SetArgs([]string{})
	err := cmd.Execute()

	if err != nil {
		t.Fatalf("unexpected error running version command: %v", err)
	}

	// We can't capture the fmt.Printf easily without os.Stdout redirection,
	// but we can ensure it executes cleanly without panic.
}

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()

	if cmd.Use != "scan [path...]" {
		t.Errorf("expected Use 'scan [path...]', got %q", cmd.Use)
	}

	// Verify flags are registered
	flags := []string{"config", "format", "recursive", "verbose", "history", "output", "fail-fast"}
	for _, f := range flags {
		if flag := cmd.Flag(f); flag == nil {
			t.Errorf("expected flag %q to be defined", f)
		}
	}
}

func TestNewRunCmd(t *testing.T) {
	cmd := NewRunCmd()

	if cmd.Use != "run" {
		t.Errorf("expected Use 'run', got %q", cmd.Use)
	}

	// Verify flags are registered
	flags := []string{"config", "format", "verbose", "fail-fast"}
	for _, f := range flags {
		if flag := cmd.Flag(f); flag == nil {
			t.Errorf("expected flag %q to be defined", f)
		}
	}
}

func TestNewUpdateCmd(t *testing.T) {
	cmd := NewUpdateCmd()

	if !strings.HasPrefix(cmd.Use, "update") {
		t.Errorf("expected Use to start with 'update', got %q", cmd.Use)
	}
}

func TestNewInstallCmd(t *testing.T) {
	cmd := NewInstallCmd()

	if !strings.HasPrefix(cmd.Use, "install") {
		t.Errorf("expected Use to start with 'install', got %q", cmd.Use)
	}
}

func TestNewUninstallCmd(t *testing.T) {
	cmd := NewUninstallCmd()

	if !strings.HasPrefix(cmd.Use, "uninstall") {
		t.Errorf("expected Use to start with 'uninstall', got %q", cmd.Use)
	}
}
