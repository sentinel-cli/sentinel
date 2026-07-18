//go:build !dashboard

package commands

import "github.com/spf13/cobra"

// NewDashboardCmd returns nil in standard community builds.
// The dashboard sub-command is available in the development build
// used internally for testing and iterating on the tool.
func NewDashboardCmd() *cobra.Command { return nil }
