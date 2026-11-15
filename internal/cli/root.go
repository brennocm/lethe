// Package cli wires every lethe subcommand. apps/lethe only calls Execute.
package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// Execute runs the CLI with args and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	root := newRoot(stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "lethe:", err)
	}
	return exitCode(err)
}

func newRoot(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "lethe",
		Short:         "Local OpSec leak monitor (IP, DNS, identity) for Linux",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newVersionCmd(), newVerifyCmd(), newReportCmd(), newProfileCmd(), newBaselineCmd(), newDiscoverCmd())
	return root
}
