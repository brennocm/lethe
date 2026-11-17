package cli

import (
	"fmt"
	"os"

	"lethe/internal/setup"

	"github.com/spf13/cobra"

	"lethe/internal/platform"
	"lethe/internal/profile"
)

func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "profile", Short: "Create and validate operation profiles"}
	var out string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a commented profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" || out == "-" {
				_, err := cmd.OutOrStdout().Write(profile.Template)
				return err
			}
			return setup.WriteNew(out, profile.Template)
		},
	}
	initCmd.Flags().StringVar(&out, "out", "", "output file (default stdout)")

	validate := &cobra.Command{
		Use:   "validate FILE",
		Short: "Validate a profile against the schema and semantic rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			op, err := platform.CurrentOperator(os.Getenv)
			if err != nil {
				return err
			}
			_, warns, err := profile.Load(args[0], op.Home)
			for _, w := range warns {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "WARN", w)
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "OK", args[0])
			return err
		},
	}
	cmd.AddCommand(initCmd, validate)
	return cmd
}
