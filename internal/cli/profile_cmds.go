package cli

import (
	"errors"
	"fmt"
	"os"

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
			return writeNew(out, profile.Template)
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

// writeNew creates path with 0600 and refuses to overwrite an existing file.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- operator-chosen output
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// replaceFile atomically replaces path with data (same directory temp file + rename), mode 0600.
func replaceFile(path string, data []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := writeNew(tmp, data); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
