package cli

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/google/nftables"
	"github.com/spf13/cobra"

	"lethe/internal/guard"
)

// newCleanupCmd removes every lethe* nftables table, with or without a running daemon
// (spec §11.6). It never touches other tables. Socket and runtime files arrive with M7.
func newCleanupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cleanup",
		Short: "Remove every lethe* nftables table (after a crash or an interrupted session)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := nftables.New()
			if err != nil {
				return fmt.Errorf("nftables: %w", err)
			}
			removed, err := guard.Cleanup(c)
			if err != nil {
				if errors.Is(err, syscall.EPERM) {
					return WithCode(ExitPrivileges, fmt.Errorf("%w (needs CAP_NET_ADMIN)", err))
				}
				return err
			}
			out := cmd.OutOrStdout()
			if len(removed) == 0 {
				_, _ = fmt.Fprintln(out, "no lethe tables present")
				return nil
			}
			for _, r := range removed {
				_, _ = fmt.Fprintf(out, "removed table %s\n", guard.FamilyName(r.Family)+" "+r.Name)
			}
			return nil
		},
	}
}
