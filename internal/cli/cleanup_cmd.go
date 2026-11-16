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
// (spec §11.6). It never touches other tables, says what it removed and checks that nothing of
// lethe is left (spec §10.6 item 7).
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
				_, _ = fmt.Fprintln(out, "no lethe tables present: nada a remover; o lethe não está bloqueando a rede")
				return nil
			}
			for _, r := range removed {
				_, _ = fmt.Fprintf(out, "removed table %s\n", r)
			}
			left, err := guard.Leftovers(c)
			if err != nil {
				return err
			}
			if len(left) > 0 {
				return fmt.Errorf("lethe tables still present after cleanup: %v; reboot the machine to clear them", left)
			}
			_, _ = fmt.Fprintln(out, "a rede voltou ao estado de antes do lethe: nenhuma tabela lethe* restou e as outras tabelas não foram tocadas")
			return nil
		},
	}
}
