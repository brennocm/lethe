package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"lethe/internal/buildinfo"
	"lethe/internal/contracts"
	"lethe/internal/geo"
)

func newVersionCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, binary hash and geo database date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := buildinfo.Read("")
			if err != nil {
				return err
			}
			if db, err := geo.EmbeddedMMDB(); err == nil {
				info.GeoDBDate = db.Built().Format("2006-01-02")
			}
			out := cmd.OutOrStdout()
			if asJSON {
				if err := contracts.Validate("version", info); err != nil {
					return fmt.Errorf("internal: version output violates contract: %w", err)
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			dirty := ""
			if info.Modified {
				dirty = " (modified)"
			}
			_, err = fmt.Fprintf(out, "lethe %s\ncommit   %s%s\ngo       %s %s\nsha256   %s\ngeo db   %s\n",
				info.Version, info.Commit, dirty, info.GoVersion, info.Platform, info.BinarySHA, info.GeoDBDate)
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (schema: version)")
	return cmd
}
