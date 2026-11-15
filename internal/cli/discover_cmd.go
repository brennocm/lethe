package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/platform"
	"lethe/internal/profile"
)

func newDiscoverCmd() *cobra.Command {
	var asJSON, learn bool
	var profilePath string
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Show the discovered environment (tunnel, endpoints, egress interfaces, DNS) without arming",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if learn {
				return fmt.Errorf("%w: --learn needs the capture sensor (M8)", ErrNotImplemented)
			}
			opt := discovery.Options{Now: time.Now()}
			if profilePath != "" {
				op, err := platform.CurrentOperator(os.Getenv)
				if err != nil {
					return err
				}
				p, _, err := profile.Load(profilePath, op.Home)
				if err != nil {
					return err
				}
				opt.Overrides = discovery.Overrides{Egress: p.Network.EgressIfaces, Internal: p.Network.InternalIfaces}
				for _, e := range p.Egress.ParsedEndpoints {
					opt.ProfileEndpoints = append(opt.ProfileEndpoints, discovery.Endpoint{Addr: e.Addr, Proto: e.Proto})
				}
			}
			if r, err := discovery.NewDBusResolved(); err == nil {
				defer func() { _ = r.Close() }()
				opt.Resolved = r
			}
			s := discovery.Discover(discovery.NetlinkKernel{}, opt)
			if asJSON {
				if err := contracts.Validate("discover", s); err != nil {
					return fmt.Errorf("internal: discover output violates contract: %w", err)
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			return printSnapshot(cmd.OutOrStdout(), s)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (schema: discover)")
	cmd.Flags().BoolVar(&learn, "learn", false, "show destinations leaving the egress interfaces for 10s (learning mode)")
	cmd.Flags().StringVarP(&profilePath, "profile", "p", "", "apply interface overrides and endpoints from a profile")
	return cmd
}

func printSnapshot(w io.Writer, s discovery.Snapshot) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "INTERFACE\tCLASS\tTYPE\tSTATE\tADDRESSES")
	for _, i := range s.Ifaces {
		state := "down"
		if i.Up {
			state = "up"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", i.Name, i.Class, i.Type, state, strings.Join(i.Addrs, " "))
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintf(w, "\ncapture on: %s\n", orNone(s.CaptureIfaces))
	for _, t := range s.Tunnels {
		_, _ = fmt.Fprintf(w, "tunnel %s (%s)", t.Iface, t.Kind)
		if t.FwMark != 0 {
			_, _ = fmt.Fprintf(w, " fwmark 0x%x", t.FwMark)
		}
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintf(w, "endpoints: %s\n", orNone(s.Endpoints))
	if r := s.Routes.ProbeV4; r != nil {
		_, _ = fmt.Fprintf(w, "route to %s: via %s (%s)\n", r.Dst, r.Iface, r.Class)
	}
	if r := s.Routes.ProbeV6; r != nil {
		_, _ = fmt.Fprintf(w, "route to %s: via %s (%s)\n", r.Dst, r.Iface, r.Class)
	}
	_, _ = fmt.Fprintf(w, "resolv.conf nameservers: %s (stub: %v)\n", orNone(s.DNS.ResolvConf.Nameservers), s.DNS.ResolvConf.Stub)
	for _, l := range s.DNS.Resolved.Links {
		_, _ = fmt.Fprintf(w, "resolved %s: %s default_route=%v domains=%s\n", l.Iface, orNone(l.Servers), l.DefaultRoute, orNone(l.Domains))
	}
	if s.LegacyIPTables {
		_, _ = fmt.Fprintln(w, "WARN iptables-legacy tables are loaded: their rules are invisible to lethe (TUN-007)")
	}
	if len(s.Unavailable) > 0 {
		_, _ = fmt.Fprintf(w, "WARN unavailable sources (visibility gap): %s\n", strings.Join(s.Unavailable, ", "))
	}
	return nil
}

func orNone(xs []string) string {
	if len(xs) == 0 {
		return "(none)"
	}
	return strings.Join(xs, ", ")
}
