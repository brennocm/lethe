package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"lethe/internal/setup"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"lethe/internal/baseline"
	"lethe/internal/buildinfo"
)

// ErrNotImplemented marks features scheduled for a later milestone.
var ErrNotImplemented = errors.New("not implemented yet")

type secretFlags struct {
	fd         int
	workFactor int
}

func (s *secretFlags) register(cmd *cobra.Command) {
	cmd.Flags().IntVar(&s.fd, "passphrase-fd", -1, "read the passphrase from this file descriptor instead of the terminal")
	cmd.Flags().IntVar(&s.workFactor, "scrypt-work-factor", baseline.DefaultWorkFactor, "scrypt work factor")
	_ = cmd.Flags().MarkHidden("scrypt-work-factor")
}

func (s *secretFlags) source(cmd *cobra.Command) *passphraseSource {
	return &passphraseSource{fd: s.fd, stderr: cmd.ErrOrStderr()}
}

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "baseline", Short: "Create and inspect the encrypted identity baseline"}
	cmd.AddCommand(newBaselineCreateCmd(), newBaselineAddNetworkCmd(), newBaselineShowCmd())
	return cmd
}

func newBaselineCreateCmd() *cobra.Command {
	var manual, allowTunnel bool
	var out string
	var recipients []string
	var sec secretFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create the encrypted baseline (run without tunnel, on a known network)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			def := baseline.Network{}
			if !manual {
				var err error
				if def, err = onlineNetwork(cmd.Context(), cmd.ErrOrStderr(), allowTunnel); err != nil {
					return err
				}
			}
			b, err := baseline.New(time.Now(), buildinfo.Version)
			if err != nil {
				return err
			}
			baseline.CollectLocal("/", os.Getenv).Apply(b)
			pr := &prompter{in: bufio.NewReader(cmd.InOrStdin()), out: cmd.ErrOrStderr()}
			n, err := askNetworkWith(pr, def)
			if err != nil {
				return err
			}
			if err := b.AddNetwork(n); err != nil {
				return err
			}
			recs, err := parseRecipients(recipients)
			if err != nil {
				return err
			}
			pw, err := sec.source(cmd).read("Passphrase da baseline: ", true)
			if err != nil {
				return WithCode(ExitAuth, err)
			}
			defer wipeBytes(pw)
			enc, err := baseline.Encrypt(b, pw, sec.workFactor)
			if err != nil {
				return err
			}
			if err := setup.WriteNew(out, enc); err != nil {
				return err
			}
			if len(recs) > 0 {
				rec, err := baseline.EncryptRecovery(b, recs)
				if err != nil {
					return err
				}
				if err := setup.WriteNew(out+".recovery", rec); err != nil {
					return err
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "baseline written to %s (%d network)\n", out, len(b.Networks))
			return err
		},
	}
	cmd.Flags().BoolVar(&manual, "manual", false, "no network queries: answer every question on stdin")
	cmd.Flags().BoolVar(&allowTunnel, "allow-tunnel", false, "detect even with a tunnel up (the public IP will be the tunnel's)")
	cmd.Flags().StringVar(&out, "out", "baseline.age", "output file")
	cmd.Flags().StringSliceVar(&recipients, "recipient", nil, "institutional age recipient for a separate recovery copy (repeatable)")
	sec.register(cmd)
	return cmd
}

func newBaselineAddNetworkCmd() *cobra.Command {
	var manual, allowTunnel bool
	var sec secretFlags
	cmd := &cobra.Command{
		Use:   "add-network FILE",
		Short: "Add another known network to the baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			def := baseline.Network{}
			if !manual {
				var err error
				if def, err = onlineNetwork(cmd.Context(), cmd.ErrOrStderr(), allowTunnel); err != nil {
					return err
				}
			}
			pw, b, err := openBaseline(cmd, args[0], &sec)
			if err != nil {
				return err
			}
			defer wipeBytes(pw)
			pr := &prompter{in: bufio.NewReader(cmd.InOrStdin()), out: cmd.ErrOrStderr()}
			n, err := askNetworkWith(pr, def)
			if err != nil {
				return err
			}
			if err := b.AddNetwork(n); err != nil {
				return err
			}
			enc, err := baseline.Encrypt(b, pw, sec.workFactor)
			if err != nil {
				return err
			}
			if err := setup.ReplaceFile(args[0], enc); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "baseline updated: %d networks\n", len(b.Networks))
			return err
		},
	}
	cmd.Flags().BoolVar(&manual, "manual", false, "no network queries: answer every question on stdin")
	cmd.Flags().BoolVar(&allowTunnel, "allow-tunnel", false, "detect even with a tunnel up (the public IP will be the tunnel's)")
	sec.register(cmd)
	return cmd
}

func newBaselineShowCmd() *cobra.Command {
	var sec secretFlags
	cmd := &cobra.Command{
		Use:   "show FILE",
		Short: "Print the decrypted baseline (shows real identity values)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pw, b, err := openBaseline(cmd, args[0], &sec)
			if err != nil {
				return err
			}
			wipeBytes(pw)
			b.LogIdentity = "[oculta]"
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "ATENÇÃO: os valores abaixo identificam você. Não copie para fora desta máquina.")
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(b)
		},
	}
	sec.register(cmd)
	return cmd
}

func openBaseline(cmd *cobra.Command, path string, sec *secretFlags) ([]byte, *baseline.Baseline, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-chosen baseline
	if err != nil {
		return nil, nil, err
	}
	pw, err := sec.source(cmd).read("Passphrase da baseline: ", false)
	if err != nil {
		return nil, nil, WithCode(ExitAuth, err)
	}
	b, err := baseline.Decrypt(data, pw)
	if err != nil {
		wipeBytes(pw)
		if errors.Is(err, baseline.ErrWrongPassphrase) {
			return nil, nil, WithCode(ExitAuth, err)
		}
		return nil, nil, err
	}
	return pw, b, nil
}

// askNetworkWith asks the network questions; def holds what was detected (Enter keeps it).
func askNetworkWith(pr *prompter, def baseline.Network) (baseline.Network, error) {
	var n baseline.Network
	var err error
	q := func(label, d string) string {
		if err != nil {
			return ""
		}
		if d != "" {
			label = strings.TrimSuffix(label, ": ") + " [" + d + "]: "
		}
		var v string
		v, err = pr.ask(label)
		if v == "" {
			v = d
		}
		return v
	}
	asnDef := ""
	if def.ASN != 0 {
		asnDef = strconv.FormatUint(uint64(def.ASN), 10)
	}
	n.Name = q("Nome da rede (ex.: casa): ", def.Name)
	n.PublicIPv4 = q("IP público IPv4 (vazio se não souber): ", def.PublicIPv4)
	n.PublicIPv6 = q("IP público IPv6 (vazio se não houver): ", def.PublicIPv6)
	asn := q("ASN do provedor (só o número, vazio se não souber): ", asnDef)
	n.Provider = q("Nome do provedor: ", def.Provider)
	n.Resolvers = splitList(q("Resolvedores DNS do provedor (separados por vírgula): ", strings.Join(def.Resolvers, ",")))
	n.GatewayIP = q("IP do gateway (roteador): ", def.GatewayIP)
	n.GatewayMAC = q("MAC do gateway: ", def.GatewayMAC)
	n.SSIDs = splitList(q("SSIDs desta rede (separados por vírgula): ", strings.Join(def.SSIDs, ",")))
	if err != nil {
		return n, err
	}
	if asn != "" {
		v, perr := strconv.ParseUint(asn, 10, 32)
		if perr != nil {
			return n, fmt.Errorf("ASN %q is not a number", asn)
		}
		n.ASN = uint32(v)
	}
	return n, nil
}

func parseRecipients(in []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, s := range in {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, fmt.Errorf("--recipient %q: %w", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}
