package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

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
	var manual bool
	var out string
	var recipients []string
	var sec secretFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create the encrypted baseline (run without tunnel, on a known network)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !manual {
				return fmt.Errorf("%w: online baseline (public IP + offline ASN) arrives with the geo database (M11); use --manual", ErrNotImplemented)
			}
			b, err := baseline.New(time.Now(), buildinfo.Version)
			if err != nil {
				return err
			}
			baseline.CollectLocal("/", os.Getenv).Apply(b)
			pr := &prompter{in: bufio.NewReader(cmd.InOrStdin()), out: cmd.ErrOrStderr()}
			n, err := askNetwork(pr)
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
			if err := writeNew(out, enc); err != nil {
				return err
			}
			if len(recs) > 0 {
				rec, err := baseline.EncryptRecovery(b, recs)
				if err != nil {
					return err
				}
				if err := writeNew(out+".recovery", rec); err != nil {
					return err
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "baseline written to %s (%d network)\n", out, len(b.Networks))
			return err
		},
	}
	cmd.Flags().BoolVar(&manual, "manual", false, "no network queries: answer the questions on stdin")
	cmd.Flags().StringVar(&out, "out", "baseline.age", "output file")
	cmd.Flags().StringSliceVar(&recipients, "recipient", nil, "institutional age recipient for a separate recovery copy (repeatable)")
	sec.register(cmd)
	return cmd
}

func newBaselineAddNetworkCmd() *cobra.Command {
	var manual bool
	var sec secretFlags
	cmd := &cobra.Command{
		Use:   "add-network FILE",
		Short: "Add another known network to the baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !manual {
				return fmt.Errorf("%w: online mode arrives in M11; use --manual", ErrNotImplemented)
			}
			pw, b, err := openBaseline(cmd, args[0], &sec)
			if err != nil {
				return err
			}
			defer wipeBytes(pw)
			pr := &prompter{in: bufio.NewReader(cmd.InOrStdin()), out: cmd.ErrOrStderr()}
			n, err := askNetwork(pr)
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
			if err := replaceFile(args[0], enc); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "baseline updated: %d networks\n", len(b.Networks))
			return err
		},
	}
	cmd.Flags().BoolVar(&manual, "manual", false, "no network queries: answer the questions on stdin")
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

func askNetwork(pr *prompter) (baseline.Network, error) {
	var n baseline.Network
	var err error
	q := func(label string) string {
		if err != nil {
			return ""
		}
		var v string
		v, err = pr.ask(label)
		return v
	}
	n.Name = q("Nome da rede (ex.: casa): ")
	n.PublicIPv4 = q("IP público IPv4 (vazio se não souber): ")
	n.PublicIPv6 = q("IP público IPv6 (vazio se não houver): ")
	asn := q("ASN do provedor (só o número, vazio se não souber): ")
	n.Provider = q("Nome do provedor: ")
	n.Resolvers = splitList(q("Resolvedores DNS do provedor (separados por vírgula): "))
	n.GatewayIP = q("IP do gateway (roteador): ")
	n.GatewayMAC = q("MAC do gateway: ")
	n.SSIDs = splitList(q("SSIDs desta rede (separados por vírgula): "))
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
