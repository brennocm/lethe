package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"lethe/internal/contracts"
	"lethe/internal/journal"
	"lethe/internal/report"
)

func loadIdentities(path string) ([]age.Identity, error) {
	if path == "" {
		return nil, errors.New("an age identity file is required")
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied identity file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identity file %s: %w", path, err)
	}
	return ids, nil
}

// logKeys names where the identities that open a log come from: an age identity file
// (institutional keys) or the operator's baseline, whose embedded log_identity opens a log
// written without log_recipients (spec §10.6 item 9).
type logKeys struct {
	identity string
	baseline string
	secret   secretFlags
}

func (k *logKeys) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&k.identity, "identity", "", "age identity file that opens the log")
	cmd.Flags().StringVar(&k.baseline, "baseline", "", "open the log with the baseline's log_identity (asks the passphrase)")
	k.secret.register(cmd)
	cmd.MarkFlagsMutuallyExclusive("identity", "baseline")
}

// load returns the identities; with --baseline the passphrase is read once and wiped.
func (k *logKeys) load(cmd *cobra.Command) ([]age.Identity, error) {
	if k.baseline == "" {
		if k.identity == "" {
			return nil, errors.New("--identity FILE or --baseline FILE is required to open the log")
		}
		return loadIdentities(k.identity)
	}
	pw, b, err := openBaseline(cmd, k.baseline, &k.secret)
	wipeBytes(pw)
	if err != nil {
		return nil, err
	}
	id, err := b.Identity()
	if err != nil {
		return nil, err
	}
	return []age.Identity{id}, nil
}

// readVerified reads and verifies a session; integrity failures map to exit code 4.
func readVerified(dir string, ids []age.Identity, expectFP string) (*journal.Session, journal.Result, error) {
	s, err := journal.Read(dir, ids)
	if err != nil {
		if journal.IsIntegrity(err) {
			return nil, journal.Result{}, WithCode(ExitIntegrity, err)
		}
		return nil, journal.Result{}, err
	}
	res, err := journal.Verify(s, expectFP)
	if err != nil {
		return s, res, WithCode(ExitIntegrity, err)
	}
	return s, res, nil
}

func newVerifyCmd() *cobra.Command {
	var keys logKeys
	var expect string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify SESSION_DIR",
		Short: "Verify the hash chain, checkpoints and signatures of a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := keys.load(cmd)
			if err != nil {
				return err
			}
			_, res, err := readVerified(args[0], ids, expect)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				if err := contracts.Validate("verify", res); err != nil {
					return fmt.Errorf("internal: verify output violates contract: %w", err)
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			_, _ = fmt.Fprintf(out, "OK  session %s: %d events in %d segments, %d signatures, final %s\nfingerprint %s\n",
				res.Session, res.Events, res.Segments, res.Checkpoints, res.FinalHash, res.Fingerprint)
			for _, w := range res.Warnings() {
				_, _ = fmt.Fprintln(out, "WARN", w)
			}
			return nil
		},
	}
	keys.register(cmd)
	cmd.Flags().StringVar(&expect, "expect-fingerprint", "", "fingerprint recorded outside the machine at arm")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (schema: verify)")
	return cmd
}

func newReportCmd() *cobra.Command {
	var keys logKeys
	var sensIdentity, expect, format string
	var includeSensitive bool
	cmd := &cobra.Command{
		Use:   "report SESSION_DIR",
		Short: "Generate the session report (md or json)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := keys.load(cmd)
			if err != nil {
				return err
			}
			s, res, err := readVerified(args[0], ids, expect)
			if err != nil {
				return err
			}
			if includeSensitive {
				sens := ids // with the baseline, sensitive fields are sealed to the same identity
				if sensIdentity != "" || keys.baseline == "" {
					if sens, err = loadIdentities(sensIdentity); err != nil {
						return fmt.Errorf("--include-sensitive: %w", err)
					}
				}
				if err := s.UnlockSensitive(sens); err != nil {
					return WithCode(ExitAuth, err)
				}
				defer s.Wipe()
			}
			r, err := report.Build(s, res, report.Options{IncludeSensitive: includeSensitive})
			if err != nil {
				return err
			}
			switch format {
			case "md":
				return report.WriteMarkdown(cmd.OutOrStdout(), r)
			case "json":
				return report.WriteJSON(cmd.OutOrStdout(), r)
			default:
				return fmt.Errorf("unknown --format %q (md|json)", format)
			}
		},
	}
	keys.register(cmd)
	cmd.Flags().StringVar(&sensIdentity, "sensitive-identity", "", "age identity file that opens sensitive fields (default with --baseline: the baseline's)")
	cmd.Flags().StringVar(&expect, "expect-fingerprint", "", "fingerprint recorded outside the machine at arm")
	cmd.Flags().StringVar(&format, "format", "md", "md | json")
	cmd.Flags().BoolVar(&includeSensitive, "include-sensitive", false, "decrypt sensitive fields (needs --sensitive-identity)")
	return cmd
}
