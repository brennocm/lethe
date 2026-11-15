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
		return nil, errors.New("--identity is required (age identity file)")
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

// readVerified reads and verifies a session; integrity failures map to exit code 4.
func readVerified(dir, identityFile, expectFP string) (*journal.Session, journal.Result, error) {
	ids, err := loadIdentities(identityFile)
	if err != nil {
		return nil, journal.Result{}, err
	}
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
	var identity, expect string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify SESSION_DIR",
		Short: "Verify the hash chain, checkpoints and signatures of a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, res, err := readVerified(args[0], identity, expect)
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
	cmd.Flags().StringVar(&identity, "identity", "", "age identity file that opens the log")
	cmd.Flags().StringVar(&expect, "expect-fingerprint", "", "fingerprint recorded outside the machine at arm")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (schema: verify)")
	return cmd
}

func newReportCmd() *cobra.Command {
	var identity, sensIdentity, expect, format string
	var includeSensitive bool
	cmd := &cobra.Command{
		Use:   "report SESSION_DIR",
		Short: "Generate the session report (md or json)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, res, err := readVerified(args[0], identity, expect)
			if err != nil {
				return err
			}
			if includeSensitive {
				ids, err := loadIdentities(sensIdentity)
				if err != nil {
					return fmt.Errorf("--include-sensitive: %w", err)
				}
				if err := s.UnlockSensitive(ids); err != nil {
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
	cmd.Flags().StringVar(&identity, "identity", "", "age identity file that opens the log")
	cmd.Flags().StringVar(&sensIdentity, "sensitive-identity", "", "age identity file that opens sensitive fields")
	cmd.Flags().StringVar(&expect, "expect-fingerprint", "", "fingerprint recorded outside the machine at arm")
	cmd.Flags().StringVar(&format, "format", "md", "md | json")
	cmd.Flags().BoolVar(&includeSensitive, "include-sensitive", false, "decrypt sensitive fields (needs --sensitive-identity)")
	return cmd
}
