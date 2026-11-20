package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"lethe/internal/daemon"
	"lethe/internal/ipc"
)

// selftestTimeout bounds one selftest call (13 cases of at most ~10 s each).
const selftestTimeout = 3 * time.Minute

func newSelftestCmd() *cobra.Command {
	var cases []string
	var asJSON, yes bool
	var s secretFlags
	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Prove that the sensors see and the guard blocks, with documentation addresses only (spec §18)",
		Long: "Runs the selftest inside the armed session (lethe run or lethe arm). Test traffic goes only to\n" +
			"192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32, which are not routed on the\n" +
			"internet. RESP-001 applies the panic for real (the network stops for about 1 s): it is asked\n" +
			"first and needs the passphrase; --yes confirms it without asking.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			c, err := dialDaemon()
			if err != nil {
				return WithCode(ExitDaemonDown, errors.New("the selftest runs inside an armed session and there is no daemon: "+
					"in another terminal run `sudo lethe run -p PROFILE --guard off`, then `lethe selftest`"))
			}
			defer func() { _ = c.Close() }()
			var st daemon.Status
			if err := c.Call("status.get", nil, nil, &st); err != nil {
				return rpcErr(err)
			}
			if st.State != "ARMED" {
				return fmt.Errorf("the selftest needs an ARMED session (current state: %s); arm with `lethe arm` or `lethe run`", st.State)
			}
			req := daemon.SelftestRequest{Cases: cases}
			wantResp := len(cases) == 0
			for _, id := range cases {
				if id == daemon.Resp001 {
					wantResp = true
				}
			}
			if wantResp {
				req.Resp = yes || (!asJSON && confirmResp(cmd.InOrStdin(), cmd.ErrOrStderr()))
			}
			var proof *ipc.Auth
			if req.Resp {
				if proof, err = prove(c, s.source(cmd), "selftest.run", req); err != nil {
					return err
				}
			}
			if !asJSON {
				_, _ = fmt.Fprintf(out, "selftest running (guard %s); it takes about 1 minute…\n", st.Guard)
			}
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			defer signal.Stop(sig)
			go func() { <-sig; _ = c.Close() }() // the daemon cancels the run and undoes the case
			_ = c.SetDeadline(time.Now().Add(selftestTimeout))
			var res daemon.SelftestResult
			if err := c.Call("selftest.run", req, proof, &res); err != nil {
				return rpcErr(err)
			}
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return err
				}
			} else {
				printSelftest(out, res)
			}
			if !res.Passed {
				return WithCode(ExitGeneric, errors.New("selftest failed"))
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&cases, "case", nil, "run only these cases (ST-NET-001, …, RESP-001)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output (RESP-001 only with --yes)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm RESP-001 without asking")
	s.register(cmd)
	return cmd
}

// confirmResp asks before RESP-001 cuts the network.
func confirmResp(in io.Reader, w io.Writer) bool {
	_, _ = fmt.Fprint(w, "RESP-001 applies a real panic: the network stops for about 1 s and comes back by itself.\n"+
		"Run RESP-001 now? It asks for the passphrase. [y/N] ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "s", "sim", "y", "yes":
		return true
	}
	_, _ = fmt.Fprintln(w, "RESP-001 skipped.")
	return false
}

func printSelftest(w io.Writer, r daemon.SelftestResult) {
	word := map[string]string{daemon.CasePass: "ok", daemon.CaseFail: "FALHOU", daemon.CaseSkip: "pulado"}
	for _, c := range r.Cases {
		line := fmt.Sprintf("  %-12s %-7s", c.ID, word[c.Result])
		if c.LatencyMS > 0 {
			line += fmt.Sprintf(" %7.1f ms", c.LatencyMS)
		}
		if c.Reason != "" {
			line += "  " + c.Reason
		}
		_, _ = fmt.Fprintln(w, line)
	}
	switch {
	case r.Critical:
		_, _ = fmt.Fprintln(w, "selftest: CRITICAL FAILURE. A leak may pass without an alert or the panic may not block; do not operate with strict until it is fixed.")
	case !r.Passed:
		_, _ = fmt.Fprintln(w, "selftest: failed (the preflight will warn). See the reasons above.")
	case r.Guard != "strict":
		_, _ = fmt.Fprintln(w, "selftest passed. To operate, switch the profile to `guard.mode: strict` (recommended) and run the selftest again.")
	default:
		_, _ = fmt.Fprintln(w, "selftest passed.")
	}
}

// newSelftestDenyCmd is the ST-HOST-001 child: it renames itself lethe-st-deny (the selftest
// deny rule) and waits until the daemon stops it, at most 15 s.
func newSelftestDenyCmd() *cobra.Command {
	return &cobra.Command{
		Use: "selftest-deny", Hidden: true, Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := os.WriteFile("/proc/self/comm", []byte("lethe-st-deny"), 0); err != nil {
				return err
			}
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			select {
			case <-sig:
			case <-time.After(15 * time.Second):
			}
			return nil
		},
	}
}
