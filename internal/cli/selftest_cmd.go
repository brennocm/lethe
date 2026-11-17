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
				return WithCode(ExitDaemonDown, errors.New("o selftest roda dentro de uma sessão armada e não há daemon: "+
					"em outro terminal rode `sudo lethe run -p PERFIL --guard off` e depois `lethe selftest`"))
			}
			defer func() { _ = c.Close() }()
			var st daemon.Status
			if err := c.Call("status.get", nil, nil, &st); err != nil {
				return rpcErr(err)
			}
			if st.State != "ARMED" {
				return fmt.Errorf("o selftest precisa da sessão ARMADA (estado atual: %s); arme com `lethe arm` ou `lethe run`", st.State)
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
				_, _ = fmt.Fprintf(out, "selftest em andamento (guarda %s); leva cerca de 1 minuto…\n", st.Guard)
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
				return WithCode(ExitGeneric, errors.New("selftest com falha"))
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
	_, _ = fmt.Fprint(w, "RESP-001 aplica o pânico de verdade: a rede para por cerca de 1 s e volta sozinha.\n"+
		"Rodar o RESP-001 agora? Pede a passphrase. [s/N] ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "s", "sim", "y", "yes":
		return true
	}
	_, _ = fmt.Fprintln(w, "RESP-001 pulado.")
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
		_, _ = fmt.Fprintln(w, "selftest: FALHA CRÍTICA. Um vazamento pode passar sem alerta ou o pânico pode não bloquear; não opere com o estrito até resolver.")
	case !r.Passed:
		_, _ = fmt.Fprintln(w, "selftest: com falhas (o preflight vai avisar). Veja os motivos acima.")
	case r.Guard != "strict":
		_, _ = fmt.Fprintln(w, "selftest aprovado. Para operar, passe o perfil para `guard.mode: strict` (recomendado) e rode o selftest de novo.")
	default:
		_, _ = fmt.Fprintln(w, "selftest aprovado.")
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
