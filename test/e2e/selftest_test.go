//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"lethe/internal/daemon"
	"lethe/test/netlab"
)

// TestE2E_AC11_Selftest: every case of §18.2 passes in off and in strict (RESP-001 confirmed).
// ST-NET-002 is strict only. ST-NET-003 skips: IPv6 on the egress outside the tunnel fails the
// preflight (NET-003 CRITICAL), so an armed lab has none.
func TestE2E_AC11_Selftest(t *testing.T) {
	for _, mode := range []string{"off", "strict"} {
		t.Run(mode, func(t *testing.T) {
			lab := netlab.New(t, true)
			defer lab.Close()
			lab.WaitHandshake(t, 10*time.Second)
			s := newSession(t)
			d, c, out := startDaemon(t, s)
			req := s.armRequest(t)
			req.Guard = mode
			if err := c.Call("session.arm", req, nil, nil); err != nil {
				t.Fatalf("arm: %v\n%s", err, out.String())
			}
			waitFor(t, "armed", func() bool { return d.Status().State == "ARMED" && !d.Status().Confirming })
			st := daemon.SelftestRequest{Resp: true}
			_ = c.SetDeadline(time.Now().Add(3 * time.Minute))
			var res daemon.SelftestResult
			if err := c.Call("selftest.run", st, proof(t, c, s.pass, "selftest.run", st), &res); err != nil {
				t.Fatalf("selftest: %v\n%s", err, out.String())
			}
			var rows []string
			for _, r := range res.Cases {
				rows = append(rows, r.ID+"="+r.Result+" "+r.Reason)
				skipOK := (r.ID == daemon.STNet002 && mode == "off") || r.ID == daemon.STNet003
				allowed := r.Result == daemon.CasePass || (skipOK && r.Result == daemon.CaseSkip)
				if !allowed {
					t.Errorf("%s: %s %s", r.ID, r.Result, r.Reason)
				}
			}
			if t.Failed() {
				t.Logf("cases:\n%s", strings.Join(rows, "\n"))
				return
			}
			if !res.Passed || res.Critical || !res.Full {
				t.Fatalf("%+v", res)
			}
			// the lab host's own state may open HOST-005/006; none of the exercised checks may
			exercised := map[string]bool{"NET-001": true, "NET-002": true, "NET-006": true, "NET-010": true, "NET-012": true,
				"DNS-001": true, "DNS-004": true, "TUN-004": true, "HOST-001": true, "SELF-001": true, "SELF-002": true}
			now := d.Status()
			for _, a := range now.Alerts {
				if exercised[a.Check] {
					t.Fatalf("the selftest left a real alert: %+v", a)
				}
			}
			if now.State != "ARMED" {
				t.Fatalf("the selftest changed the state: %s", now.State)
			}
			// the guard is back to the plain strict ruleset: no exception, no panic table
			if mode == "strict" {
				conn, _ := nftConn()
				tabs, _ := conn.ListTables()
				for _, tb := range tabs {
					if tb.Name == "lethe_panic" || tb.Name == "lethe_selftest" {
						t.Fatalf("%s left behind", tb.Name)
					}
				}
			}
		})
	}
}
