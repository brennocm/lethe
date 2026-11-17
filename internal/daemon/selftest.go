package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/engine"
	"lethe/internal/guard"
	"lethe/internal/sensors/capture"
)

// Selftest (spec §18). The runner lives in the daemon: it owns the sensors, the guard and the
// privileges. Every case sends traffic only to documentation addresses; the findings it causes
// are recognised by probes (exact flow, interface, table or PID), journaled with selftest: true
// and run through the engine in dry-run, so the selftest never triggers a real response, except
// RESP-001, which applies and removes the panic table for real when the operator confirms it.

// Selftest case IDs, in run order.
const (
	STNet001  = "ST-NET-001"
	STNet002  = "ST-NET-002"
	STNet003  = "ST-NET-003"
	STNet006  = "ST-NET-006"
	STNet010  = "ST-NET-010"
	STNet012  = "ST-NET-012"
	STDNS001  = "ST-DNS-001"
	STDNS004  = "ST-DNS-004"
	STTun004  = "ST-TUN-004"
	STHost001 = "ST-HOST-001"
	STSelf001 = "ST-SELF-001"
	STSelf002 = "ST-SELF-002"
	Resp001   = "RESP-001"
)

// SelftestCases is every case of §18.2, in run order.
var SelftestCases = []string{STNet001, STNet002, STNet003, STNet006, STNet010, STNet012, STDNS001, STDNS004,
	STTun004, STHost001, STSelf001, STSelf002, Resp001}

// criticalCases: a failure here makes the preflight CRITICAL (spec §18.3).
var criticalCases = map[string]bool{STNet001: true, STNet002: true, Resp001: true}

// Case results.
const (
	CasePass = "pass"
	CaseFail = "fail"
	CaseSkip = "skip"
)

// Selftest flow constants (documentation destinations only, spec §18.1).
var (
	stDst001  = netip.MustParseAddrPort("192.0.2.1:9")
	stDst003  = netip.MustParseAddrPort("[2001:db8::1]:9")
	stDst010  = netip.MustParseAddrPort("198.51.100.1:443")
	stDst012  = netip.MustParseAddrPort("203.0.113.1:3478")
	stDstDNS  = netip.MustParseAddrPort("192.0.2.53:53")
	stDstBurt = netip.MustParseAddrPort("192.0.2.2:9")
)

const (
	stDummy     = "lethe-st0"
	stTable     = "lethe_selftest"
	stDenyComm  = "lethe-st-deny"
	stWait      = 6 * time.Second // per case
	stGrace     = 5 * time.Second // late findings of a finished case are still absorbed
	stPause     = 4 * time.Second // ST-SELF-001
	stBurst     = 2000            // ST-SELF-002
	stMinRcvbuf = 1
)

// SelftestRequest is selftest.run. RESP-001 runs only when Resp is true (a sensitive call).
type SelftestRequest struct {
	Cases []string `json:"cases,omitempty"` // empty = all
	Resp  bool     `json:"resp,omitempty"`  // the operator confirmed RESP-001 (it cuts the network ~1 s)
}

// CaseResult is one row of the result table.
type CaseResult struct {
	ID        string  `json:"id"`
	Result    string  `json:"result"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Reason    string  `json:"reason,omitempty"`
}

// SelftestResult is the table written to the journal and to storage.dir/state/selftest.json.
type SelftestResult struct {
	FinishedAt time.Time    `json:"finished_at"`
	Guard      string       `json:"guard"`
	Passed     bool         `json:"passed"`
	Critical   bool         `json:"critical"`
	Full       bool         `json:"full"` // every case was asked (only a full run updates SELF-004)
	Cases      []CaseResult `json:"cases"`
}

// ErrSelftestBusy: one selftest at a time.
var ErrSelftestBusy = errors.New("a selftest is already running")

// stProbe recognises the findings one case causes.
type stProbe struct {
	flow   func(checks.Finding) bool  // the finding comes from the test (absorbed)
	want   string                     // the check that proves the case
	verify func(checks.Finding) error // extra condition on the proving finding; runs under d.mu
	hit    chan stHit
	until  time.Time // zero while the case runs
}

type stHit struct {
	at  time.Time
	err error
}

// selftestAbsorbLocked journals f as a selftest event when a probe recognises it.
func (d *Daemon) selftestAbsorbLocked(f checks.Finding) bool {
	s := d.sess
	if len(s.probes) == 0 {
		return false
	}
	now := time.Now()
	s.probes = slices.DeleteFunc(s.probes, func(p *stProbe) bool { return !p.until.IsZero() && now.After(p.until) })
	for _, p := range s.probes {
		if !p.flow(f) {
			continue
		}
		if f.Check == p.want && p.until.IsZero() {
			var err error
			if p.verify != nil {
				err = p.verify(f)
			}
			select {
			case p.hit <- stHit{at: now, err: err}:
			default:
			}
		}
		d.selftestEventLocked(f)
		return true
	}
	return false
}

// selftestEventLocked writes the finding with selftest: true and the response plan in dry-run.
func (d *Daemon) selftestEventLocked(f checks.Finding) {
	ev, err := f.SealedAlert(d.sess.journal.Seal)
	if err != nil {
		ev = f.Alert()
	}
	ev.Selftest, ev.Source = true, contracts.SourceSelftest
	dec := d.eng.Observe(ev)
	data := make(map[string]any, len(ev.Data)+1)
	for k, v := range ev.Data {
		data[k] = v
	}
	data["dry_run"] = true
	ev.Data = data
	for _, a := range dec.Actions {
		ev.Actions = append(ev.Actions, string(a))
	}
	d.appendLocked(ev)
}

func (d *Daemon) addProbe(s *session, p *stProbe) {
	p.hit = make(chan stHit, 1)
	d.mu.Lock()
	defer d.mu.Unlock()
	s.probes = append(s.probes, p)
}

// endProbe keeps absorbing late findings of the case for stGrace.
func (d *Daemon) endProbe(p *stProbe) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p.until = time.Now().Add(stGrace)
}

func waitHit(ctx context.Context, p *stProbe, start time.Time) CaseResult {
	t := time.NewTimer(stWait)
	defer t.Stop()
	select {
	case h := <-p.hit:
		if h.err != nil {
			return CaseResult{Result: CaseFail, Reason: h.err.Error()}
		}
		return CaseResult{Result: CasePass, LatencyMS: ms(h.at.Sub(start))}
	case <-t.C:
		return CaseResult{Result: CaseFail, Reason: p.want + " not raised within " + stWait.String()}
	case <-ctx.Done():
		return CaseResult{Result: CaseFail, Reason: "interrupted"}
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// flowOf matches a finding of the test flow: same protocol and destination, and the test's
// source port when the finding has one.
func flowOf(proto string, sport uint16, dst netip.AddrPort) func(checks.Finding) bool {
	return func(f checks.Finding) bool {
		if f.Data["proto"] != proto || f.Data["dst"] != dst.Addr().String() {
			return false
		}
		if p, ok := f.Data["dport"].(int); !ok || p != int(dst.Port()) {
			return false
		}
		if p, ok := f.Data["sport"].(int); ok && sport != 0 && p != int(sport) {
			return false
		}
		return true
	}
}

func dataIs(key, val string) func(checks.Finding) bool {
	return func(f checks.Finding) bool { return f.Data[key] == val }
}

// RunSelftest runs the cases of req in the armed session. auth is called when RESP-001 runs
// (the call must carry a passphrase proof).
func (d *Daemon) RunSelftest(ctx context.Context, req SelftestRequest, auth func() error) (SelftestResult, error) {
	want := SelftestCases
	if len(req.Cases) > 0 {
		for _, c := range req.Cases {
			if !slices.Contains(SelftestCases, c) {
				return SelftestResult{}, errParams(fmt.Errorf("unknown selftest case %q", c))
			}
		}
		want = req.Cases
	}
	if req.Resp && slices.Contains(want, Resp001) {
		if err := auth(); err != nil {
			return SelftestResult{}, err
		}
	}
	d.mu.Lock()
	s := d.sess
	switch {
	case s == nil:
		d.mu.Unlock()
		return SelftestResult{}, errState(errNotArmed)
	case d.eng.Session() != engine.StateArmed || s.confirming:
		d.mu.Unlock()
		return SelftestResult{}, errState(fmt.Errorf("selftest needs the session ARMED (it is %s)", d.eng.Session()))
	case s.selftesting:
		d.mu.Unlock()
		return SelftestResult{}, errState(ErrSelftestBusy)
	}
	s.selftesting = true
	mode := s.guardMode
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		s.selftesting = false
		d.mu.Unlock()
	}()

	res := SelftestResult{Guard: string(mode), Full: len(req.Cases) == 0, Passed: true, Cases: []CaseResult{}}
	for _, id := range want {
		r := d.runCase(ctx, s, id, req.Resp)
		r.ID = id
		res.Cases = append(res.Cases, r)
		if r.Result == CaseFail {
			res.Passed = false
			if criticalCases[id] {
				res.Critical = true
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	res.FinishedAt = time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == s {
		d.appendLocked(contracts.Event{Type: contracts.EvSelftestResult, Source: contracts.SourceSelftest, Selftest: true, Data: res.data()})
	}
	if res.Full {
		if err := d.writeSelftestFile(s, res); err != nil {
			_, _ = fmt.Fprintf(d.cfg.Out, "lethe: selftest.json: %v\n", err)
		}
	}
	return res, nil
}

func (r SelftestResult) data() map[string]any {
	cases := make([]any, 0, len(r.Cases))
	for _, c := range r.Cases {
		m := map[string]any{"id": c.ID, "result": c.Result}
		if c.LatencyMS > 0 {
			m["latency_ms"] = c.LatencyMS
		}
		if c.Reason != "" {
			m["reason"] = c.Reason
		}
		cases = append(cases, m)
	}
	return map[string]any{"passed": r.Passed, "critical": r.Critical, "guard": r.Guard, "full": r.Full, "cases": cases}
}

// writeSelftestFile records the result for SELF-004, owned by the operator (the preflight
// without the daemon reads it with the operator's rights).
func (d *Daemon) writeSelftestFile(s *session, r SelftestResult) error {
	dir := filepath.Join(s.prof.Storage.Dir, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".selftest.json.tmp")
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if os.Geteuid() == 0 && d.cfg.Operator.UID > 0 {
		_ = os.Chown(dir, d.cfg.Operator.UID, d.cfg.Operator.GID)
		_ = os.Chown(tmp, d.cfg.Operator.UID, d.cfg.Operator.GID)
	}
	return os.Rename(tmp, filepath.Join(dir, "selftest.json"))
}

// stEgress is the egress interface the traffic cases use: the first one with a capture.
func (d *Daemon) stEgress(s *session) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s.sensors == nil { // sensors off (unit tests): the cases still need an egress name
		if len(d.snap.CaptureIfaces) > 0 {
			return d.snap.CaptureIfaces[0], true
		}
		return "", false
	}
	for _, i := range d.snap.CaptureIfaces {
		if _, ok := s.sensors.captures[i]; ok {
			return i, true
		}
	}
	return "", false
}

func (d *Daemon) runCase(ctx context.Context, s *session, id string, resp bool) CaseResult {
	ops := d.cfg.SelftestOps
	strict := s.guardMode == engine.GuardStrict
	switch id {
	case STNet001:
		return d.stUDPCase(ctx, s, "NET-001", stDst001, []byte("lethe selftest ST-NET-001"), strict, nil)
	case STNet002:
		if !strict {
			return CaseResult{Result: CaseSkip, Reason: "strict mode only"}
		}
		return d.stUDPCase(ctx, s, "NET-002", stDst001, []byte("lethe selftest ST-NET-002"), false, func(f checks.Finding) error {
			if u, ok := f.Data["uid"].(int); !ok || u != 0 {
				return fmt.Errorf("blocked attempt without the selftest UID (got %v)", f.Data["uid"])
			}
			return nil
		})
	case STNet003:
		if !d.egressV6(s) {
			return CaseResult{Result: CaseSkip, Reason: "no global IPv6 on the egress"}
		}
		return d.stUDPCase(ctx, s, "NET-001", stDst003, []byte("lethe selftest ST-NET-003"), strict, nil)
	case STNet006:
		p := &stProbe{flow: dataIs("iface", stDummy), want: "NET-006"}
		d.addProbe(s, p)
		defer d.endProbe(p)
		start := time.Now()
		if err := ops.AddDummy(stDummy); err != nil {
			return CaseResult{Result: CaseFail, Reason: err.Error()}
		}
		defer func() { _ = ops.DelDummy(stDummy) }()
		return waitHit(ctx, p, start)
	case STNet010:
		iface, ok := d.stEgress(s)
		if !ok {
			return CaseResult{Result: CaseFail, Reason: "no capture interface"}
		}
		var p *stProbe
		var start time.Time
		pid := os.Getpid()
		closeFn, err := ops.SYN(iface, stDst010, func(sport uint16) error {
			p = &stProbe{flow: flowOf("tcp", sport, stDst010), want: "NET-010", verify: func(f checks.Finding) error {
				pr, _ := f.Data["proc"].(contracts.Proc)
				if pr.PID != pid || pr.Confidence != contracts.ConfidenceHigh {
					return fmt.Errorf("socket not attributed to the selftest (pid %d, confidence %q)", pr.PID, pr.Confidence)
				}
				return nil
			}}
			d.addProbe(s, p)
			start = time.Now()
			return d.stException(s, strict, unix.IPPROTO_TCP, sport, stDst010)
		})
		if p != nil {
			defer d.endProbe(p)
		}
		defer d.stClearException(s, strict)
		if err != nil {
			return CaseResult{Result: CaseFail, Reason: err.Error()}
		}
		defer closeFn()
		return waitHit(ctx, p, start)
	case STNet012:
		return d.stUDPCase(ctx, s, "NET-012", stDst012, stunBinding(), strict, nil)
	case STDNS001:
		name := "lethe-st-" + randHex(6) + ".example"
		q := dnsQuery(name)
		return d.stUDPCase(ctx, s, "DNS-001", stDstDNS, q, strict, func(f checks.Finding) error {
			if f.Sensitive["qname"] != name {
				return errors.New("qname does not match the query")
			}
			// verify runs under d.mu (selftestAbsorbLocked)
			sealed, err := s.journal.Seal(f.Sensitive["qname"])
			if err != nil {
				return err
			}
			if got, err := s.journal.Unseal(sealed); err != nil || got != name {
				return errors.New("the sealed qname does not open to the same value")
			}
			return nil
		})
	case STDNS004:
		path := selftestDNSFile(s)
		if !d.sensorUp(s, "fswatch") {
			return CaseResult{Result: CaseFail, Reason: "the DNS configuration watch is not running"}
		}
		p := &stProbe{flow: dataIs("path", path), want: "DNS-004"}
		d.addProbe(s, p)
		defer d.endProbe(p)
		start := time.Now()
		if err := replaceFile(path, "# lethe selftest (ST-DNS-004) "+randHex(4)+"\n"); err != nil {
			return CaseResult{Result: CaseFail, Reason: err.Error()}
		}
		return waitHit(ctx, p, start)
	case STTun004:
		d.mu.Lock()
		readable := s.nftArm != nil
		d.mu.Unlock()
		if !readable {
			return CaseResult{Result: CaseFail, Reason: "nftables could not be read at arm"}
		}
		p := &stProbe{flow: dataIs("table", "inet "+stTable), want: "TUN-004"}
		d.addProbe(s, p)
		defer d.endProbe(p)
		start := time.Now()
		if err := ops.AddTable(stTable); err != nil {
			return CaseResult{Result: CaseFail, Reason: err.Error()}
		}
		d.refreshNow(s)
		r := waitHit(ctx, p, start)
		_ = ops.DelTable(stTable)
		d.refreshNow(s)
		return r
	case STHost001:
		var pid int
		p := &stProbe{flow: func(f checks.Finding) bool {
			pr, _ := f.Data["proc"].(contracts.Proc)
			return f.Check == "HOST-001" && pr.Comm == stDenyComm
		}, want: "HOST-001", verify: func(f checks.Finding) error {
			if pr, _ := f.Data["proc"].(contracts.Proc); pr.PID != pid {
				return fmt.Errorf("matched PID %d, the selftest child is %d", pr.PID, pid)
			}
			return nil
		}}
		d.setSelftestDeny(s, true)
		defer d.setSelftestDeny(s, false)
		d.addProbe(s, p)
		defer d.endProbe(p)
		start := time.Now()
		cpid, stop, err := ops.SpawnDeny()
		if err != nil {
			return CaseResult{Result: CaseFail, Reason: err.Error()}
		}
		d.mu.Lock()
		pid = cpid
		d.mu.Unlock()
		defer stop()
		time.Sleep(100 * time.Millisecond) // the child renames itself
		d.ObserveHost(s, d.collector(s).Collect())
		return waitHit(ctx, p, start)
	case STSelf001:
		return d.stPauseCase(ctx, s)
	case STSelf002:
		return d.stDropCase(ctx, s, strict)
	case Resp001:
		if !resp {
			return CaseResult{Result: CaseSkip, Reason: "not confirmed: it cuts the network for about 1 s (lethe selftest asks first)"}
		}
		return d.stPanicCase(s)
	}
	return CaseResult{Result: CaseFail, Reason: "unknown case"}
}

// stUDPCase sends one datagram through the egress and waits for want. In strict, the exact flow
// gets a temporary exception when withException.
func (d *Daemon) stUDPCase(ctx context.Context, s *session, want string, dst netip.AddrPort, payload []byte, withException bool, verify func(checks.Finding) error) CaseResult {
	iface, ok := d.stEgress(s)
	if !ok {
		return CaseResult{Result: CaseFail, Reason: "no capture interface"}
	}
	var p *stProbe
	var start time.Time
	_, err := d.cfg.SelftestOps.UDP(iface, dst, payload, 1, func(sport uint16) error {
		p = &stProbe{flow: flowOf("udp", sport, dst), want: want, verify: verify}
		d.addProbe(s, p)
		start = time.Now()
		return d.stException(s, withException, unix.IPPROTO_UDP, sport, dst)
	})
	if p != nil {
		defer d.endProbe(p)
	}
	defer d.stClearException(s, withException)
	if errors.Is(err, unix.EPERM) && p != nil && !withException {
		err = nil // the guard refused the datagram: the case waits for its NFLOG record (ST-NET-002)
	}
	if err != nil {
		return CaseResult{Result: CaseFail, Reason: err.Error()}
	}
	return waitHit(ctx, p, start)
}

// stException installs the strict exception of one test flow (a no-op unless on).
func (d *Daemon) stException(s *session, on bool, proto uint8, sport uint16, dst netip.AddrPort) error {
	if !on {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s {
		return errNotArmed
	}
	s.stExceptions = []guard.Exception{{Proto: proto, Sport: sport, Dst: dst}}
	s.gcfg.Exceptions = s.stExceptions
	return d.applyStrictLocked()
}

func (d *Daemon) stClearException(s *session, on bool) {
	if !on {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s || len(s.stExceptions) == 0 {
		return
	}
	s.stExceptions, s.gcfg.Exceptions = nil, nil
	if err := d.applyStrictLocked(); err != nil {
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: selftest: removing the exception failed: %v\n", err)
	}
}

// applyStrictLocked replaces the strict ruleset in one transaction.
func (d *Daemon) applyStrictLocked() error {
	rs, err := guard.Strict(d.sess.gcfg)
	if err != nil {
		return err
	}
	c, err := d.cfg.NFT()
	if err != nil {
		return err
	}
	return guard.Apply(c, rs)
}

func (d *Daemon) refreshNow(s *session) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == s {
		d.refreshLocked()
	}
}

func (d *Daemon) sensorUp(s *session, src string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := s.beats[src]
	return ok && !s.down[src]
}

func (d *Daemon) setSelftestDeny(s *session, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s.stDeny = on
}

func (d *Daemon) egressV6(s *session) bool {
	iface, ok := d.stEgress(s)
	if !ok {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, i := range d.snap.Ifaces {
		if i.Name == iface && len(i.GlobalV6) > 0 && !i.IPv6Disabled {
			return true
		}
	}
	return false
}

// stPauseCase: the capture sensor loses its heartbeats for 4 s; GRAY must come and go.
func (d *Daemon) stPauseCase(ctx context.Context, s *session) CaseResult {
	iface, ok := d.stEgress(s)
	if !ok {
		return CaseResult{Result: CaseFail, Reason: "no capture interface"}
	}
	src := capture.SourceID + ":" + iface
	start := time.Now()
	if err := d.PauseSensor(src, stPause); err != nil {
		return CaseResult{Result: CaseFail, Reason: err.Error()}
	}
	// The sensor must be reported down and the state must show it: GRAY, or RED when a real
	// CRITICAL is open (red outranks gray, spec §6.1, so gray cannot appear then).
	gray := waitState(ctx, func() bool {
		if !d.sourceDown(s, src) {
			return false
		}
		c := d.Status().Color
		return c == string(engine.ColorGray) || c == string(engine.ColorRed)
	}, stPause+2*time.Second)
	if gray.IsZero() {
		return CaseResult{Result: CaseFail, Reason: "the sensor was not reported down (no GRAY)"}
	}
	back := waitState(ctx, func() bool { return !d.sourceDown(s, src) }, stPause+3*time.Second)
	if back.IsZero() {
		return CaseResult{Result: CaseFail, Reason: "the sensor did not come back"}
	}
	return CaseResult{Result: CasePass, LatencyMS: ms(gray.Sub(start))}
}

func (d *Daemon) sourceDown(s *session, src string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return s.down[src]
}

func waitState(ctx context.Context, cond func() bool, limit time.Duration) time.Time {
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); {
		if cond() {
			return time.Now()
		}
		select {
		case <-ctx.Done():
			return time.Time{}
		case <-time.After(50 * time.Millisecond):
		}
	}
	return time.Time{}
}

// stDropCase: the minimum receive buffer plus a burst of 2000 test datagrams must drop.
func (d *Daemon) stDropCase(ctx context.Context, s *session, strict bool) CaseResult {
	iface, ok := d.stEgress(s)
	if !ok {
		return CaseResult{Result: CaseFail, Reason: "no capture interface"}
	}
	d.mu.Lock()
	c := s.sensors.captures[iface]
	d.mu.Unlock()
	orig, err := c.ReadBuffer()
	if err != nil {
		return CaseResult{Result: CaseFail, Reason: err.Error()}
	}
	p := &stProbe{flow: func(f checks.Finding) bool {
		return (f.Check == "SELF-002" && f.Data["iface"] == iface) || flowOf("udp", 0, stDstBurt)(f)
	}, want: "SELF-002"}
	d.addProbe(s, p)
	defer d.endProbe(p)
	if err := d.ShrinkCapture(iface, stMinRcvbuf); err != nil {
		return CaseResult{Result: CaseFail, Reason: err.Error()}
	}
	defer func() { _ = d.ShrinkCapture(iface, orig) }()
	var start time.Time
	_, err = d.cfg.SelftestOps.UDP(iface, stDstBurt, make([]byte, 1200), stBurst, func(sport uint16) error {
		start = time.Now()
		return d.stException(s, strict, unix.IPPROTO_UDP, sport, stDstBurt)
	})
	defer d.stClearException(s, strict)
	if err != nil {
		return CaseResult{Result: CaseFail, Reason: err.Error()}
	}
	return waitHit(ctx, p, start)
}

// stPanicCase applies the panic table for real, proves that test traffic is refused and removes
// it. The session state does not change: this is the response, not a PANIC.
func (d *Daemon) stPanicCase(s *session) CaseResult {
	iface, ok := d.stEgress(s)
	if !ok {
		return CaseResult{Result: CaseFail, Reason: "no capture interface"}
	}
	d.mu.Lock()
	rs, err := guard.Panic(s.gcfg)
	d.mu.Unlock()
	if err != nil {
		return CaseResult{Result: CaseFail, Reason: err.Error()}
	}
	c, err := d.cfg.NFT()
	if err != nil {
		return CaseResult{Result: CaseFail, Reason: err.Error()}
	}
	start := time.Now()
	if err := guard.Apply(c, rs); err != nil {
		return CaseResult{Result: CaseFail, Reason: err.Error()}
	}
	applied := time.Since(start)
	defer func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		strictNow := d.sess == s && s.guardMode == engine.GuardStrict
		var rmErr error
		for _, t := range rs.Tables {
			if strictNow && t.Name != guard.TablePanic {
				continue // the strict L2 table is restored below, in one transaction
			}
			rmErr = errors.Join(rmErr, guard.Remove(c, guard.TableRef{Family: t.Family, Name: t.Name}))
		}
		if strictNow {
			rmErr = errors.Join(rmErr, d.applyStrictLocked())
		}
		if rmErr != nil {
			_, _ = fmt.Fprintf(d.cfg.Out, "lethe: selftest: the panic could not be undone: %v (sudo lethe cleanup removes it)\n", rmErr)
		}
		d.appendLocked(contracts.Event{Type: contracts.EvResponseExecuted, Source: contracts.SourceSelftest, Selftest: true,
			Data: map[string]any{"action": "block_all", "result": "ok", "latency_ms": ms(applied), "removed": rmErr == nil}})
	}()
	_, err = d.cfg.SelftestOps.UDP(iface, stDst001, []byte("lethe selftest RESP-001"), 1, nil)
	if !errors.Is(err, unix.EPERM) {
		return CaseResult{Result: CaseFail, Reason: fmt.Sprintf("test traffic was not refused under panic (%v)", err)}
	}
	return CaseResult{Result: CasePass, LatencyMS: ms(applied)}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// replaceFile writes content atomically (rename), as resolv.conf managers do.
func replaceFile(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// stunBinding is a STUN Binding Request (RFC 5389): type 1, no attributes, magic cookie.
func stunBinding() []byte {
	b := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}
	tid := make([]byte, 12)
	_, _ = rand.Read(tid)
	return append(b, tid...)
}

// dnsQuery is a standard A query for name.
func dnsQuery(name string) []byte {
	id := make([]byte, 2)
	_, _ = rand.Read(id)
	q := append(id, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, l := range splitLabels(name) {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0x00, 0x00, 0x01, 0x00, 0x01)
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}
