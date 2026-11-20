package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/discovery"
	"lethe/internal/platform"
)

// learnWindow is how long --learn watches the egress (spec §7.3).
const learnWindow = 10 * time.Second

// candidate is one destination seen leaving an egress interface, grouped by process.
type candidate struct {
	Endpoint string // "ip:port/proto"
	Exe      string // "" when the packet could not be attributed
	Count    int
}

// learnCandidates groups the NET-001 and NET-002 events (packets leaving, or blocked on their
// way out of, an egress interface) by destination and process, most frequent first.
func learnCandidates(evs []contracts.Event) []candidate {
	idx := map[string]*candidate{}
	for _, ev := range evs {
		if ev.Type != contracts.EvCheckAlert || (ev.Check != "NET-001" && ev.Check != "NET-002") {
			continue
		}
		proto := ev.Str("proto")
		if proto != "udp" && proto != "tcp" {
			continue
		}
		ep, err := discovery.ParseEndpoint(fmt.Sprintf("%s/%s", joinHostPort(ev.Str("dst"), ev.Int("dport")), proto))
		if err != nil {
			continue
		}
		exe := ev.ProcExe()
		k := ep.String() + "|" + exe
		if c, ok := idx[k]; ok {
			c.Count++
			continue
		}
		idx[k] = &candidate{Endpoint: ep.String(), Exe: exe, Count: 1}
	}
	out := make([]candidate, 0, len(idx))
	for _, c := range idx {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Endpoint+out[i].Exe < out[j].Endpoint+out[j].Exe
	})
	return out
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// printCandidates shows the list the operator chooses from.
func printCandidates(w io.Writer, cs []candidate) {
	if len(cs) == 0 {
		_, _ = fmt.Fprintln(w, "No destination left through the egress interface in these 10 s.")
		_, _ = fmt.Fprintln(w, "Connect (or reconnect) the VPN and run again, or declare the endpoint in egress.endpoints.")
		return
	}
	_, _ = fmt.Fprintln(w, "Destinations seen leaving through the egress interface:")
	for i, c := range cs {
		who := "unknown process"
		if c.Exe != "" {
			who = filepath.Base(c.Exe) + " (" + platform.TermSafe(c.Exe) + ")"
			if discovery.IsVPNClient(c.Exe) {
				who += "  ← VPN client"
			}
		}
		_, _ = fmt.Fprintf(w, "  %d) %-28s %s  ×%d\n", i+1, c.Endpoint, who, c.Count)
	}
}

// chooseCandidate reads the operator's choice: a number from the list, or empty for none.
func chooseCandidate(r *bufio.Reader, w io.Writer, cs []candidate) (string, bool, error) {
	_, _ = fmt.Fprint(w, "Which of these is the tunnel endpoint? (number; Enter = none): ")
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", false, nil
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false, nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(cs) {
		return "", false, fmt.Errorf("invalid choice %q", line)
	}
	return cs[n-1].Endpoint, true, nil
}

// runLearn is discover --learn: watch the armed session's egress for 10 s, then let the operator
// confirm the endpoint (a sensitive call, proven with the passphrase).
func runLearn(in io.Reader, out io.Writer, src *passphraseSource) error {
	c, err := dialDaemon()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	var st daemon.Status
	if err := c.Call("status.get", nil, nil, &st); err != nil {
		return rpcErr(err)
	}
	if st.State != "ARMED" {
		return fmt.Errorf("--learn watches an armed session (current state: %s); arm with lethe run or lethe arm", st.State)
	}
	if err := c.Call("events.subscribe", daemon.QueryParams{}, nil, nil); err != nil {
		return rpcErr(err)
	}
	_, _ = fmt.Fprintf(out, "Watching the egress interface for %d s...\n", int(learnWindow/time.Second))
	var evs []contracts.Event
	deadline := time.Now().Add(learnWindow)
	_ = c.SetDeadline(deadline)
	for {
		raw, err := c.ReadNotification()
		if err != nil {
			break // the deadline ends the window
		}
		var ev contracts.Event
		if json.Unmarshal(raw, &ev) == nil {
			evs = append(evs, ev)
		}
	}
	cs := learnCandidates(evs)
	printCandidates(out, cs)
	if len(cs) == 0 {
		return nil
	}
	ep, ok, err := chooseCandidate(bufio.NewReader(in), out, cs)
	if err != nil || !ok {
		return err
	}
	// the subscription connection has a stale deadline and pending pushes: use a fresh one
	c2, err := dialDaemon()
	if err != nil {
		return err
	}
	defer func() { _ = c2.Close() }()
	params := map[string]string{"endpoint": ep}
	proof, err := prove(c2, src, "discovery.confirm_endpoint", params)
	if err != nil {
		return err
	}
	if err := c2.Call("discovery.confirm_endpoint", params, proof, nil); err != nil {
		return rpcErr(err)
	}
	_, _ = fmt.Fprintf(out, "Endpoint %s confirmed and allowed in this session.\n", ep)
	return nil
}
