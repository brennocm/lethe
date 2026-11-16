package daemon

import (
	"fmt"
	"slices"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/engine"
	"lethe/internal/sensors/nflog"
)

// maxLearned bounds the endpoints learned or confirmed in one session, so a client (or whatever
// impersonates one) cannot grow the strict sets without limit.
const maxLearned = 64

// learnBlocked adds the destination of a blocked packet to the allowlist when the VPN client
// sent it (spec §7.4: a client reconnecting to a new server). Only packets dropped on the way out
// (inet output and the L2 egress chains) are considered.
func (d *Daemon) learnBlocked(s *session, b nflog.Blocked) {
	if p := strings.TrimSpace(b.Prefix); p != "LETHE-BLOCK" && p != "LETHE-L2" {
		return
	}
	proto, src, dst, ok := b.Leak.Tuple()
	if !ok {
		return
	}
	d.mu.Lock()
	clients := slices.Clone(d.snap.VPNClients)
	d.mu.Unlock()
	if len(clients) == 0 || d.cfg.Sockets == nil {
		return
	}
	socks, owners, err := d.cfg.Sockets() // fresh: the socket of a new connection is not in the last scan
	if err != nil {
		return
	}
	ep, ok := discovery.LearnBlocked(proto, src, dst, socks, owners, clients)
	if !ok {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s || d.eng.Session() != engine.StateArmed {
		return // never widen the allowlist during a panic
	}
	if d.addLearnedLocked(ep, contracts.EvDiscoveryEndpointLearned, contracts.SourceDaemon, map[string]any{"via": "nflog"}) == nil {
		d.refreshLocked()
	}
}

// ConfirmEndpoint is the operator naming the tunnel endpoint (spec §7.3; a sensitive method).
func (d *Daemon) ConfirmEndpoint(raw string) (map[string]any, error) {
	ep, err := parseEndpoint(raw)
	if err != nil {
		return nil, errParams(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return nil, errState(errNotArmed)
	}
	if err := d.addLearnedLocked(ep, contracts.EvDiscoveryEndpointConfirm, contracts.SourceOperator, nil); err != nil {
		return nil, errParams(err)
	}
	if d.eng.Session() == engine.StateArmed {
		d.refreshLocked()
	}
	return map[string]any{"endpoint": ep.String()}, nil
}

func (d *Daemon) addLearnedLocked(ep discovery.Endpoint, typ contracts.EventType, src contracts.Source, extra map[string]any) error {
	s := d.sess
	if slices.Contains(s.learned, ep) {
		return fmt.Errorf("endpoint %s already known", ep)
	}
	if len(s.learned) >= maxLearned {
		return fmt.Errorf("at most %d endpoints can be learned in one session", maxLearned)
	}
	s.learned = append(s.learned, ep)
	data := map[string]any{"endpoint": ep.String()}
	for k, v := range extra {
		data[k] = v
	}
	d.appendLocked(contracts.Event{Type: typ, Source: src, Data: data})
	return nil
}

func parseEndpoint(raw string) (discovery.Endpoint, error) {
	ep, err := discovery.ParseEndpoint(raw)
	if err != nil {
		return discovery.Endpoint{}, fmt.Errorf("endpoint must look like 203.0.113.10:51820/udp")
	}
	if a := ep.Addr.Addr(); a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
		return discovery.Endpoint{}, fmt.Errorf("endpoint must be a unicast address")
	}
	return ep, nil
}
