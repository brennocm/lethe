// Package netlinkmon watches links, routes and policy rules (RTM_* notifications) for
// NET-005/NET-006 and discovery refreshes (spec §7.4, §9.1).
package netlinkmon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// SourceID of this sensor (spec §9.7).
const SourceID = "netlink"

// rulePoll: vishvananda/netlink has no rule subscription; rules are diffed every second.
const rulePoll = time.Second

// LinkEvent is one RTM_NEWLINK/DELLINK.
type LinkEvent struct {
	Index   int
	Name    string
	Up      bool // IFF_UP
	Deleted bool
}

// RouteChange is one route or rule change (RTM_NEWROUTE/DELROUTE, rules by polling).
type RouteChange struct {
	Kind   string // route | rule
	Op     string // new | del
	Family string // ipv4 | ipv6
	Table  int
	Iface  string // routes only
	Dst    string // routes only, "default" for a zero-length prefix
	Mark   uint32 // rules only
}

// Tracker turns the raw link stream into "is it new / was it up" (pure, used by the daemon).
type Tracker struct {
	up map[int]bool
}

// NewTracker starts from the links present when the session begins (they are not "new").
func NewTracker(initial []LinkEvent) *Tracker {
	t := &Tracker{up: map[int]bool{}}
	for _, l := range initial {
		t.up[l.Index] = l.Up
	}
	return t
}

// Apply records ev and reports whether the link is new and whether it was up before.
func (t *Tracker) Apply(ev LinkEvent) (isNew, wasUp bool) {
	prev, known := t.up[ev.Index]
	if ev.Deleted {
		delete(t.up, ev.Index)
		return false, prev
	}
	t.up[ev.Index] = ev.Up
	return !known, prev
}

// Monitor streams link and route changes of the current network namespace.
type Monitor struct {
	mu    sync.Mutex
	names map[int]string
}

// Links lists the current links (the Tracker's initial state).
func Links() ([]LinkEvent, error) {
	ls, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("netlink links: %w", err)
	}
	out := make([]LinkEvent, 0, len(ls))
	for _, l := range ls {
		a := l.Attrs()
		out = append(out, LinkEvent{Index: a.Index, Name: a.Name, Up: a.Flags&net.FlagUp != 0})
	}
	return out, nil
}

// Run subscribes and forwards events until ctx ends; beat is called at least every second.
func (m *Monitor) Run(ctx context.Context, links chan<- LinkEvent, routes chan<- RouteChange, beat func(time.Time)) error {
	initial, err := Links()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.names = map[int]string{}
	for _, l := range initial {
		m.names[l.Index] = l.Name
	}
	m.mu.Unlock()

	done := make(chan struct{})
	defer close(done)
	errs := make(chan error, 2)
	cb := func(err error) {
		select {
		case errs <- err:
		default:
		}
	}
	lch := make(chan netlink.LinkUpdate, 64)
	if err := netlink.LinkSubscribeWithOptions(lch, done, netlink.LinkSubscribeOptions{ErrorCallback: cb}); err != nil {
		return fmt.Errorf("netlink link subscribe: %w", err)
	}
	rch := make(chan netlink.RouteUpdate, 256)
	if err := netlink.RouteSubscribeWithOptions(rch, done, netlink.RouteSubscribeOptions{ErrorCallback: cb}); err != nil {
		return fmt.Errorf("netlink route subscribe: %w", err)
	}
	rules, err := ruleSet()
	if err != nil {
		return err
	}
	tick := time.NewTicker(rulePoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			return fmt.Errorf("netlink subscription: %w", err)
		case u, ok := <-lch:
			if !ok {
				return fmt.Errorf("netlink link subscription closed")
			}
			ev := linkEvent(u)
			m.mu.Lock()
			m.names[ev.Index] = ev.Name
			m.mu.Unlock()
			send(ctx, links, ev)
		case u, ok := <-rch:
			if !ok {
				return fmt.Errorf("netlink route subscription closed")
			}
			m.mu.Lock()
			name := m.names[u.LinkIndex]
			m.mu.Unlock()
			send(ctx, routes, routeChange(u, name))
		case now := <-tick.C:
			cur, err := ruleSet()
			if err != nil {
				return err
			}
			for _, c := range diffRules(rules, cur) {
				send(ctx, routes, c)
			}
			rules = cur
			beat(now)
		}
	}
}

func send[T any](ctx context.Context, ch chan<- T, v T) {
	select {
	case ch <- v:
	case <-ctx.Done():
	}
}

func linkEvent(u netlink.LinkUpdate) LinkEvent {
	a := u.Attrs()
	return LinkEvent{Index: a.Index, Name: a.Name, Up: a.Flags&net.FlagUp != 0, Deleted: u.Header.Type == unix.RTM_DELLINK}
}

func family(f int) string {
	if f == unix.AF_INET6 {
		return "ipv6"
	}
	return "ipv4"
}

func routeChange(u netlink.RouteUpdate, iface string) RouteChange {
	op := "new"
	if u.Type == unix.RTM_DELROUTE {
		op = "del"
	}
	dst := "default"
	if u.Dst != nil {
		if ones, _ := u.Dst.Mask.Size(); ones > 0 || !u.Dst.IP.IsUnspecified() {
			dst = u.Dst.String()
		}
	}
	return RouteChange{Kind: "route", Op: op, Family: family(u.Family), Table: u.Table, Iface: iface, Dst: dst}
}

// rule is the comparable identity of a policy rule.
type rule struct {
	Family   int
	Priority int
	Table    int
	Mark     uint32
	Invert   bool
	Src, Dst string
	IifName  string
	OifName  string
	Suppress int
}

func ruleSet() (map[rule]bool, error) {
	rs, err := netlink.RuleListFiltered(netlink.FAMILY_ALL, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("netlink rules: %w", err)
	}
	out := map[rule]bool{}
	for _, r := range rs {
		k := rule{Family: r.Family, Priority: r.Priority, Table: r.Table, Mark: r.Mark, Invert: r.Invert,
			IifName: r.IifName, OifName: r.OifName, Suppress: r.SuppressPrefixlen}
		if r.Src != nil {
			k.Src = r.Src.String()
		}
		if r.Dst != nil {
			k.Dst = r.Dst.String()
		}
		out[k] = true
	}
	return out, nil
}

// diffRules is deterministic (sorted by priority, then table) for tests and logs.
func diffRules(prev, cur map[rule]bool) []RouteChange {
	var out []RouteChange
	add := func(set, other map[rule]bool, op string) {
		var ks []rule
		for k := range set {
			if !other[k] {
				ks = append(ks, k)
			}
		}
		sort.Slice(ks, func(i, j int) bool {
			if ks[i].Priority != ks[j].Priority {
				return ks[i].Priority < ks[j].Priority
			}
			return ks[i].Table < ks[j].Table
		})
		for _, k := range ks {
			out = append(out, RouteChange{Kind: "rule", Op: op, Family: family(k.Family), Table: k.Table, Mark: k.Mark})
		}
	}
	add(prev, cur, "del")
	add(cur, prev, "new")
	return out
}
