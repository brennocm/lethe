package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/nftables"
)

// Lister is what Dump needs from *nftables.Conn.
type Lister interface {
	ListTables() ([]*nftables.Table, error)
	ListChains() ([]*nftables.Chain, error)
	GetRules(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error)
	GetSets(*nftables.Table) ([]*nftables.Set, error)
	GetSetElements(*nftables.Set) ([]nftables.SetElement, error)
}

// Dump renders the whole ruleset canonically (tables, sets with elements, chains, rule
// expressions), for AC-13 comparisons and TUN-004. Handles and set IDs are left out.
func Dump(c Lister) (string, error) {
	tables, err := c.ListTables()
	if err != nil {
		return "", fmt.Errorf("dump: tables: %w", err)
	}
	chains, err := c.ListChains()
	if err != nil {
		return "", fmt.Errorf("dump: chains: %w", err)
	}
	var lines []string
	for _, t := range tables {
		tl := fmt.Sprintf("table %s %s", familyName(t.Family), t.Name)
		lines = append(lines, tl)
		sets, err := c.GetSets(t)
		if err != nil {
			return "", fmt.Errorf("dump: sets of %s: %w", t.Name, err)
		}
		for _, s := range sets {
			if s.Anonymous {
				continue
			}
			el, err := c.GetSetElements(s)
			if err != nil {
				return "", fmt.Errorf("dump: elements of %s: %w", s.Name, err)
			}
			var es []string
			for _, e := range el {
				es = append(es, fmt.Sprintf("%x/%x/%v", e.Key, e.KeyEnd, e.IntervalEnd))
			}
			sort.Strings(es)
			lines = append(lines, fmt.Sprintf("%s set %s %s [%s]", tl, s.Name, s.KeyType.Name, strings.Join(es, " ")))
		}
		for _, ch := range chains {
			if ch.Table.Name != t.Name || ch.Table.Family != t.Family {
				continue
			}
			hk, prio, pol := "-", "-", "-"
			if ch.Hooknum != nil {
				hk = fmt.Sprint(*ch.Hooknum)
			}
			if ch.Priority != nil {
				prio = fmt.Sprint(*ch.Priority)
			}
			if ch.Policy != nil {
				pol = fmt.Sprint(*ch.Policy)
			}
			cl := fmt.Sprintf("%s chain %s hook=%s prio=%s policy=%s dev=%s", tl, ch.Name, hk, prio, pol, ch.Device)
			lines = append(lines, cl)
			rules, err := c.GetRules(t, ch)
			if err != nil {
				return "", fmt.Errorf("dump: rules of %s: %w", ch.Name, err)
			}
			for _, r := range rules {
				var es []string
				for _, e := range r.Exprs {
					b, _ := json.Marshal(e)
					es = append(es, fmt.Sprintf("%T%s", e, b))
				}
				lines = append(lines, cl+" rule "+strings.Join(es, " "))
			}
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n"), nil
}

// WatchCgroup polls the VPN client's cgroup and calls onChange when its ID changes or it
// disappears (ok=false), so the socket cgroupv2 rule can be regenerated (spec §11.2).
func WatchCgroup(ctx context.Context, root, dir string, every time.Duration, cur Cgroup, onChange func(Cgroup, bool)) {
	t := time.NewTicker(every)
	defer t.Stop()
	gone := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cg, err := CgroupID(root, dir)
			switch {
			case err != nil && !gone:
				gone = true
				onChange(Cgroup{}, false)
			case err == nil && (gone || cg.ID != cur.ID):
				gone = false
				cur = cg
				onChange(cg, true)
			}
		}
	}
}
