// Package nftmon snapshots the nftables tables of third parties (VPN kill switches, firewalls)
// so TUN-004 can tell when one changes or disappears during a session (spec §9.3).
package nftmon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// SourceID of this sensor.
const SourceID = "nftmon"

// Lister is the read side of *nftables.Conn.
type Lister interface {
	ListTables() ([]*nftables.Table, error)
	ListChains() ([]*nftables.Chain, error)
	GetRules(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error)
	GetSets(*nftables.Table) ([]*nftables.Set, error)
	GetSetElements(*nftables.Set) ([]nftables.SetElement, error)
}

// Table is one third-party table.
type Table struct {
	Name       string // "inet killswitch"
	Hash       string // content hash: chains, rules and sets, without counters or handles
	OutputDrop bool   // an output-hook chain drops (policy or rule): a kill switch
}

// Own are lethe's own tables ("family name"), the only ones Snapshot leaves out. Any other
// table counts, even one named lethe_*: the selftest table (ST-TUN-004) must be seen, and a
// third party cannot hide a table behind the prefix.
var Own = map[string]bool{"inet lethe": true, "inet lethe_panic": true, "netdev lethe_l2": true, "bridge lethe": true}

// Snapshot lists every table except lethe's own (Own), sorted by name.
func Snapshot(c Lister) ([]Table, error) {
	tables, err := c.ListTables()
	if err != nil {
		return nil, fmt.Errorf("nftmon: tables: %w", err)
	}
	chains, err := c.ListChains()
	if err != nil {
		return nil, fmt.Errorf("nftmon: chains: %w", err)
	}
	var out []Table
	for _, t := range tables {
		if Own[family(t.Family)+" "+t.Name] {
			continue
		}
		tb, err := describe(c, t, chains)
		if err != nil {
			return nil, err
		}
		out = append(out, tb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func describe(c Lister, t *nftables.Table, chains []*nftables.Chain) (Table, error) {
	tb := Table{Name: family(t.Family) + " " + t.Name}
	var lines []string
	sets, err := c.GetSets(t)
	if err != nil {
		return tb, fmt.Errorf("nftmon: sets of %s: %w", tb.Name, err)
	}
	for _, s := range sets {
		if s.Anonymous {
			continue
		}
		el, err := c.GetSetElements(s)
		if err != nil {
			return tb, fmt.Errorf("nftmon: elements of %s: %w", s.Name, err)
		}
		var es []string
		for _, e := range el {
			es = append(es, fmt.Sprintf("%x/%x/%v", e.Key, e.KeyEnd, e.IntervalEnd))
		}
		sort.Strings(es)
		lines = append(lines, fmt.Sprintf("set %s %s [%s]", s.Name, s.KeyType.Name, strings.Join(es, " ")))
	}
	for _, ch := range chains {
		if ch.Table.Name != t.Name || ch.Table.Family != t.Family {
			continue
		}
		hook, out := "-", false
		if ch.Hooknum != nil {
			hook = fmt.Sprint(*ch.Hooknum)
			out = *ch.Hooknum == *nftables.ChainHookOutput && t.Family != nftables.TableFamilyNetdev
		}
		pol := "-"
		if ch.Policy != nil {
			pol = fmt.Sprint(*ch.Policy)
			if out && *ch.Policy == nftables.ChainPolicyDrop {
				tb.OutputDrop = true
			}
		}
		prio := "-"
		if ch.Priority != nil {
			prio = fmt.Sprint(*ch.Priority)
		}
		lines = append(lines, fmt.Sprintf("chain %s hook=%s prio=%s policy=%s dev=%s", ch.Name, hook, prio, pol, ch.Device))
		rules, err := c.GetRules(t, ch)
		if err != nil {
			return tb, fmt.Errorf("nftmon: rules of %s: %w", ch.Name, err)
		}
		for _, r := range rules {
			var es []string
			for _, e := range r.Exprs {
				if out && drops(e) {
					tb.OutputDrop = true
				}
				b, _ := json.Marshal(static(e))
				es = append(es, fmt.Sprintf("%T%s", e, b))
			}
			lines = append(lines, "  rule "+strings.Join(es, " "))
		}
	}
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	tb.Hash = hex.EncodeToString(h[:16])
	return tb, nil
}

func drops(e expr.Any) bool {
	switch v := e.(type) {
	case *expr.Verdict:
		return v.Kind == expr.VerdictDrop
	case *expr.Reject:
		return true
	}
	return false
}

// static strips the state the kernel updates on its own (counters, quota usage), so traffic
// alone never looks like a change.
func static(e expr.Any) expr.Any {
	switch v := e.(type) {
	case *expr.Counter:
		return &expr.Counter{}
	case *expr.Quota:
		q := *v
		q.Consumed = 0
		return &q
	}
	return e
}

func family(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyNetdev:
		return "netdev"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyARP:
		return "arp"
	}
	return fmt.Sprintf("family%d", f)
}
