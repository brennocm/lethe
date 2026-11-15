package guard

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Conn is the subset of *nftables.Conn the guard uses.
type Conn interface {
	AddTable(*nftables.Table) *nftables.Table
	DelTable(*nftables.Table)
	AddSet(*nftables.Set, []nftables.SetElement) error
	FlushSet(*nftables.Set)
	SetAddElements(*nftables.Set, []nftables.SetElement) error
	AddChain(*nftables.Chain) *nftables.Chain
	AddRule(*nftables.Rule) *nftables.Rule
	ListTables() ([]*nftables.Table, error)
	Flush() error
}

// Apply installs every table of rs in ONE netlink transaction; each table replaces an existing
// one with the same family and name (add + delete + add inside the batch).
func Apply(c Conn, rs Ruleset) error {
	for _, t := range rs.Tables {
		if !strings.HasPrefix(t.Name, Prefix) {
			return fmt.Errorf("guard: refusing to manage table %q (not %s*)", t.Name, Prefix)
		}
		nt := &nftables.Table{Family: t.Family, Name: t.Name}
		c.AddTable(nt)
		c.DelTable(nt)
		c.AddTable(nt)
		sets := map[string]*nftables.Set{}
		for _, s := range t.Sets {
			ns := nftSet(nt, s)
			if err := c.AddSet(ns, elements(s)); err != nil {
				return fmt.Errorf("guard: set %s: %w", s.Name, err)
			}
			sets[s.Name] = ns
		}
		for _, ch := range t.Chains {
			pol := ch.Policy
			prio := nftables.ChainPriority(ch.Priority)
			nc := c.AddChain(&nftables.Chain{Name: ch.Name, Table: nt, Hooknum: ch.Hook, Priority: &prio,
				Type: nftables.ChainTypeFilter, Policy: &pol, Device: ch.Device})
			for _, r := range ch.Rules {
				exprs, err := bindSets(r.Exprs, sets)
				if err != nil {
					return err
				}
				c.AddRule(&nftables.Rule{Table: nt, Chain: nc, Exprs: exprs})
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("guard: apply: %w", err)
	}
	return nil
}

func nftSet(t *nftables.Table, s *Set) *nftables.Set {
	// ID 0: the library allocates a transaction-unique ID, which bindSets copies into lookups
	return &nftables.Set{Table: t, Name: s.Name, KeyType: s.Key, Concatenation: s.Concat, Interval: s.Interval}
}

// bindSets copies the rule expressions, pointing each lookup at the set's transaction ID.
func bindSets(in []expr.Any, sets map[string]*nftables.Set) ([]expr.Any, error) {
	out := make([]expr.Any, len(in))
	for i, e := range in {
		if l, ok := e.(*expr.Lookup); ok {
			s, ok := sets[l.SetName]
			if !ok {
				return nil, fmt.Errorf("guard: rule uses undefined set %s", l.SetName)
			}
			cp := *l
			cp.SetID = s.ID
			e = &cp
		}
		out[i] = e
	}
	return out, nil
}

func elements(s *Set) []nftables.SetElement {
	var out []nftables.SetElement
	for _, e := range s.Elems {
		out = append(out, nftables.SetElement{Key: e.Key})
		if s.Interval {
			out = append(out, nftables.SetElement{Key: e.End, IntervalEnd: true})
		}
	}
	return out
}

// UpdateSets replaces the elements of every set of rs that exists in the installed tables, in
// one transaction (allowlist changes without touching the chains).
func UpdateSets(c Conn, rs Ruleset) error {
	for _, t := range rs.Tables {
		nt := &nftables.Table{Family: t.Family, Name: t.Name}
		for _, s := range t.Sets {
			ns := nftSet(nt, s)
			c.FlushSet(ns)
			if el := elements(s); len(el) > 0 {
				if err := c.SetAddElements(ns, el); err != nil {
					return fmt.Errorf("guard: set %s: %w", s.Name, err)
				}
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("guard: update sets: %w", err)
	}
	return nil
}

// Remove deletes the named tables (family, name) that exist, in one transaction.
func Remove(c Conn, which ...TableRef) error {
	have, err := c.ListTables()
	if err != nil {
		return fmt.Errorf("guard: list tables: %w", err)
	}
	n := 0
	for _, w := range which {
		if !strings.HasPrefix(w.Name, Prefix) {
			return fmt.Errorf("guard: refusing to remove table %q (not %s*)", w.Name, Prefix)
		}
		for _, t := range have {
			if t.Family == w.Family && t.Name == w.Name {
				c.DelTable(t)
				n++
			}
		}
	}
	if n == 0 {
		return nil
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("guard: remove: %w", err)
	}
	return nil
}

// TableRef names a table.
type TableRef struct {
	Family nftables.TableFamily
	Name   string
}

// All is every table the guard can create (disarm, §11.6).
func All() []TableRef {
	return []TableRef{
		{nftables.TableFamilyINet, TableStrict}, {nftables.TableFamilyINet, TablePanic},
		{nftables.TableFamilyNetdev, TableL2}, {nftables.TableFamilyBridge, TableBridge},
	}
}

// Cleanup removes every table whose name starts with "lethe", in any family, and nothing else
// (lethe cleanup, after a crash). It returns the removed tables.
func Cleanup(c Conn) ([]TableRef, error) {
	have, err := c.ListTables()
	if err != nil {
		return nil, fmt.Errorf("guard: list tables: %w", err)
	}
	var out []TableRef
	for _, t := range have {
		if strings.HasPrefix(t.Name, Prefix) {
			out = append(out, TableRef{t.Family, t.Name})
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Name < out[j].Name
	})
	return out, Remove(c, out...)
}

// CgroupID returns the cgroup v2 ID of dir (the kernfs inode number, which is what
// "socket cgroupv2" compares) and its level below root.
func CgroupID(root, dir string) (Cgroup, error) {
	rel := strings.Trim(strings.TrimPrefix(dir, root), "/")
	if !strings.HasPrefix(dir, root) || rel == "" {
		return Cgroup{}, fmt.Errorf("guard: cgroup %s is not below %s", dir, root)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return Cgroup{}, fmt.Errorf("guard: cgroup: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() {
		return Cgroup{}, errors.New("guard: cgroup path is not a directory")
	}
	return Cgroup{Path: rel, Level: uint32(strings.Count(rel, "/") + 1), ID: st.Ino}, nil // #nosec G115 -- depth is small
}

func errPerm() error { return syscall.EPERM }
