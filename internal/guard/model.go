// Package guard generates and applies the lethe* nftables tables (spec §11). Every table is
// built as a Ruleset (pure, golden-tested through Render) and applied in one netlink
// transaction. Only tables whose name starts with "lethe" are ever created or removed.
package guard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Prefix of every table this package owns.
const Prefix = "lethe"

// Table names (spec §11.3–§11.5).
const (
	TableStrict = "lethe"
	TablePanic  = "lethe_panic"
	TableL2     = "lethe_l2"
	TableBridge = "lethe" // family bridge
)

// Ruleset is a list of tables to install (each replaces any table of the same family+name).
type Ruleset struct {
	Tables []*Table
}

// Table is one nftables table.
type Table struct {
	Family nftables.TableFamily
	Name   string
	Sets   []*Set
	Chains []*Chain
}

// Set is a named set with its elements.
type Set struct {
	Name     string
	TypeText string // as nft prints it
	Key      nftables.SetDatatype
	Concat   bool
	Interval bool
	Elems    []Elem
}

// Elem is one set element. End is the exclusive end of an interval element.
type Elem struct {
	Text string
	Key  []byte
	End  []byte
}

// Chain is a base chain.
type Chain struct {
	Name     string
	Hook     *nftables.ChainHook
	HookText string
	Priority int32
	Policy   nftables.ChainPolicy
	Device   string
	Rules    []Rule
}

// Rule pairs the nft text (for the golden test and logs) with the expressions sent to the kernel.
type Rule struct {
	Text  string
	Exprs []expr.Any
}

// Find returns the table of the given family and name.
func (r Ruleset) Find(f nftables.TableFamily, name string) *Table {
	for _, t := range r.Tables {
		if t.Family == f && t.Name == name {
			return t
		}
	}
	return nil
}

// Set returns the named set of the table.
func (t *Table) Set(name string) *Set {
	for _, s := range t.Sets {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// FamilyName prints a table family as nft does.
func FamilyName(f nftables.TableFamily) string { return familyName(f) }

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyNetdev:
		return "netdev"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyARP:
		return "arp"
	default:
		return fmt.Sprintf("family-%d", f)
	}
}

// Render prints the ruleset in nft syntax (deterministic: set elements sorted).
func (r Ruleset) Render() string {
	var b strings.Builder
	for i, t := range r.Tables {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "table %s %s {\n", familyName(t.Family), t.Name)
		for _, s := range t.Sets {
			fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s;\n", s.Name, s.TypeText)
			if s.Interval {
				b.WriteString("\t\tflags interval;\n")
			}
			if len(s.Elems) > 0 {
				el := make([]string, 0, len(s.Elems))
				for _, e := range s.Elems {
					el = append(el, e.Text)
				}
				sort.Strings(el)
				fmt.Fprintf(&b, "\t\telements = { %s };\n", strings.Join(el, ", "))
			}
			b.WriteString("\t}\n")
		}
		for _, c := range t.Chains {
			policy := "accept"
			if c.Policy == nftables.ChainPolicyDrop {
				policy = "drop"
			}
			dev := ""
			if c.Device != "" {
				dev = fmt.Sprintf(" device %q", c.Device)
			}
			fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s%s priority %d; policy %s;\n", c.Name, c.HookText, dev, c.Priority, policy)
			for _, r := range c.Rules {
				fmt.Fprintf(&b, "\t\t%s\n", r.Text)
			}
			b.WriteString("\t}\n")
		}
		b.WriteString("}\n")
	}
	return b.String()
}
