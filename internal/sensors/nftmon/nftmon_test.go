package nftmon

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type fake struct {
	tables []*nftables.Table
	chains []*nftables.Chain
	rules  map[string][]*nftables.Rule
}

func (f *fake) ListTables() ([]*nftables.Table, error) { return f.tables, nil }
func (f *fake) ListChains() ([]*nftables.Chain, error) { return f.chains, nil }
func (f *fake) GetRules(_ *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	return f.rules[c.Name], nil
}
func (f *fake) GetSets(*nftables.Table) ([]*nftables.Set, error)            { return nil, nil }
func (f *fake) GetSetElements(*nftables.Set) ([]nftables.SetElement, error) { return nil, nil }

func killswitch(counter uint64) *fake {
	ks := &nftables.Table{Family: nftables.TableFamilyINet, Name: "killswitch"}
	ours := &nftables.Table{Family: nftables.TableFamilyINet, Name: "lethe"}
	accept := nftables.ChainPolicyAccept
	return &fake{
		tables: []*nftables.Table{ks, ours},
		chains: []*nftables.Chain{
			{Name: "out", Table: ks, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &accept},
			{Name: "output", Table: ours, Hooknum: nftables.ChainHookOutput},
		},
		rules: map[string][]*nftables.Rule{"out": {{Exprs: []expr.Any{&expr.Counter{Packets: counter}, &expr.Verdict{Kind: expr.VerdictDrop}}}}},
	}
}

func TestTUN004_Snapshot(t *testing.T) {
	a, err := Snapshot(killswitch(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0].Name != "inet killswitch" || !a[0].OutputDrop {
		t.Fatalf("got %+v (lethe tables must be left out)", a)
	}
	b, _ := Snapshot(killswitch(99))
	if a[0].Hash != b[0].Hash {
		t.Fatal("counters must not change the hash")
	}
	f := killswitch(1)
	f.rules["out"][0].Exprs[1] = &expr.Verdict{Kind: expr.VerdictAccept}
	c, _ := Snapshot(f)
	if c[0].Hash == a[0].Hash || c[0].OutputDrop {
		t.Fatalf("a changed verdict must change the hash and drop detection: %+v", c)
	}
}

// A table named lethe_* that is not one of lethe's own counts (ST-TUN-004, no hiding place).
func TestTUN004_PrefixIsNoHidingPlace(t *testing.T) {
	f := killswitch(1)
	f.tables = append(f.tables, &nftables.Table{Family: nftables.TableFamilyINet, Name: "lethe_selftest"},
		&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "lethe"})
	got, err := Snapshot(f)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range got {
		names = append(names, x.Name)
	}
	if strings.Join(names, ",") != "inet killswitch,inet lethe_selftest,ip lethe" {
		t.Fatal(names)
	}
}
