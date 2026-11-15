package guard

import (
	"errors"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Features are the optional kernel capabilities the generator depends on (spec §11.2, §11.5).
type Features struct {
	L2           bool // netdev egress hook (>= 5.16, CONFIG_NETFILTER_EGRESS)
	SocketCgroup bool // nft_socket with cgroupv2 (CONFIG_NFT_SOCKET)
	Bridge       bool // nf_tables bridge family (CONFIG_NF_TABLES_BRIDGE)
}

// ProbeTable is the scratch table used by Probe; it never holds a base chain that filters.
const ProbeTable = "lethe_probe"

// Probe loads tiny throwaway tables, each in its own transaction, to learn what the kernel
// supports. Nothing is left behind and no traffic is affected (no hook is attached with a
// drop, and the probes are deleted in the same transaction).
func Probe(c Conn) (Features, error) {
	var f Features
	try := func(build func(t *nftables.Table)) (bool, error) {
		return tryTx(c, build)
	}
	var err error
	if f.SocketCgroup, err = try(func(t *nftables.Table) {
		pol := nftables.ChainPolicyAccept
		ch := c.AddChain(&nftables.Chain{Name: "p", Table: t, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &pol})
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: []expr.Any{
			&expr.Socket{Key: expr.SocketKeyCgroupv2, Level: 1, Register: reg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: make([]byte, 8)},
		}})
	}); err != nil {
		return f, err
	}
	if f.L2, err = tryL2(c); err != nil {
		return f, err
	}
	f.Bridge, err = tryFamily(c, nftables.TableFamilyBridge)
	return f, err
}

func tryTx(c Conn, build func(t *nftables.Table)) (bool, error) {
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: ProbeTable}
	c.AddTable(t)
	build(t)
	c.DelTable(t)
	return flushOK(c)
}

func tryL2(c Conn) (bool, error) {
	t := &nftables.Table{Family: nftables.TableFamilyNetdev, Name: ProbeTable}
	c.AddTable(t)
	pol := nftables.ChainPolicyAccept
	prio := nftables.ChainPriority(prioL2)
	c.AddChain(&nftables.Chain{Name: "p", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookEgress, Priority: &prio, Policy: &pol, Device: "lo"})
	c.DelTable(t)
	return flushOK(c)
}

func tryFamily(c Conn, fam nftables.TableFamily) (bool, error) {
	t := &nftables.Table{Family: fam, Name: ProbeTable}
	c.AddTable(t)
	c.DelTable(t)
	return flushOK(c)
}

// flushOK maps "the kernel does not know this" to false and permission problems to an error.
func flushOK(c Conn) (bool, error) {
	err := c.Flush()
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, errPerm()):
		return false, err
	default:
		return false, nil
	}
}
