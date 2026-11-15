//go:build e2e

package e2e

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/nftables"

	"lethe/internal/cli"
	"lethe/internal/guard"
	"lethe/test/netlab"
)

func TestE2E_AC09_CleanupCommand(t *testing.T) {
	netlab.New(t, true)
	c := nft(t)
	foreign := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "killswitch"})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	defer func() { c := nft(t); c.DelTable(foreign); _ = c.Flush() }()
	rs, _ := guard.Strict(labConfig())
	if err := guard.Apply(nft(t), rs); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := cli.Execute([]string{"cleanup"}, &out, &errb); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "removed table inet lethe") || !strings.Contains(out.String(), "removed table netdev lethe_l2") {
		t.Fatalf("output %q", out.String())
	}
	d := dump(t)
	if strings.Contains(d, "lethe") || !strings.Contains(d, "killswitch") {
		t.Fatalf("after cleanup:\n%s", d)
	}
	out.Reset()
	if code := cli.Execute([]string{"cleanup"}, &out, &errb); code != cli.ExitOK || !strings.Contains(out.String(), "no lethe tables") {
		t.Fatalf("second run: %d %q", code, out.String())
	}
}
