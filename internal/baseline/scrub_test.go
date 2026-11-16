package baseline

import (
	"strings"
	"testing"
	"time"
)

func scrubBase(t *testing.T) *Baseline {
	t.Helper()
	b, err := New(time.Unix(0, 0), "test")
	if err != nil {
		t.Fatal(err)
	}
	b.Hostname, b.Username = "host-exemplo", "operador"
	b.PermMACs = []string{"aa:bb:cc:dd:ee:01"}
	b.Networks = []Network{{Name: "casa", PublicIPv4: "203.0.113.50", GatewayIP: "192.168.1.1", Resolvers: []string{"192.168.1.1", "2001:db8::53"}, SSIDs: []string{"RedeCasa"}}}
	return b
}

// No baseline value reaches an event: matches are recorded by field name (spec §12.1).
func TestBaseline_ScrubEventData(t *testing.T) {
	b := scrubBase(t)
	type proc struct {
		PID int    `json:"pid"`
		Exe string `json:"exe"`
	}
	in := map[string]any{
		"dst": "192.168.1.1", "dport": 53, "iface": "eth0", "src_mac": "AA:BB:CC:DD:EE:01",
		"peer":   "[2001:db8:0::53]:53",
		"proc":   proc{PID: 7, Exe: "/home/Operador/bin/dig"},
		"qname":  map[string]any{"enc": "s1", "n": "operador", "ct": "x"},
		"note":   "seen on RedeCasa from host-exemplo",
		"other":  "192.168.1.10",
		"hosts":  []any{"203.0.113.50"},
		"benign": "nothing here",
	}
	out, err := b.Scrub(in)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"dst": "[baseline]", "src_mac": "[baseline]", "peer": "[baseline]", "other": "192.168.1.10",
		"note": "seen on [baseline] from [baseline]", "benign": "nothing here"}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("%s = %v, want %v", k, out[k], v)
		}
	}
	if out["proc"].(map[string]any)["exe"] != "/home/[baseline]/bin/dig" || out["hosts"].([]any)[0] != "[baseline]" {
		t.Errorf("nested: %v %v", out["proc"], out["hosts"])
	}
	if out["qname"].(map[string]any)["n"] != "operador" {
		t.Error("sealed fields must not be rewritten")
	}
	m := out["matched"].(string)
	for _, f := range []string{"baseline.username", "baseline.hostname", "baseline.perm_macs", "baseline.networks[0].gateway_ip", "baseline.networks[0].resolvers", "baseline.networks[0].ssids", "baseline.networks[0].public_ipv4"} {
		if !strings.Contains(m, f) {
			t.Errorf("matched %q lacks %s", m, f)
		}
	}
	o2, _ := b.Scrub(map[string]any{"dst": "192.168.1.1"}) // gateway and resolver at once
	if o2["matched"] != "baseline.networks[0].gateway_ip,baseline.networks[0].resolvers" {
		t.Errorf("a value in two fields names both: %v", o2["matched"])
	}
	if _, ok := in["matched"]; ok || in["dst"] != "192.168.1.1" {
		t.Error("the input must not be modified (responses use it)")
	}
}

func TestBaseline_RedactIsCaseInsensitive(t *testing.T) {
	b := scrubBase(t)
	if got := b.Redact("mac=AA:BB:CC:DD:EE:01 host=HOST-EXEMPLO"); got != "mac=[baseline] host=[baseline]" {
		t.Fatalf("%q", got)
	}
}
