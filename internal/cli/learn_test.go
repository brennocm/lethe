package cli

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"lethe/internal/contracts"
)

func leakEv(check, proto, dst string, dport int, exe string) contracts.Event {
	d := map[string]any{"proto": proto, "dst": dst, "dport": dport}
	if exe != "" {
		d["proc"] = map[string]any{"exe": exe}
	}
	return contracts.Event{Type: contracts.EvCheckAlert, Check: check, Data: d}
}

func TestDiscover_LearnGroupsDestinations(t *testing.T) {
	evs := []contracts.Event{
		leakEv("NET-002", "udp", "198.51.100.20", 1194, "/usr/sbin/openvpn"),
		leakEv("NET-002", "udp", "198.51.100.20", 1194, "/usr/sbin/openvpn"),
		leakEv("NET-002", "udp", "198.51.100.20", 1194, "/usr/sbin/openvpn"),
		leakEv("NET-001", "tcp", "2001:db8::5", 443, ""),
		leakEv("NET-002", "icmp", "192.0.2.1", 0, ""),          // no port: not an endpoint
		leakEv("DNS-001", "udp", "192.0.2.53", 53, ""),         // not an egress leak check
		{Type: contracts.EvDiscoveryChanged, Check: "NET-001"}, // not an alert
	}
	cs := learnCandidates(evs)
	if len(cs) != 2 || cs[0].Endpoint != "198.51.100.20:1194/udp" || cs[0].Count != 3 || cs[1].Endpoint != "[2001:db8::5]:443/tcp" {
		t.Fatalf("%+v", cs)
	}
	var out bytes.Buffer
	printCandidates(&out, cs)
	if !strings.Contains(out.String(), "cliente VPN") || !strings.Contains(out.String(), "processo desconhecido") {
		t.Fatal(out.String())
	}
	for in, want := range map[string]string{"1\n": "198.51.100.20:1194/udp", "\n": "", "": ""} {
		got, ok, err := chooseCandidate(bufio.NewReader(strings.NewReader(in)), &out, cs)
		if err != nil || got != want || ok != (want != "") {
			t.Fatalf("%q: %q %v %v", in, got, ok, err)
		}
	}
	for _, bad := range []string{"0\n", "3\n", "x\n"} {
		if _, _, err := chooseCandidate(bufio.NewReader(strings.NewReader(bad)), &out, cs); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
