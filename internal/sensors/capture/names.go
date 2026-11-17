package capture

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const maxNames = 16

// announcedNames extracts the hostnames a LAN broadcast reveals (NET-009, spec §9.1): the names
// of mDNS/LLMNR questions and answers, the NetBIOS name of NBNS and datagram packets, and the
// host of an SSDP LOCATION. Names are normalized (lower case, no ".local", no trailing dot).
func announcedNames(dport uint16, p []byte) []string {
	var out []string
	add := func(n string) {
		n = normalizeName(n)
		if n == "" || len(out) >= maxNames {
			return
		}
		for _, x := range out {
			if x == n {
				return
			}
		}
		out = append(out, n)
	}
	switch dport {
	case 5353, 5355:
		var d layers.DNS
		if d.DecodeFromBytes(p, gopacket.NilDecodeFeedback) != nil {
			return nil
		}
		for _, q := range d.Questions {
			add(string(q.Name))
		}
		for _, rs := range [][]layers.DNSResourceRecord{d.Answers, d.Additionals} {
			for _, r := range rs {
				add(string(r.Name))
				if r.Type == layers.DNSTypeSRV {
					add(string(r.SRV.Name))
				}
			}
		}
	case 137:
		// NBNS shares the DNS wire format; the name is first-level encoded.
		var d layers.DNS
		if d.DecodeFromBytes(p, gopacket.NilDecodeFeedback) != nil {
			return nil
		}
		for _, q := range d.Questions {
			add(netbiosName(string(q.Name)))
		}
		for _, r := range d.Additionals {
			add(netbiosName(string(r.Name)))
		}
	case 138:
		// datagram header (14 bytes, 10 for errors) then the encoded source name
		if len(p) >= 14+34 && p[14] == 0x20 {
			add(netbiosName(string(p[15 : 15+32])))
		}
	case 1900:
		for _, line := range bytes.Split(p, []byte("\n")) {
			k, v, ok := bytes.Cut(line, []byte(":"))
			if !ok || !strings.EqualFold(strings.TrimSpace(string(k)), "location") {
				continue
			}
			if u, err := url.Parse(strings.TrimSpace(string(v))); err == nil {
				add(u.Hostname())
			}
		}
	}
	return out
}

// netbiosName decodes a first-level encoded NetBIOS name (32 letters A..P, two per byte) and
// drops the suffix byte and the space padding.
func netbiosName(enc string) string {
	enc, _, _ = strings.Cut(enc, ".") // scope
	if len(enc) != 32 {
		return ""
	}
	b := make([]byte, 16)
	for i := range 16 {
		hi, lo := enc[2*i]-'A', enc[2*i+1]-'A'
		if hi > 15 || lo > 15 {
			return ""
		}
		b[i] = hi<<4 | lo
	}
	return strings.TrimRight(string(b[:15]), " \x00")
}

func normalizeName(n string) string {
	n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
	n = strings.TrimSuffix(n, ".local")
	if inst, _, ok := strings.Cut(n, "._"); ok {
		n = inst // "estacao [mac]._workstation._tcp": the instance often carries the hostname
	}
	if strings.HasPrefix(n, "_") || n == "" || strings.HasSuffix(n, ".arpa") {
		return ""
	}
	return strings.ToValidUTF8(n, "")
}
