package capture

import (
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func dnsPayload(t *testing.T, d *layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encodeNB(name string) string {
	b := []byte(name)
	for len(b) < 15 {
		b = append(b, ' ')
	}
	b = append(b, 0)
	out := make([]byte, 0, 32)
	for _, c := range b {
		out = append(out, 'A'+c>>4, 'A'+c&0x0f)
	}
	return string(out)
}

func TestNET009_AnnouncedNames(t *testing.T) {
	mdns := dnsPayload(t, &layers.DNS{QR: true, Answers: []layers.DNSResourceRecord{
		{Name: []byte("Estacao-Real.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: []byte{192, 168, 1, 5}},
		{Name: []byte("estacao-real [aa:bb]._workstation._tcp.local"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TXTs: [][]byte{[]byte("x")}},
		{Name: []byte("_services._dns-sd._udp.local"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TXTs: [][]byte{[]byte("x")}},
	}})
	if got := announcedNames(5353, mdns); !reflect.DeepEqual(got, []string{"estacao-real", "estacao-real [aa:bb]"}) {
		t.Fatalf("mdns %q", got)
	}
	nbns := dnsPayload(t, &layers.DNS{Questions: []layers.DNSQuestion{{Name: []byte(encodeNB("ESTACAO-REAL")), Type: 0x20, Class: layers.DNSClassIN}}})
	if got := announcedNames(137, nbns); !reflect.DeepEqual(got, []string{"estacao-real"}) {
		t.Fatalf("nbns %q", got)
	}
	dg := append(make([]byte, 14), 0x20)
	dg = append(append(dg, encodeNB("WORKGROUP-PC")...), 0)
	if got := announcedNames(138, dg); !reflect.DeepEqual(got, []string{"workgroup-pc"}) {
		t.Fatalf("datagram %q", got)
	}
	ssdp := []byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nLOCATION: http://estacao-real:49152/desc.xml\r\n\r\n")
	if got := announcedNames(1900, ssdp); !reflect.DeepEqual(got, []string{"estacao-real"}) {
		t.Fatalf("ssdp %q", got)
	}
	if got := announcedNames(5353, []byte{1, 2}); got != nil {
		t.Fatalf("garbage %q", got)
	}
}

func FuzzAnnouncedNames(f *testing.F) {
	f.Add(uint16(5353), []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Add(uint16(138), make([]byte, 60))
	f.Add(uint16(1900), []byte("LOCATION: http://[::1]:80/\r\n"))
	f.Fuzz(func(_ *testing.T, port uint16, p []byte) {
		ports := []uint16{5353, 137, 138, 1900}
		_ = announcedNames(ports[port%4], p)
	})
}
