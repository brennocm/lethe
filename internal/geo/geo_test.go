package geo

import (
	"net/netip"
	"testing"

	"lethe/internal/geo/geotest"
)

func TestTUN006_MMDBLookup(t *testing.T) {
	country := geotest.Write("DBIP-Country-Lite", map[netip.Prefix]map[string]any{
		netip.MustParsePrefix("198.51.100.0/24"): {"country": map[string]any{"iso_code": "nl"}},
		netip.MustParsePrefix("2001:db8::/32"):   {"country": map[string]any{"iso_code": "SE"}},
	})
	asn := geotest.Write("DBIP-ASN-Lite", map[netip.Prefix]map[string]any{
		netip.MustParsePrefix("198.51.100.0/25"): {"autonomous_system_number": uint32(64500), "autonomous_system_organization": "Example VPN"},
	})
	db, err := Open(country, asn)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := db.Lookup(netip.MustParseAddr("198.51.100.7"))
	if !ok || got != (Info{Country: "NL", ASN: 64500, Org: "Example VPN"}) {
		t.Fatalf("%+v %v", got, ok)
	}
	if got, _ := db.Lookup(netip.MustParseAddr("198.51.100.200")); got.ASN != 0 || got.Country != "NL" {
		t.Fatalf("%+v", got)
	}
	if got, _ := db.Lookup(netip.MustParseAddr("2001:db8::1")); got.Country != "SE" {
		t.Fatalf("%+v", got)
	}
	if _, ok := db.Lookup(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("not in the database")
	}
	if db.Built().IsZero() {
		t.Fatal("build date")
	}
	if _, err := Open(nil, nil); err == nil {
		t.Fatal("no data")
	}
	if _, err := Open([]byte("garbage"), nil); err == nil {
		t.Fatal("garbage accepted")
	}
}

// This repository has no data files: the embedded database is absent and says so.
func TestTUN006_EmbeddedWithoutData(t *testing.T) {
	if _, err := Embedded(); err == nil {
		t.Skip("this build embeds the geo data")
	}
}
