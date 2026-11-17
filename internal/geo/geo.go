// Package geo answers country and ASN for an address from the offline database (spec §20.1):
// DB-IP Lite Country and ASN, embedded at release time by scripts/update-geo. A build without
// the files reports ErrNoDatabase, and the checks that need it stay inactive instead of guessing.
package geo

import (
	"embed"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Info is what the database knows about one address.
type Info struct {
	Country string // ISO 3166-1 alpha-2, upper case
	ASN     uint32 // 0 = unknown
	Org     string // the AS organisation (the provider), "" = unknown
}

// DB looks addresses up. ok is false when the address is not in the database.
type DB interface {
	Lookup(a netip.Addr) (info Info, ok bool)
}

// ErrNoDatabase means no geo database is embedded in this build.
var ErrNoDatabase = errors.New("geo: no database in this build (scripts/update-geo embeds DB-IP Lite at release)")

// File names under data/ (scripts/update-geo).
const (
	CountryFile = "dbip-country-lite.mmdb"
	ASNFile     = "dbip-asn-lite.mmdb"
)

//go:embed data
var data embed.FS

// MMDB is a country database and an ASN database (either may be nil).
type MMDB struct {
	country, asn *maxminddb.Reader
	built        time.Time
}

// Open reads the two databases from memory. At least one must be present.
func Open(country, asn []byte) (*MMDB, error) {
	m := &MMDB{}
	var err error
	if len(country) > 0 {
		if m.country, err = maxminddb.OpenBytes(country); err != nil {
			return nil, fmt.Errorf("geo: country database: %w", err)
		}
		m.built = time.Unix(int64(m.country.Metadata.BuildEpoch), 0).UTC() // #nosec G115 -- a timestamp
	}
	if len(asn) > 0 {
		if m.asn, err = maxminddb.OpenBytes(asn); err != nil {
			return nil, fmt.Errorf("geo: ASN database: %w", err)
		}
		if b := time.Unix(int64(m.asn.Metadata.BuildEpoch), 0).UTC(); m.built.IsZero() || b.Before(m.built) { // #nosec G115
			m.built = b
		}
	}
	if m.country == nil && m.asn == nil {
		return nil, ErrNoDatabase
	}
	return m, nil
}

// Built is the build date of the oldest database (version and report show it, spec §22 item 7).
func (m *MMDB) Built() time.Time { return m.built }

// Lookup implements DB.
func (m *MMDB) Lookup(a netip.Addr) (Info, bool) {
	a = a.Unmap()
	var info Info
	found := false
	if m.country != nil {
		var rec struct {
			Country struct {
				ISO string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if r := m.country.Lookup(a); r.Found() && r.Decode(&rec) == nil && rec.Country.ISO != "" {
			info.Country, found = strings.ToUpper(rec.Country.ISO), true
		}
	}
	if m.asn != nil {
		var rec struct {
			ASN uint32 `maxminddb:"autonomous_system_number"`
			Org string `maxminddb:"autonomous_system_organization"`
		}
		if r := m.asn.Lookup(a); r.Found() && r.Decode(&rec) == nil && rec.ASN != 0 {
			info.ASN, info.Org, found = rec.ASN, rec.Org, true
		}
	}
	return info, found
}

var (
	embedOnce sync.Once
	embedDB   *MMDB
	embedErr  error
)

// Embedded returns the database built into the binary.
func Embedded() (DB, error) {
	m, err := EmbeddedMMDB()
	if err != nil {
		return nil, err
	}
	return m, nil
}

// EmbeddedMMDB is Embedded with the build date.
func EmbeddedMMDB() (*MMDB, error) {
	embedOnce.Do(func() {
		c, _ := data.ReadFile("data/" + CountryFile)
		a, _ := data.ReadFile("data/" + ASNFile)
		embedDB, embedErr = Open(c, a)
	})
	return embedDB, embedErr
}

// Map is an in-memory DB (tests, and small fixed lists).
type Map map[netip.Addr]Info

// Lookup implements DB.
func (m Map) Lookup(a netip.Addr) (Info, bool) {
	i, ok := m[a.Unmap()]
	return i, ok
}
