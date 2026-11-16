// Package geo answers country and ASN for an address from the offline database (spec §20.1).
// The embedded DB-IP Lite data arrives with M11; until then Embedded reports ErrNoDatabase and
// the checks that need it (TUN-006) stay inactive instead of guessing.
package geo

import (
	"errors"
	"net/netip"
)

// Info is what the database knows about one address.
type Info struct {
	Country string // ISO 3166-1 alpha-2, upper case
	ASN     uint32 // 0 = unknown
}

// DB looks addresses up. ok is false when the address is not in the database.
type DB interface {
	Lookup(a netip.Addr) (info Info, ok bool)
}

// ErrNoDatabase means no geo database is embedded in this build.
var ErrNoDatabase = errors.New("geo: no database in this build (arrives with M11)")

// Embedded returns the database built into the binary.
func Embedded() (DB, error) { return nil, ErrNoDatabase }

// Map is an in-memory DB (tests, and small fixed lists).
type Map map[netip.Addr]Info

// Lookup implements DB.
func (m Map) Lookup(a netip.Addr) (Info, bool) {
	i, ok := m[a.Unmap()]
	return i, ok
}
