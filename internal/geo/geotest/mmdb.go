// Package geotest writes tiny MaxMind DB files for tests (the real DB-IP data is embedded only
// at release). It implements the subset of the format the lookups need: an IPv6 tree with 24-bit
// records, IPv4 under ::/96, and maps of strings and unsigned integers.
package geotest

import (
	"encoding/binary"
	"net/netip"
	"sort"
)

type node struct {
	kid  [2]*node
	data [2]int // offset into the data section + 1; 0 = none
}

// Write builds a database of type dbType where each prefix maps to its record (map[string]any
// with string, uint32 or nested map values).
func Write(dbType string, records map[netip.Prefix]map[string]any) []byte {
	root := &node{}
	var dataSec []byte
	keys := make([]netip.Prefix, 0, len(records))
	for p := range records {
		keys = append(keys, p)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	for _, p := range keys {
		off := len(dataSec)
		dataSec = append(dataSec, encode(records[p])...)
		bits, n := prefixBits(p)
		cur := root
		for i := 0; i < n; i++ {
			b := bits[i]
			if i == n-1 {
				cur.data[b] = off + 1
				break
			}
			if cur.kid[b] == nil {
				cur.kid[b] = &node{}
			}
			cur = cur.kid[b]
		}
	}
	// breadth-first numbering
	var order []*node
	index := map[*node]int{}
	queue := []*node{root}
	for len(queue) > 0 {
		x := queue[0]
		queue = queue[1:]
		index[x] = len(order)
		order = append(order, x)
		for _, k := range x.kid {
			if k != nil {
				queue = append(queue, k)
			}
		}
	}
	count := len(order)
	var tree []byte
	for _, x := range order {
		for b := 0; b < 2; b++ {
			v := count // empty
			switch {
			case x.kid[b] != nil:
				v = index[x.kid[b]]
			case x.data[b] != 0:
				v = count + 16 + x.data[b] - 1
			}
			tree = append(tree, byte(v>>16), byte(v>>8), byte(v))
		}
	}
	out := append(tree, make([]byte, 16)...)
	out = append(out, dataSec...)
	out = append(out, []byte("\xab\xcd\xefMaxMind.com")...)
	meta := map[string]any{
		"node_count": uint32(count), "record_size": uint16(24), "ip_version": uint16(6),
		"database_type": dbType, "binary_format_major_version": uint16(2), "binary_format_minor_version": uint16(0),
		"build_epoch": uint64(1_790_000_000), "languages": []string{"en"}, "description": map[string]any{"en": "lethe test"},
	}
	return append(out, encode(meta)...)
}

func prefixBits(p netip.Prefix) ([]int, int) {
	a := p.Addr()
	n := p.Bits()
	if a.Is4() {
		n += 96
	}
	b16 := a.As16()
	if a.Is4() {
		b16 = [16]byte{}
		v4 := a.As4()
		copy(b16[12:], v4[:])
	}
	bits := make([]int, 128)
	for i := 0; i < 128; i++ {
		bits[i] = int(b16[i/8]>>(7-uint(i%8))) & 1
	}
	return bits, n
}

// ctrl is the control byte, the extended type byte (types > 7) and the size bytes.
func ctrl(typ, size int) []byte {
	var sz []byte
	low := size
	switch {
	case size >= 285:
		low, sz = 30, []byte{byte((size - 285) >> 8), byte(size - 285)}
	case size >= 29:
		low, sz = 29, []byte{byte(size - 29)}
	}
	out := []byte{byte(typ<<5 | low)}
	if typ > 7 {
		out = []byte{byte(low), byte(typ - 7)}
	}
	return append(out, sz...)
}

func uintBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func encode(v any) []byte {
	switch x := v.(type) {
	case string:
		return append(ctrl(2, len(x)), x...)
	case uint16:
		b := uintBytes(uint64(x))
		return append(ctrl(5, len(b)), b...)
	case uint32:
		b := uintBytes(uint64(x))
		return append(ctrl(6, len(b)), b...)
	case uint64:
		b := uintBytes(x)
		return append(ctrl(9, len(b)), b...)
	case []string:
		out := ctrl(11, len(x))
		for _, s := range x {
			out = append(out, encode(s)...)
		}
		return out
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := ctrl(7, len(x))
		for _, k := range keys {
			out = append(out, encode(k)...)
			out = append(out, encode(x[k])...)
		}
		return out
	}
	panic("geotest: unsupported type")
}
