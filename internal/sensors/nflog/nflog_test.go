package nflog

import (
	"encoding/binary"
	"testing"
	"time"

	gonflog "github.com/florianl/go-nflog/v2"
)

func udp4(dst [4]byte, dport uint16) []byte {
	p := make([]byte, 28)
	p[0], p[9] = 0x45, 17
	copy(p[12:16], []byte{10, 0, 0, 2})
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:], 40000)
	binary.BigEndian.PutUint16(p[22:], dport)
	return p
}

func TestNET002_FromAttribute(t *testing.T) {
	pl := udp4([4]byte{192, 0, 2, 1}, 9)
	prefix, uid, gid, dev := "LETHE-BLOCK ", uint32(1000), uint32(100), uint32(3)
	ts := time.Unix(1700000000, 0)
	b, ok := FromAttribute(gonflog.Attribute{Payload: &pl, Prefix: &prefix, UID: &uid, GID: &gid, OutDev: &dev, Timestamp: &ts},
		func(i uint32) string { return map[uint32]string{3: "eth0"}[i] }, time.Unix(0, 0))
	if !ok || b.UID != 1000 || b.GID != 100 || b.OutIface != "eth0" || b.Prefix != prefix || !b.At.Equal(ts) {
		t.Fatalf("%+v", b)
	}
	if b.Leak.Dst.String() != "192.0.2.1" || b.Leak.Dport != 9 {
		t.Fatalf("%+v", b.Leak)
	}
	pl2 := udp4([4]byte{192, 0, 2, 1}, 9)
	b, ok = FromAttribute(gonflog.Attribute{Payload: &pl2}, nil, ts)
	if !ok || b.UID != -1 || b.GID != -1 || b.OutIface != "" || !b.At.Equal(ts) {
		t.Fatalf("%+v", b)
	}
	if _, ok := FromAttribute(gonflog.Attribute{}, nil, ts); ok {
		t.Fatal("no payload must be skipped")
	}
	if ifname(1<<30) == "" {
		t.Fatal("unknown index must still produce a name")
	}
}
