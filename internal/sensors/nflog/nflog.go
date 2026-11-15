// Package nflog reads the packets the strict guard blocked (log group 4242) for NET-002
// (spec §9.1). The kernel always adds NFULA_UID/GID for packets that belong to a local full
// socket, so blocked attempts carry the sender's UID.
package nflog

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	gonflog "github.com/florianl/go-nflog/v2"

	"lethe/internal/sensors/capture"
)

// SourceID of this sensor (spec §9.7).
const SourceID = "nflog"

const heartbeatEvery = 500 * time.Millisecond

// Blocked is one logged, dropped packet.
type Blocked struct {
	At       time.Time
	Prefix   string // LETHE-BLOCK | LETHE-FWD | LETHE-L2 | LETHE-BR
	UID, GID int    // -1 when the packet had no local socket (forwarded, raw)
	OutIface string
	Leak     capture.Leak
}

// FromAttribute converts one NFLOG message (pure, for tests).
func FromAttribute(a gonflog.Attribute, ifname func(uint32) string, now time.Time) (Blocked, bool) {
	if a.Payload == nil {
		return Blocked{}, false
	}
	b := Blocked{At: now, UID: -1, GID: -1, Leak: capture.ClassifyIP(*a.Payload, len(*a.Payload))}
	if a.Timestamp != nil {
		b.At = *a.Timestamp
	}
	if a.Prefix != nil {
		b.Prefix = *a.Prefix
	}
	if a.UID != nil {
		b.UID = int(*a.UID)
	}
	if a.GID != nil {
		b.GID = int(*a.GID)
	}
	if a.OutDev != nil {
		b.OutIface = ifname(*a.OutDev)
	}
	return b, true
}

func ifname(idx uint32) string {
	if i, err := net.InterfaceByIndex(int(idx)); err == nil {
		return i.Name
	}
	return fmt.Sprintf("ifindex:%d", idx)
}

// Run subscribes to group and forwards blocked packets until ctx ends.
func Run(ctx context.Context, group uint16, out chan<- Blocked, beat func(time.Time)) error {
	nf, err := gonflog.Open(&gonflog.Config{Group: group, Copymode: gonflog.CopyPacket, Bufsize: capture.Snaplen})
	if err != nil {
		return fmt.Errorf("nflog: open: %w", err)
	}
	defer func() { _ = nf.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failed := make(chan error, 1)
	hook := func(a gonflog.Attribute) int {
		if b, ok := FromAttribute(a, ifname, time.Now()); ok {
			select {
			case out <- b:
			case <-ctx.Done():
			}
		}
		return 0
	}
	errfn := func(e error) int {
		if ctx.Err() != nil {
			return 1
		}
		select {
		case failed <- e:
		default:
		}
		return 1
	}
	if err := nf.RegisterWithErrorFunc(ctx, hook, errfn); err != nil {
		return fmt.Errorf("nflog: register group %d: %w", group, err)
	}
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failed:
			return errors.Join(errors.New("nflog: receive failed"), err)
		case now := <-t.C:
			beat(now)
		}
	}
}
