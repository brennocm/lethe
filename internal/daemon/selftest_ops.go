package daemon

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"lethe/internal/guard"
	"lethe/internal/privsep"
)

// SelftestOps are the side effects of the selftest cases (fakes in unit tests).
type SelftestOps interface {
	// UDP sends count datagrams from an ephemeral port bound to iface; before runs with the
	// source port before the first one is sent (to register the probe and the exception).
	UDP(iface string, dst netip.AddrPort, payload []byte, count int, before func(sport uint16) error) (uint16, error)
	// SYN starts a TCP connection bound to iface; close aborts it.
	SYN(iface string, dst netip.AddrPort, before func(sport uint16) error) (close func(), err error)
	AddDummy(name string) error
	DelDummy(name string) error
	AddTable(name string) error // inet <name>
	DelTable(name string) error
	// SpawnDeny starts a child of this binary named lethe-st-deny (ST-HOST-001).
	SpawnDeny() (pid int, stop func(), err error)
}

// liveOps does it for real (netlink, nftables, sockets, /proc/self/exe).
type liveOps struct{ nft func() (guard.Conn, error) }

func socketFor(dst netip.AddrPort, typ int, iface string) (int, uint16, error) {
	fam := unix.AF_INET
	var sa unix.Sockaddr = &unix.SockaddrInet4{}
	if dst.Addr().Is6() && !dst.Addr().Is4In6() {
		fam, sa = unix.AF_INET6, &unix.SockaddrInet6{}
	}
	fd, err := unix.Socket(fam, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, 0, err
	}
	if err := unix.BindToDevice(fd, iface); err != nil {
		_ = unix.Close(fd)
		return -1, 0, fmt.Errorf("bind to %s: %w", iface, err)
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, 0, err
	}
	got, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, 0, err
	}
	var port int
	switch a := got.(type) {
	case *unix.SockaddrInet4:
		port = a.Port
	case *unix.SockaddrInet6:
		port = a.Port
	}
	return fd, uint16(port), nil // #nosec G115 -- a port
}

func sockaddr(dst netip.AddrPort) unix.Sockaddr {
	a := dst.Addr().Unmap()
	if a.Is4() {
		return &unix.SockaddrInet4{Port: int(dst.Port()), Addr: a.As4()}
	}
	return &unix.SockaddrInet6{Port: int(dst.Port()), Addr: a.As16()}
}

func (liveOps) UDP(iface string, dst netip.AddrPort, payload []byte, count int, before func(uint16) error) (uint16, error) {
	if !guard.IsDocumentation(dst.Addr()) {
		return 0, errors.New("selftest traffic only goes to documentation addresses")
	}
	fd, port, err := socketFor(dst, unix.SOCK_DGRAM, iface)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	if before != nil {
		if err := before(port); err != nil {
			return port, err
		}
	}
	var first error
	for i := range count {
		if err := unix.Sendto(fd, payload, 0, sockaddr(dst)); err != nil {
			if i == 0 {
				first = err
			}
			if errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EAGAIN) {
				time.Sleep(time.Millisecond) // the burst outran the qdisc: keep going
				continue
			}
			if count == 1 {
				return port, err
			}
		}
	}
	if count == 1 {
		return port, first
	}
	return port, nil
}

func (liveOps) SYN(iface string, dst netip.AddrPort, before func(uint16) error) (func(), error) {
	if !guard.IsDocumentation(dst.Addr()) {
		return nil, errors.New("selftest traffic only goes to documentation addresses")
	}
	fd, port, err := socketFor(dst, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, iface)
	if err != nil {
		return nil, err
	}
	closeFn := func() { _ = unix.Close(fd) }
	if err := before(port); err != nil {
		closeFn()
		return nil, err
	}
	if err := unix.Connect(fd, sockaddr(dst)); err != nil && !errors.Is(err, unix.EINPROGRESS) {
		closeFn()
		return nil, err
	}
	return closeFn, nil
}

func (liveOps) AddDummy(name string) error {
	l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(l); err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	return netlink.LinkSetUp(l)
}

func (liveOps) DelDummy(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkDel(l)
}

func (o liveOps) AddTable(name string) error {
	c, err := o.nft()
	if err != nil {
		return err
	}
	c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
	return c.Flush()
}

func (o liveOps) DelTable(name string) error {
	c, err := o.nft()
	if err != nil {
		return err
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
	return c.Flush()
}

func (liveOps) SpawnDeny() (int, func(), error) {
	cmd, err := privsep.Spawn([]string{"selftest-deny"}, privsep.SpawnOptions{Env: []string{"PATH=/usr/bin:/bin"}})
	if err != nil {
		return 0, nil, err
	}
	stop := func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	return cmd.Process.Pid, stop, nil
}
