//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/sys/unix"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/journal"
	"lethe/internal/sensors/capture"
	"lethe/internal/sensors/sockdiag"
	"lethe/test/netlab"
)

// capture starts the sensor on the netlab egress with the WireGuard endpoint allowed.
type capRun struct {
	frames chan capture.Frame
	sensor *capture.Sensor
}

func startCapture(t *testing.T) *capRun {
	t.Helper()
	al := capture.Allowlist{Endpoints: []capture.Endpoint{{Addr: netip.MustParseAddrPort("198.18.0.2:51820"), Proto: unix.IPPROTO_UDP}}}
	s, err := capture.Open(netlab.DUTEgress, al)
	if err != nil {
		t.Fatalf("open sensor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &capRun{frames: make(chan capture.Frame, 256), sensor: s}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, r.frames, func(time.Time) {}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("sensor: %v", err)
		}
		_ = s.Close()
	})
	return r
}

// wait returns the first frame whose destination is dst, failing after timeout. Frames to the
// allowed endpoint must never show up.
func (r *capRun) wait(t *testing.T, dst string, timeout time.Duration) capture.Frame {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case f := <-r.frames:
			if src := f.Leak.Src.String(); src == "10.0.0.1" || src == "198.18.0.2" || src == "2001:db8:1::1" {
				t.Fatalf("incoming frame delivered (PACKET_OUTGOING check broken): %+v", f.Leak)
			}
			if f.Leak.Dst.String() == "198.18.0.2" {
				t.Fatalf("allowed WireGuard traffic was delivered: %+v", f.Leak)
			}
			if f.Leak.Dst.String() == dst {
				return f
			}
		case <-deadline:
			t.Fatalf("no frame to %s within %s", dst, timeout)
		}
	}
}

func bindEgress(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) { serr = unix.BindToDevice(int(fd), netlab.DUTEgress) })
	if err != nil {
		return err
	}
	return serr
}

// leak opens a socket bound to the egress (ST-NET-001 style) and writes payload. TCP only
// sends the SYN; the connection never completes (the isp namespace blackholes the target).
func leak(t *testing.T, network, addr string, payload []byte) (local netip.AddrPort, closeFn func()) {
	t.Helper()
	d := net.Dialer{Control: bindEgress, Timeout: 5 * time.Second}
	if network == "tcp" {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.BindToDevice(fd, netlab.DUTEgress); err != nil {
			t.Fatal(err)
		}
		ap := netip.MustParseAddrPort(addr)
		if err := unix.Connect(fd, &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}); err != nil && err != unix.EINPROGRESS {
			t.Fatal(err)
		}
		sa, err := unix.Getsockname(fd)
		if err != nil {
			t.Fatal(err)
		}
		in := sa.(*unix.SockaddrInet4)
		return netip.AddrPortFrom(netip.AddrFrom4(in.Addr), uint16(in.Port)), func() { _ = unix.Close(fd) }
	}
	c, err := d.Dial(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	return c.LocalAddr().(*net.UDPAddr).AddrPort(), func() { _ = c.Close() }
}

func attribute(t *testing.T, f capture.Frame) contracts.Proc {
	t.Helper()
	proto, src, dst, ok := f.Leak.Tuple()
	if !ok {
		t.Fatalf("no tuple: %+v", f.Leak)
	}
	socks, err := sockdiag.Dump()
	if err != nil {
		t.Fatal(err)
	}
	owners, err := sockdiag.Owners("/proc")
	if err != nil {
		t.Fatal(err)
	}
	return sockdiag.Attribute(socks, owners, proto, src, dst)
}

func randomName(t *testing.T) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "st-" + hex.EncodeToString(b) + ".example.test"
}

func dnsQuery(name string) []byte {
	q := []byte{0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func labWithTunnel(t *testing.T) *netlab.Lab {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	return lab
}

func TestE2E_AC01_LeakDetectedAndAttributed(t *testing.T) {
	lab := labWithTunnel(t)
	_ = lab
	r := startCapture(t)
	start := time.Now()
	local, closeFn := leak(t, "tcp", "192.0.2.1:80", nil)
	defer closeFn()
	f := r.wait(t, "192.0.2.1", 2*time.Second)
	if lat := f.At.Sub(start); lat > time.Second {
		t.Fatalf("detection took %s (> 1 s)", lat)
	}
	p := attribute(t, f)
	exe, _ := os.Executable()
	if f.Leak.Check != "NET-001" || f.Leak.Severity != contracts.SeverityCritical || f.Leak.Sport != local.Port() {
		t.Fatalf("leak %+v", f.Leak)
	}
	if p.Confidence != contracts.ConfidenceHigh || p.PID != os.Getpid() || p.Exe != exe {
		t.Fatalf("attribution %+v (want pid %d exe %s)", p, os.Getpid(), exe)
	}
	ev := checks.FromFrame(f, p).Alert()
	if ev.Str("iface") != netlab.DUTEgress || ev.ProcExe() != exe {
		t.Fatalf("event %+v", ev)
	}
}

func TestE2E_ST_NET001_UDPToDocumentationAddress(t *testing.T) {
	labWithTunnel(t)
	r := startCapture(t)
	_, closeFn := leak(t, "udp", "192.0.2.1:9", []byte("lethe-selftest"))
	defer closeFn()
	f := r.wait(t, "192.0.2.1", 2*time.Second)
	if f.Leak.Check != "NET-001" || f.Leak.Dport != 9 || f.Leak.Proto != "udp" {
		t.Fatalf("%+v", f.Leak)
	}
	if p := attribute(t, f); p.PID != os.Getpid() || p.Confidence != contracts.ConfidenceHigh {
		t.Fatalf("connected UDP must attribute exactly: %+v", p)
	}
}

func TestE2E_ST_NET010_SYNAttributedToSelftestPID(t *testing.T) {
	labWithTunnel(t)
	r := startCapture(t)
	_, closeFn := leak(t, "tcp", "198.51.100.1:443", nil)
	defer closeFn()
	f := r.wait(t, "198.51.100.1", 2*time.Second)
	if p := attribute(t, f); p.PID != os.Getpid() || p.Confidence != contracts.ConfidenceHigh {
		t.Fatalf("%+v", p)
	}
}

func TestE2E_ST_NET012_STUNBindingRequest(t *testing.T) {
	labWithTunnel(t)
	r := startCapture(t)
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:], 0x0001)
	binary.BigEndian.PutUint32(msg[4:], 0x2112A442)
	copy(msg[8:], "lethe-st-txid")
	_, closeFn := leak(t, "udp", "203.0.113.1:3478", msg)
	defer closeFn()
	if f := r.wait(t, "203.0.113.1", 2*time.Second); f.Leak.Check != "NET-012" || f.Leak.Severity != contracts.SeverityCritical {
		t.Fatalf("%+v", f.Leak)
	}
}

// TestE2E_AC02_DNSLeakQNameSealed covers AC-02 and ST-DNS-001.
func TestE2E_AC02_DNSLeakQNameSealed(t *testing.T) {
	labWithTunnel(t)
	r := startCapture(t)
	name := randomName(t)
	_, closeFn := leak(t, "udp", "192.0.2.53:53", dnsQuery(name))
	defer closeFn()
	f := r.wait(t, "192.0.2.53", 2*time.Second)
	if f.Leak.Check != "DNS-001" || f.Leak.QName != name {
		t.Fatalf("%+v", f.Leak)
	}

	logID, _ := age.GenerateX25519Identity()
	sensID, _ := age.GenerateX25519Identity()
	dir := t.TempDir() + "/session"
	w, err := journal.Open(journal.Config{Dir: dir, Session: "5f0c9e2a-7b1d-4c3e-9a8f-2d6b1e0c4a77",
		Recipients: []age.Recipient{logID.Recipient()}, SensitiveRecipients: []age.Recipient{sensID.Recipient()},
		Now: time.Now, Mono: func() int64 { var ts unix.Timespec; _ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); return ts.Nano() }})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := checks.FromFrame(f, attribute(t, f)).SealedAlert(w.Seal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ev); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(nil); err != nil {
		t.Fatal(err)
	}

	s, err := journal.Read(dir, []age.Identity{logID})
	if err != nil {
		t.Fatal(err)
	}
	var got *contracts.Event
	for i := range s.Events {
		if s.Events[i].Check == "DNS-001" {
			got = &s.Events[i]
		}
	}
	if got == nil {
		t.Fatal("DNS-001 not in the journal")
	}
	if strings.Contains(asJSON(t, got.Data), name) {
		t.Fatal("qname visible without the sensitive key")
	}
	if _, err := s.Field(got.Data["qname"]); err == nil {
		t.Fatal("field opened without the sensitive key")
	}
	if err := s.UnlockSensitive([]age.Identity{logID}); err == nil {
		t.Fatal("the log identity must not unlock sensitive fields")
	}
	if err := s.UnlockSensitive([]age.Identity{sensID}); err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	if q, err := s.Field(got.Data["qname"]); err != nil || q != name {
		t.Fatalf("qname=%q err=%v", q, err)
	}
}

// TestE2E_AC03_IPv6OutsideTunnel covers AC-03 (NET-003 at arm time) and ST-NET-003.
func TestE2E_AC03_IPv6OutsideTunnel(t *testing.T) {
	lab := labWithTunnel(t)
	lab.EgressIPv6(t)
	var s discovery.Snapshot
	_ = lab.In(lab.DUT, func() error {
		s = discovery.Discover(discovery.NetlinkKernel{}, discovery.Options{Overrides: discovery.Overrides{Egress: []string{netlab.DUTEgress}}, Now: time.Now()})
		return nil
	})
	fs := (checks.NET003{}).Evaluate(&s, false)
	if len(fs) != 1 || fs[0].Severity != contracts.SeverityCritical || fs[0].Data["iface"] != netlab.DUTEgress {
		t.Fatalf("NET-003: %+v (routes %+v)", fs, s.Routes)
	}
	if fs := (checks.NET004{}).Evaluate(&s); len(fs) != 1 || fs[0].Data["family"] != "ipv6" {
		t.Fatalf("NET-004 must flag the v6 probe route: %+v", fs)
	}

	r := startCapture(t)
	d := net.Dialer{Control: bindEgress}
	c, err := d.Dial("udp6", "[2001:db8::1]:9")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) { // the first datagrams may wait on neighbour discovery
		_, _ = c.Write([]byte("lethe-selftest"))
		select {
		case f := <-r.frames:
			if f.Leak.Dst.String() != "2001:db8::1" {
				continue
			}
			if f.Leak.Check != "NET-001" || f.Leak.Subtype != "ipv6" {
				t.Fatalf("%+v", f.Leak)
			}
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("no IPv6 leak seen")
}

func TestE2E_NET001_FilterUpdateIsAtomic(t *testing.T) {
	labWithTunnel(t)
	r := startCapture(t)
	// allow 192.0.2.1:9/udp: the same leak is now silent
	if err := r.sensor.Update(capture.Allowlist{Endpoints: []capture.Endpoint{
		{Addr: netip.MustParseAddrPort("198.18.0.2:51820"), Proto: unix.IPPROTO_UDP},
		{Addr: netip.MustParseAddrPort("192.0.2.1:9"), Proto: unix.IPPROTO_UDP},
	}}); err != nil {
		t.Fatal(err)
	}
	_, closeFn := leak(t, "udp", "192.0.2.1:9", []byte("allowed"))
	defer closeFn()
	_, closeFn2 := leak(t, "udp", "192.0.2.2:9", []byte("marker"))
	defer closeFn2()
	f := r.wait(t, "192.0.2.2", 2*time.Second)
	_ = f
	select {
	case f := <-r.frames:
		if f.Leak.Dst.String() == "192.0.2.1" {
			t.Fatalf("allowed destination delivered: %+v", f.Leak)
		}
	case <-time.After(300 * time.Millisecond):
	}
	if st, err := r.sensor.Stats(); err != nil || st.Drops != 0 {
		t.Fatalf("stats %+v err %v", st, err)
	}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
