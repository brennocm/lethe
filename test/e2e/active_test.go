//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"lethe/internal/sensors/egressip"
	"lethe/test/netlab"
)

// The exit-IP services live inside the vpn namespace, on the WireGuard server address: they
// are only reachable through the tunnel, as a real one would be after the VPN's exit.
const (
	exitSrv = "10.200.0.1"
	exitIP  = "10.200.0.2" // what the services see: the DUT's tunnel address
)

var exitNames = []string{"ip-a.lethe.test", "ip-b.lethe.test"}

// exitServices starts a DNS server (A records for exitNames) and an HTTPS server answering the
// caller's address, both in the vpn namespace, and returns the pool that trusts the server.
func exitServices(t *testing.T, l *netlab.Lab) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lethe exit test"},
		DNSNames: exitNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	var dns net.PacketConn
	var web net.Listener
	if err := l.In(l.VPN, func() error {
		var err error
		if dns, err = net.ListenPacket("udp4", exitSrv+":53"); err != nil {
			return err
		}
		web, err = tls.Listen("tcp4", exitSrv+":443", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dns.Close(); _ = web.Close() })
	go serveDNS(dns)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if r.Host == exitNames[0] {
			_, _ = w.Write([]byte(`{"ip":"` + host + `"}`))
			return
		}
		_, _ = w.Write([]byte(host + "\n"))
	})}
	go func() { _ = srv.Serve(web) }()
	t.Cleanup(func() { _ = srv.Close() })
	return pool
}

func serveDNS(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var q layers.DNS
		if q.DecodeFromBytes(buf[:n], gopacket.NilDecodeFeedback) != nil || len(q.Questions) == 0 {
			continue
		}
		a := q
		a.QR, a.ResponseCode, a.Answers = true, layers.DNSResponseCodeNoErr, nil
		qq := q.Questions[0]
		known := false
		for _, name := range exitNames {
			known = known || string(qq.Name) == name
		}
		if known && qq.Type == layers.DNSTypeA {
			a.Answers = []layers.DNSResourceRecord{{Name: qq.Name, Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP(exitSrv).To4()}}
		} else if !known {
			a.ResponseCode = layers.DNSResponseCodeNXDomain
		}
		a.ANCount = uint16(len(a.Answers))
		sb := gopacket.NewSerializeBuffer()
		if a.SerializeTo(sb, gopacket.SerializeOptions{FixLengths: true}) == nil {
			_, _ = pc.WriteTo(sb.Bytes(), from)
		}
	}
}

func exitConfig(pool *x509.CertPool) egressip.Config {
	return egressip.Config{Endpoints: []string{"https://" + exitNames[0] + "/json", "https://" + exitNames[1] + "/"},
		RootCAs: pool, Timeout: 5 * time.Second, Pick: func(int) []int { return []int{0, 1} }}
}

func TestE2E_NET011_ExitThroughTheTunnel(t *testing.T) {
	l := netlab.New(t, true)
	l.WaitHandshake(t, 10*time.Second)
	pool := exitServices(t, l)
	sn := l.Sniff(t)
	start := time.Now()
	r := egressip.Query(context.Background(), egressip.Path{Tunnel: netlab.DUTTunnel, DNS: []netip.Addr{netip.MustParseAddr(exitSrv)}}, exitConfig(pool))
	if !r.Agreed || r.IP != netip.MustParseAddr(exitIP) {
		t.Fatalf("%+v", r)
	}
	time.Sleep(300 * time.Millisecond)
	if leaks := leaksOnWire(sn.Since(start), true); len(leaks) != 0 {
		t.Fatalf("%d frames left through the egress outside the tunnel (DNS or HTTPS of the check)", len(leaks))
	}
}

func TestE2E_NET011_NoTunnelResolverSkips(t *testing.T) {
	l := netlab.New(t, true)
	l.WaitHandshake(t, 10*time.Second)
	pool := exitServices(t, l)
	sn := l.Sniff(t)
	start := time.Now()
	r := egressip.Query(context.Background(), egressip.Path{Tunnel: netlab.DUTTunnel}, exitConfig(pool))
	if r.Skipped != egressip.ErrNoTunnelDNS.Error() || r.Agreed || len(r.Answers) != 0 {
		t.Fatalf("without a tunnel DNS the round must skip, never ask the system resolver: %+v", r)
	}
	time.Sleep(300 * time.Millisecond)
	if leaks := leaksOnWire(sn.Since(start), true); len(leaks) != 0 {
		t.Fatalf("%d frames on the egress", len(leaks))
	}
}

// TestE2E_NET011_BoundEvenWhenTheTunnelDrops: with the tunnel link down the bound socket fails
// instead of falling back to the egress default route.
func TestE2E_NET011_BoundEvenWhenTheTunnelDrops(t *testing.T) {
	l := netlab.New(t, true)
	l.WaitHandshake(t, 10*time.Second)
	pool := exitServices(t, l)
	l.SetTunnel(t, false)
	sn := l.Sniff(t)
	start := time.Now()
	r := egressip.Query(context.Background(), egressip.Path{Tunnel: netlab.DUTTunnel, DNS: []netip.Addr{netip.MustParseAddr(exitSrv)}}, exitConfig(pool))
	if r.Agreed {
		t.Fatalf("%+v", r)
	}
	time.Sleep(300 * time.Millisecond)
	if leaks := leaksOnWire(sn.Since(start), false); len(leaks) != 0 {
		t.Fatalf("%d frames on the egress with the tunnel down", len(leaks))
	}
}
