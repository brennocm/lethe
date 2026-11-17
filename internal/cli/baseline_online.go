package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"lethe/internal/baseline"
	"lethe/internal/discovery"
	"lethe/internal/geo"
	"lethe/internal/profile"
	"lethe/internal/sensors/egressip"
)

// onlineNetwork fills the defaults of the network questions from this connection: the public
// IP (two endpoints that must agree, over the normal path: the baseline is made WITHOUT the
// tunnel), the ASN and provider from the offline database, the gateway and the resolvers from
// the discovery. Tests replace it.
var onlineNetwork = liveOnlineNetwork

// ErrTunnelUp: the baseline needs the real connection.
var ErrTunnelUp = errors.New("o túnel está ligado: a baseline precisa do IP real. Desligue a VPN/Tor e rode de novo (ou use --manual; --allow-tunnel aceita o túnel)")

func liveOnlineNetwork(ctx context.Context, w io.Writer, allowTunnel bool) (baseline.Network, error) {
	snap := discovery.Discover(discovery.NetlinkKernel{}, discovery.Options{Now: time.Now()})
	return detectNetwork(ctx, w, snap, allowTunnel, func(ctx context.Context, eps []string) egressip.Result {
		direct := egressip.Path{Dial: (&net.Dialer{Timeout: 15 * time.Second}).DialContext}
		return egressip.Query(ctx, direct, egressip.Config{Endpoints: eps})
	}, geoOrNil())
}

func geoOrNil() geo.DB {
	db, err := geo.Embedded()
	if err != nil {
		return nil
	}
	return db
}

// templateEndpoints are the default endpoints of the profile template.
func templateEndpoints() []string {
	p, _, err := profile.Parse(profile.Template, "/")
	if err != nil {
		return nil
	}
	return p.ActiveChecks.EgressIP.Endpoints
}

func detectNetwork(ctx context.Context, w io.Writer, snap discovery.Snapshot, allowTunnel bool, query func(context.Context, []string) egressip.Result, db geo.DB) (baseline.Network, error) {
	var n baseline.Network
	for _, r := range snap.Routes.DefaultV4 {
		if r.Class == discovery.ClassTunnel {
			if !allowTunnel {
				return n, ErrTunnelUp
			}
			_, _ = fmt.Fprintln(w, "aviso: --allow-tunnel: o IP público coletado será o da saída do túnel, não o da rede real. Confira antes de confirmar.")
			break
		}
	}
	for _, r := range snap.Routes.DefaultV4 {
		if r.Gateway != "" && n.GatewayIP == "" {
			n.GatewayIP = r.Gateway
		}
	}
	if !snap.DNS.ResolvConf.Stub {
		n.Resolvers = append(n.Resolvers, snap.DNS.ResolvConf.Nameservers...)
	}
	for _, l := range snap.DNS.Resolved.Links {
		if l.DefaultRoute {
			n.Resolvers = append(n.Resolvers, l.Servers...)
		}
	}
	_, _ = fmt.Fprintln(w, "Consultando o IP público desta conexão (dois serviços, que precisam concordar)…")
	res := query(ctx, templateEndpoints())
	switch {
	case res.Skipped != "":
		_, _ = fmt.Fprintf(w, "aviso: não consultei o IP público (%s); responda à mão.\n", res.Skipped)
		return n, nil
	case !res.Agreed:
		_, _ = fmt.Fprintln(w, "aviso: os serviços não concordaram sobre o IP público; responda à mão.")
		return n, nil
	}
	if res.IP.Is4() {
		n.PublicIPv4 = res.IP.String()
	} else {
		n.PublicIPv6 = res.IP.String()
	}
	if db == nil {
		_, _ = fmt.Fprintln(w, "aviso: este binário não tem a base geo; informe o ASN à mão se souber.")
		return n, nil
	}
	if info, ok := db.Lookup(res.IP); ok {
		n.ASN, n.Provider = info.ASN, info.Org
	}
	return n, nil
}
