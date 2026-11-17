# 0011. Active exit check and offline geo

- Status: accepted
- Date: 2026-11-16

## Context
M11 delivers NET-011 (spec §9.9), the embedded geo database that turns on TUN-006 and the country
part of PER-001, and the online `baseline create`. The spec left these points open: where the geo
files come from and when; which resolvers count as "DNS known in the tunnel"; how the result
appears without exposing the real IP; how often the query runs and how to turn it off; and how
PER-001 maps a timezone to a country.

## Decision
- **Geo data comes only from the release.** `scripts/update-geo` downloads DB-IP Lite Country and
  ASN for the month in `scripts/update-geo/pins.json` and refuses to write unless each SHA-256
  matches the pin (`-print` shows the hashes to review and pin). The `.mmdb` files are embedded
  (`//go:embed data`) and kept out of git. lethe never downloads them. A build without them is
  valid: `geo.Embedded` returns `ErrNoDatabase`, TUN-006 and the country/ASN comparisons stay
  inactive, and the baseline IP comparison in NET-011 still runs. `lethe version` prints the
  database build date, or `none`.
- **Tunnel DNS** comes from, in this order: the new profile field `active_checks.tunnel_dns` (it
  rejects loopback and unspecified addresses); the systemd-resolved servers of the tunnel link; and
  the `resolv.conf` nameservers whose kernel route leaves through the tunnel. Loopback stubs never
  count. With no tunnel DNS, the round is skipped with a W (`reason: skipped`), and the resolver
  `Dial` is never given the system address. Both the HTTP and the DNS sockets use
  `SO_BINDTODEVICE`. When the link goes down they fail instead of using the egress route; the
  netlab e2e tests this.
- **Tor** uses the first TCP `SocksPort` that `GETINFO net/listeners/socks` reports
  (`discover --json` now shows `tor.socks`), with socks5h. A Tor profile with no SOCKS port is
  skipped with a W.
- **Endpoints:** two are picked at random from the list for each round, and their answers must
  agree. The answer is the JSON `ip`/`IP`/`query`/`origin` field, or plain text. Only https is
  accepted, with no redirects, no environment proxy and no keep-alive, and with a common
  Firefox User-Agent. Results:
  - the baseline IP or ASN → C;
  - a country other than `expect_country`, or an ASN outside `expect_asn` → W;
  - disagreement or failure → W.

  The exit IP is always sealed, and the matched field is named.
- **Scheduling:** one round at arm time, then a uniform random wait in
  `active_checks.egress_ip.interval`. `active_checks.enabled: false` or `lethe run --no-active`
  (`ArmRequest.no_active`) disables it for the session. `status.exit` shows country, ASN (never
  the baseline's), path and time. It never shows the IP.
- **PER-001, country part.** The exit country is compared with:
  - the countries of the machine's timezone, from the system `zone1970.tab` (or `zone.tab`); a
    zone shared by several countries matches any of them, and UTC is never compared;
  - the territory of the locale (`pt_BR` → BR).

  When the host has not been read yet, the profile's `expect` values stand in. This condition
  resolves separately from the keyboard condition (`conditionGroupLocked`).
- **Online `baseline create`/`add-network`.** The public IP comes from two of the template's
  endpoints, which must agree. The query uses the normal path, because the baseline records the
  real connection. ASN and provider come from the offline database; the gateway and the
  non-stub resolvers come from discovery. Every value is a default the operator confirms or
  replaces. With a tunnel default route, the command refuses and explains how to proceed;
  `--allow-tunnel` accepts it with a warning, as §12.1 asks. Tests replace `onlineNetwork`, so no
  test reaches the internet.

## Consequences
- A dev build has no geo data, so on a dev machine TUN-006 and the country checks stay silent.
  The release guide must run `scripts/update-geo` and keep the DB-IP attribution
  (`docs/THIRD_PARTY.md`).
- NET-011 can only be as good as the tunnel DNS it finds. A VPN that pushes only a loopback stub
  needs `active_checks.tunnel_dns`; otherwise the operator sees a skip W, never a silent query
  through the system resolver.
