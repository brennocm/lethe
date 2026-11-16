# 0007. Tunnel checks and endpoint discovery (M8)

- Status: accepted
- Date: 2026-11-15

## Context
Spec §7.3–§7.5 and §9.3 define tunnel discovery and the TUN checks. A few behaviors were left
open.

## Decision
- **TUN-001 expectation.** The expected tunnels are the ones present at arm plus any that
  appear later in the session; the set never shrinks. A tunnel that disappears stays CRITICAL
  until it comes back. A VPN client that reconnects on another interface name therefore needs an
  ack or a new arm. Every `egress.type` except `tor` also requires at least one tunnel interface
  (`no_tunnel`), and `auto` with no tunnel at all fails the preflight. Unpanic re-checks TUN-001
  as well.
- **TUN-007** is a condition while armed (WARNING) and a WARN in the preflight.
- **Endpoint changes.** The daemon polls wgctrl every second, and any difference triggers a
  discovery pass. That pass updates the capture allowlists and the strict sets in one
  transaction, and journals `discovery.endpoint_changed` (INFO, with the added and removed
  endpoints). A tunnel without any known endpoint emits `discovery.endpoint_unknown` and turns the
  state GRAY until an endpoint appears. Learned and confirmed endpoints (NFLOG, operator) are kept
  for the rest of the session and merged into every discovery.
- **MLD in the capture filter.** MLD reports always carry a Hop-by-Hop header. The filter drops
  only an 8-byte Hop-by-Hop header followed by ICMPv6 MLD to `ff02::/16`; any other chain is
  delivered. Otherwise every MLDv2 report on the egress was a NET-001 CRITICAL, which in strict mode
  means panic.
- **TUN-004** compares a snapshot of the third-party tables (every table not named `lethe*`) taken
  at arm with a fresh one on every discovery pass. The arm-time pass runs every 5 s, which is the
  spec's resampling interval; the `NFNLGRP_NFTABLES` monitor is left out, and that interval is the
  latency. The hash covers sets, chains and rule expressions, without counters, quota usage or
  handles, so traffic alone never looks like a change. A table that is added, changed or removed is
  WARNING. A removed table with a drop (policy, drop or reject) in an output hook is CRITICAL. Only
  table names reach the events.
- **Tor control client** (`internal/discovery/torctl`). Whatever answers on the control port
  decides which addresses the strict guard and the capture filter let through, and any local user
  can listen on 127.0.0.1:9051 while tor is not running. Authentication is therefore SAFECOOKIE
  only. NULL would believe whoever holds the port, plain COOKIE hands the cookie over, and the
  profile has no password field. Before `PROTOCOLINFO`, sock_diag and `/proc` identify the process
  holding the server end of the connection. Its executable must be named `tor`, and it must run as
  the operator (Tor Browser) or as a system user (uid ≤ 999); otherwise nothing is sent. The cookie
  (from the profile, or from `PROTOCOLINFO` with `tor_cookie: auto`) must be a regular file owned
  by that same uid, not writable by group or others, and exactly 32 bytes. Only then is it read,
  into locked memory that is wiped afterwards. A server that wrote its own cookie therefore fails
  unless it is a trusted tor. SAFECOOKIE then checks the server's hash before sending anything
  derived from the cookie. `tor_control` must be `auto` or a loopback address, both in the profile and
  in `Dial`, because a remote control port would itself be traffic outside the tunnel. Lines are
  capped at 64 KiB and replies at 4 MiB. Events go to a 256-entry buffer, and an overflow marks
  them as lost so that the caller does a full refresh. Guards are the first hops of BUILT or
  EXTENDED circuits plus `entry-guards` marked `up`, resolved through `ns/id/<fp>`. A fingerprint
  missing from the consensus (552), such as a bridge, is covered by the `Bridge` lines.
- **Tor in discovery.** Tor is queried for `egress.type` `tor`, `vpn+tor` and `auto`. An
  unreachable control port is a visibility gap (`torctl`) only for `tor` and `vpn+tor`. With
  `auto`, Tor is part of the session when its control port answered at arm. In that case TUN-003
  applies, and no tunnel interface is required (TUN-001 `no_tunnel` fires only when there is
  neither a tunnel nor Tor). Guards and, with `UseBridges 1`, the addresses on the `Bridge` lines
  become `/tcp` endpoints. Every CIRC, STATUS_CLIENT or GUARD event triggers a discovery pass, and
  the 5 s refresh covers the rest. The daemon builds one control client per arm from the profile.
  Discovery passes run under the daemon lock, and a slow control port must not delay panic
  (≤ 200 ms). The daemon therefore queries tor synchronously only at arm. Later passes read a cache
  that is refreshed in the background (single flight, on every pass and on tor events), and a
  changed answer triggers another pass. A stop is seen one refresh later.
- **TUN-003** is a CRITICAL condition while armed (`control_unreachable`, `bootstrap`,
  `no_circuit`), is in the preflight, and is part of the unpanic re-check.
- **TUN-008.** `snowflake`, `meek` and `meek_lite` with the strict guard are a preflight FAIL, and
  the daemon refuses that arm even with `--force`: the guard cannot follow those destinations, and
  spec §7.5 leaves only observer mode for them.
- **OpenVPN and generic clients** (added with the M8 debt work). A VPN client is a process whose
  executable is a known client (`openvpn`, `openconnect`, `openfortivpn`, `vpnc`, strongSwan
  `charon`, and the Mullvad, NordVPN, ExpressVPN, IVPN, PIA and WARP daemons) and that holds a
  socket. The remote ends of its connected sockets become endpoints, but only when they are routed
  outside the tunnel, because what a client sends through its own tunnel (its API) is not an
  endpoint. Under the daemon lock, discovery reads the last scan of the socket sensor (every 2 s),
  so a pass never walks `/proc` while holding the lock. A packet dropped on the way out is learned
  when its socket is identified without ambiguity and belongs to a discovered client. That means
  the connected socket with the 5-tuple, or the only unconnected UDP socket on the source port,
  since OpenVPN over UDP does not connect. Requiring an exact 5-tuple would never learn OpenVPN
  over UDP, which would leave the operator GRAY and blocked. The single-socket rule is just as
  certain about who sent the packet. Nothing is learned in panic, and a session learns at most 64
  endpoints. `discovery.confirm_endpoint` (sensitive) adds an operator choice to the same list.
- **The VPN client's cgroup is never accepted whole** (fail-closed; this changes spec §11.3). With
  NetworkManager the client runs in `NetworkManager.service`, so a blanket `socket cgroupv2 accept`
  would let the NM connectivity check and dispatcher scripts out with the real IP. The cgroup rule
  now opens only port 53 (UDP and TCP), and only with `egress.allow_vpn_client_dns`. A changed
  cgroup ID, after the service restarts, regenerates the ruleset on the next discovery pass. A
  lookup that goes through systemd-resolved leaves from resolved's cgroup, not the client's, so
  this flag helps only clients that query DNS themselves.
