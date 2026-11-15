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
- **Tor control client** (`internal/discovery/torctl`). Authentication is NULL or SAFECOOKIE only.
  Plain COOKIE hands the cookie to whatever listens on the port, and the profile has no password
  field, so neither is used. With `tor_cookie: auto` the cookie path comes from `PROTOCOLINFO`;
  that is safe only because SAFECOOKIE checks the server's hash before sending anything derived
  from the cookie. The cookie must be exactly 32 bytes, and it is read into locked memory and
  wiped afterwards. `tor_control` must be `auto` or a loopback address, both in the profile and
  in `Dial`, because a remote control port would itself be traffic outside the tunnel. Lines are
  capped at 64 KiB and replies at 4 MiB. Events go to a 256-entry buffer, and an overflow marks
  them as lost so that the caller does a full refresh. Guards are the first hops of BUILT or
  EXTENDED circuits plus `entry-guards` marked `up`, resolved through `ns/id/<fp>`. A fingerprint
  missing from the consensus (552), such as a bridge, is covered by the `Bridge` lines.
