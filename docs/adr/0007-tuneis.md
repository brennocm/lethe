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
