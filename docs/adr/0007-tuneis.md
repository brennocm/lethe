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
