# 0008. Safe use: never lock the operator out by mistake

- Status: accepted
- Date: 2026-11-15

## Context
The owner found that a misconfigured lethe can lock the operator's network. Two examples: arming
strict with `--force` while the tunnel is down, or typing the passphrase wrong five times in
observer mode. In both cases nothing says how to get out. The people using lethe are
investigators, not firewall specialists, and a tool that blocks them for an obscure reason gets
uninstalled or bypassed, which is worse for OpSec than a missed alert. Spec principle 11 and §10.6
now state the rule. This ADR records the decisions behind it.

## Decision
- **Blocking stays where it stops a leak.** Strict tables, panic and the fail-closed behavior after
  a daemon crash do not change. What changes is how one gets there by mistake and how one gets out.
- **`--force` does not override tunnel failures under strict or reactive.** A FAIL from TUN-001,
  TUN-003 or TUN-008 means the guard would cut the network as soon as it was applied, so `--force`
  cannot be the answer to it. Under `off` it still works, because nothing is blocked there.
- **Arm confirmation window** (`guard.arm_confirm`, default 30 s). Under strict, the session is
  only announced as armed after local proof that the tunnel carries traffic with the guard on: a
  WireGuard handshake under 180 s old, rx bytes rising on a tunnel interface, or a Tor circuit.
  Without proof, the guard is removed and the session ends with `arm_unconfirmed` and exit code 6.
  This fails open, which is acceptable only because it happens before the operation starts and is
  loud. lethe sends no traffic of its own to obtain the proof (principle 5). An idle tunnel
  without keepalive can undo the arm, which §22 lists as a limitation. Setting the window to 0
  restores the old behavior with a preflight WARN.
- **Passphrase failures in observer mode** open SELF-006 CRITICAL and lock the sensitive methods
  for 5 minutes, without `block_all`. An explicit `lethe panic` still blocks in every mode,
  because the operator asked for it. No new event type is added: existing `check.alert`,
  `ipc.denied`, `guard.removed` and `session.end` carry everything.
- **Generated profiles start in `off`.** Strict remains the recommended mode, but a first run that
  cuts the network teaches the operator to avoid the tool. `lethe setup` (M10) offers strict only
  after a selftest passes on that machine.
- **Every lockdown explains itself.** It says what happened, why (cause and alert, never baseline
  values) and the exact way out. The `status --json` field `lockdown` carries the same three parts.
  `status` without a daemon looks for leftover `lethe*` tables as root.
- **Reading one's own report** does not require a second key: `report` and `verify` accept
  `--baseline` and use the embedded `log_identity`.
- **Scheduling.** These items are milestone M8.1, after M8 and before M9, except `lethe setup`,
  which needs the selftest and goes into M10.

## Consequences
- Exit code 6 and the profile field `guard.arm_confirm` are new contracts.
- AC-16 to AC-18 cover the new behavior in the netlab.

## Implementation notes (M8.1)
- The proof is read from discovery: WireGuard peers through wgctrl, `rx_bytes` from the netlink
  link statistics of the tunnel interfaces (compared with the snapshot taken at arm), and
  `status/circuit-established` from the tor control port. The daemon polls every 500 ms without
  holding its lock, so sensors and IPC keep working during the window.
- `guard.arm_confirm` accepts 0 or 5 s to 5 min. Below 5 s a 25 s WireGuard keepalive may not
  fit; above 5 min the CLI would wait too long for an answer.
- During the window `status` reports `confirming: true` and a `lockdown` saying the lethe will
  undo the block by itself; `state.changed` with `ARMED` is journaled only with the proof (its
  data carries `proof`). A PANIC during the window ends the wait and keeps the block.
- The IPC error code -32004 carries `arm_unconfirmed`; the CLI maps it to exit code 6.
- `lethe status` without a daemon prints the state `NO_DAEMON` (status schema), keeps exit
  code 12 for scripts and, as root, fills `lockdown` from the leftover `lethe*` tables. Without
  root it adds `leftover_tables_unchecked` to `degraded` and says that `sudo lethe status` checks.
- SELF-006 is a condition alert: it stays open until acknowledged. Under `off` the lock covers
  every sensitive method, including the acknowledgment itself, for the 5 minutes.
