# 0010. Selftest and first-use assistant

- Status: accepted
- Date: 2026-11-16

## Context
M10 delivers every case of spec §18.2, the temporary strict exceptions, the dry-run of the
responses, `selftest.json` and `lethe setup`. Some points were open: where the selftest runs, how
its findings are told apart from real ones, how RESP-001 is confirmed, and DNS-004, which ST-DNS-004
needs but no milestone delivered.

## Decision
- **The selftest runs in the armed session's daemon** (`selftest.run` over IPC), because the
  daemon owns the sensors, the guard and the privileges. `lethe selftest` without a daemon does
  not start one: it says how (`sudo lethe run -p PROFILE --guard off`, then `lethe selftest`).
  It refuses while the session is not ARMED (arm window, PANIC) and runs one at a time.
- **Probes, not flags on the sensors.** Each case registers a probe that recognises what it
  causes: the exact flow (protocol, documentation destination, ephemeral source port), the dummy
  interface `lethe-st0`, the table `inet lethe_selftest`, the child PID named `lethe-st-deny`, the
  watched test file. A recognised finding is journaled with `selftest: true`, `source: selftest`
  and `data.dry_run`, with the engine's plan as `actions`; no alert is opened and nothing runs.
  Late findings of a finished case are absorbed for 5 s (a TCP retransmission, the next socket scan).
- **Strict exceptions** go into `guard.Config.Exceptions`: first rule of `inet lethe output`
  (`meta skuid 0`, daddr, l4proto, sport, dport) and of the L2 chains (no UID at netdev). The
  ruleset is replaced in one transaction to add and again to remove. The guard refuses any
  exception whose destination is not RFC 5737 / RFC 3849, so a bug cannot open a real leak.
  The discovery refresh keeps the exception of the running case.
- **ST-NET-002** sends the same datagram without the exception: `sendto` returns EPERM and the
  case waits for the NFLOG record with UID 0.
- **RESP-001** applies the panic tables for real, proves that test traffic gets EPERM, and
  removes them (in strict, the strict ruleset is restored in one transaction, so its L2 table is
  never missing). The session state does not change. It runs only when the call carries the
  passphrase proof: `lethe selftest` asks first ("a rede para por cerca de 1 s"), `--yes`
  confirms without asking (new flag), and `--json` without `--yes` skips it.
- **ST-NET-003** skips when the egress has no global IPv6. An armed lab never has it, because
  IPv6 outside the tunnel fails the preflight (NET-003 CRITICAL); AC-11 accepts that skip.
- **ST-HOST-001** re-executes `/proc/self/exe selftest-deny` (hidden command), which writes
  `lethe-st-deny` to `/proc/self/comm`; a selftest deny rule is active only during the case.
- **ST-SELF-001/002** use `PauseSensor` and `ShrinkCapture`; the original `SO_RCVBUF` is restored.
- **Results**: `selftest.result` in the journal, and, only for a full run, `storage.dir/state/
  selftest.json` (owned by the operator, so the preflight without the daemon reads it). The file
  has `critical`: a failure in ST-NET-001, ST-NET-002 or RESP-001 makes SELF-004 CRITICAL.
- **DNS-004 is delivered here** (inotify on the directory of `/etc/resolv.conf` and of its
  symlink target, plus the selftest file `storage.dir/state/selftest-resolv.conf`). The resolved
  and NetworkManager D-Bus signals of §9.2 are not subscribed yet: a change made only through
  D-Bus is seen at the next discovery refresh. DNS-002/003 stay pending.
- **TUN-004** now leaves out only lethe's own tables (`nftmon.Own`), not every `lethe*` name:
  otherwise ST-TUN-004 could not be seen and a third party could hide behind the prefix.
- **`lethe setup`** asks the operation, persona, exit type (suggested from the discovery),
  expected country, timezone, locale and keyboard, creates the baseline with the manual questions
  (or reuses one), and writes `~/lethe/profile.yaml` in off. Strict is offered only with a full,
  passed selftest under 24 h old; then the profile is switched and the preflight under strict is
  shown. Running `setup` again with an existing profile goes straight to that offer.
