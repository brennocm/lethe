# 0006. Daemon, session and IPC details (M7)

- Status: accepted
- Date: 2026-11-15

## Context
Spec §5, §6, §10.5, §17 and §19.3 describe the daemon. Some details had gaps, or turned out to
contradict each other once the code had to run.

## Decision
- **One mutex, not an actor.** The engine and the journal are only called under `Daemon.mu`.
  Sensors and IPC handlers only deliver events to it. Response actions run before the alert is
  journaled, so blocking does not wait for an fsync, but the alert still comes before its
  `response.executed` in `seq`.
- **`session.arm` carries the passphrase.** The daemon needs the passphrase to decrypt the
  baseline and derive `K` (§17.3), so it cannot use an HMAC before the session exists. The CLI
  reads the profile and the baseline with the operator's rights and sends their bytes together with
  the passphrase over the peer-checked socket. Successful decryption is the proof. The daemon never
  opens a path chosen by a peer. The passphrase is wiped once `K` is derived, and the raw
  parameters are zeroed after decoding. Five wrong passphrases within 5 min lock `arm` for 5 min.
  Every other sensitive method uses the HMAC challenge. The salt goes in `session.start` (as
  `auth_salt`) and in `status.get`.
- **Preflight on arm.** `session.arm` runs the automatic preflight in the daemon. The CLI asks the
  manual checklist on the terminal and sends the answers, and each one is journaled. A negative or
  missing answer makes the result FAIL (fail-closed). Without `--force --reason`, a FAIL refuses
  the arm with exit code 2. With them, the arm goes ahead and is journaled as `operator.force`.
- **Unpanic ordering.** In strict mode, the strict tables are reapplied first and the panic table
  is removed second, so there is never a moment without a guard. In reactive mode, the panic and
  L2 tables are removed. Links taken down by `link_down` stay down: bringing them back is the
  operator's call. If any step fails, the session goes back to PANIC. The state re-check covers
  NET-003 and NET-004, the state checks implemented so far; DNS-002, TUN-001 and TUN-003 join it
  when they exist (M8/M9).
- **Ending in PANIC keeps the block.** Ctrl-C on `run`, or stopping the daemon while in PANIC,
  closes the journal and leaves the tables in place. `lethe cleanup` (root) removes them.
- **Privileges are dropped after arm, and there is one session per daemon process.** After
  `Harden`, the daemon has no `CAP_CHOWN`, `CAP_DAC_OVERRIDE` or `CAP_SETUID`. It could not create
  the next session directory as root:operator, nor fork another agent. So the portable daemon
  (`run`) hardens after its single arm. The service daemon also hardens after arm and exits when
  the session ends, and systemd starts a fresh one. `storage.dir/sessions` and each session
  directory are root:operator `02750`, so the operator can read the sessions (`report`, `verify`).
- **SELF-001 and SELF-003 as state.** A heartbeat source that stays silent for more than 3 s
  (capture per interface, netlink, nflog, sock_diag, the agent) produces `sensor.down` and turns
  the state GRAY. Its return produces `sensor.up`. They are not separate alerts: the closed event
  list already covers them, and the color is what the operator acts on.
- **Agent reports are low-trust.** `agent.report` accepts only `check.alert`. The source is forced
  to `agent`, and the engine never lets that source resolve anything (principle 9).
- **Terminal alerts.** With no GUI (M12), the daemon prints one line per new or escalated alert,
  with a bell for CRITICAL. Baseline values are redacted from it as a second line of defense.

## Consequences
- `lethe run` needs root and a terminal (or `--passphrase-fd`). `lethe arm` works only against a
  freshly started service daemon.
- In service mode, the agent comes from a user unit and cannot be recognized by PID. Until
  packaging (M13) settles how it identifies itself, it is treated like any other operator client
  and cannot call `agent.report`.
- `--tui` returns "not implemented" until M12. `--no-gui` and `--no-active` are accepted and
  change nothing yet.
