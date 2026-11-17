# 0015. Security review and GUI-first operation

- Status: accepted
- Date: 2026-11-17

## Context
A review after M15 looked for bugs, security issues and technical debt, with one product goal: the operator must never lock the network by accident and be left without a way to undo it. The review also asked for two things:
- that everything an operator does day to day can be done from the GUI, with the CLI only starting the tool;
- that the panel shows where the web sees the operator, as VPN clients do.

## Decision
Security fixes (each with a test named after its ID):
- **Root writes in the operator's state directory go through descriptors** (`platform.OpenDir`, `MkdirAt`, `WriteFileAt`). A planted symlink is replaced and never followed (SELF-001).
- **Kills are limited to the operator's processes.** `kill_processes` and `kill_offender` act only on the operator's UID, and they check the executable against the PID again before the signal. A root service that matches a rule (`systemd-resolved`, NetworkManager) is never killed.
- **Interfaces that `link_down` took down come back up.** They are recorded under `/run/lethe-state` (tmpfs, root only) and restored on unpanic, on the session end and by `lethe cleanup`.
- **SELF-006 counts only a wrong MAC.** A missing proof or an expired nonce is a client error. Counting it would let a slow dialog cause a panic without one wrong passphrase.
- **The TUI strips control characters** from process names and daemon text before drawing them.

Ways out of a block:
- **Disarm also works in PANIC** (passphrase). The unpanic re-check needs the tunnel, and the default panic blocks the tunnel. When the VPN really goes down, the re-check can never pass, so the only exit used to be `sudo lethe cleanup` in a terminal. Ending the session from PANIC journals `session.end` with `reason: disarm_in_panic` and the count of unacknowledged CRITICALs. Without the passphrase (a signal, a crash) the block stays, on purpose (spec §10.6 item 10).
- The GUI shows the block notice with both exits as buttons: leave the panic, or end the session.

Where the exit is:
- **Exit place.** The status carries the exit IP when it is not a baseline value, and the city and country the endpoint claims (`am.i.mullvad.net` answers both), with the source named. The country that decides alerts is still the one from the offline database.
- **DNS leak test.** It runs only when the operator asks, through `dns.leak_test`, a safe method:
  - it resolves 10 random `N.ID.bash.ws` names through the system resolver, which is the path under test;
  - it fetches the result through the NET-011 path (the tunnel or Tor), and with no such path it stops before resolving anything;
  - a resolver from `baseline.networks[].resolvers` is shown by its field name.
  The result is not journaled, since no event type exists for it. A baseline resolver seen by the test raises DNS-002 (CRITICAL), kept in its own condition group until the next test.
- **`active.check_now`** (safe) starts a NET-011 round.

GUI first:
- The panel starts sessions. It reads the profile and the baseline it names as the operator and sends `session.arm` with the passphrase and the chosen protection.
- To find `baseline.file`, the GUI now also imports `internal/profile`. That package does parsing only and depends only on `internal/contracts`. The import test enforces the new list.
- The profile path is never stored: a remembered path could name the operation. The default is the one `lethe setup` writes (`~/lethe/profile.yaml`).
- The GUI finds the daemon on the portable socket, then the service socket. When neither answers, it says how to start the service.
- Theme: the palette of the logo. Charcoal canvas, aged gold for the one primary action and a protected route, teal for selection, sage, ochre and brick for ok, warning and critical. Only the dark composition exists: the panel is watched for hours in dim rooms.

## Consequences
- An operator who knows the passphrase can always release the network from the panel, with or without a working tunnel. An attacker without it cannot.
- The DNS leak test makes the system resolver ask for `bash.ws` names. When DNS is leaking, whoever sees it learns that someone ran the test. The GUI says so before running it.
- `bash.ws`'s JSON format has no documentation. It was checked against the live service on 2026-11-17: a list of `{ip, country (lowercase ISO), country_name, asn, org, type}`, or `{"error": ...}` when no lookup arrived. Anything else skips the test.
- First use is in the GUI too. While `~/lethe/profile.yaml` is missing, the panel shows a form in place of the session start, even with the daemon down:
  - it fills the gateway, the resolvers and the kind of tunnel from a local reading;
  - it asks the public IP only on request, and never with a tunnel on the default route;
  - the only secret is the passphrase, typed twice, with no key to generate or keep.
  The creation moved to `internal/setup`, shared with `lethe setup`. It runs as the operator, and a test keeps it away from the guard, the responses, the daemon, privsep and `os/exec` in lethe code. The GUI may now import `internal/setup` and `internal/buildinfo`, which pulls netlink, D-Bus and age into the GUI module.
