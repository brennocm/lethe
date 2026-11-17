# 0009. Host, persona, self checks and the session agent

- Status: accepted
- Date: 2026-11-16

## Context
M9 adds the host checks (HOST-001…009), the persona checks (PER-001…003), the self checks
SELF-001…005, the Wi-Fi and LAN identity checks (NET-007/008/009/013/014) and the session agent.
The spec leaves some points open: what exactly the agent sends, how its data may affect alerts,
how a screencast is recognised, and what SELF-005 does when `timerfd` is not usable. Following the
fail-closed rule, the gaps are closed with the more restrictive option.

## Decision
- **The agent sends facts, never checks.** `agent.report` carries `{lang, keyboard, capture:
  {audio, video, screencast}}`. The daemon derives HOST-002, HOST-003, HOST-005 and PER-001 from
  them; the agent cannot pick a check ID or a severity. Before M9 the method accepted an arbitrary
  `check.alert`, which let a compromised agent fill the log with any check.
- **Agent data may raise, never clear or lower.** Agent findings are journaled with source
  `agent`, and the engine ignores agent resolutions (already the case since M7). A daemon finding
  of the same check at a higher severity is never lowered by the agent. Reports are size and
  range checked (64 bytes per string, counts 0…1024).
- **Keyboard:** when the agent reports a layout, PER-001 uses it and the daemon stops comparing
  the system layout (locale1/`/etc/default/keyboard`), so the two sources do not fight.
- **Screencast (HOST-003) through PipeWire, not the portal D-Bus.** The xdg portal lives on the
  session bus and exposes no list of active sessions. The agent speaks the PipeWire native
  protocol (hello, registry, sync; read-only, no objects created) and counts `Video/Source` nodes
  whose name marks a compositor screencast (gnome-shell, mutter, kwin, xdpw, obs). Capture streams
  are `Stream/Input/Audio` and `Stream/Input/Video`. No library is added: the client is ~250
  lines with a fuzzed pod parser.
- **Notifications** go through `org.freedesktop.Notifications` on the session bus, with the
  `sound-name` hint when the plan has `alert_sound`; CRITICAL stays until dismissed and tells the
  operator to look at the terminal or `lethe status` (principle 11). No player is executed.
- **SELF-005** compares `CLOCK_REALTIME − CLOCK_BOOTTIME` at every 1 s tick and on wakeups of a
  `CLOCK_REALTIME` timerfd armed with `TFD_TIMER_CANCEL_ON_SET`. A jump over 2 s writes
  `clock.jump` and opens SELF-005 INFO. If timerfd is not available, the tick comparison remains.
- **SELF-002** reads `PACKET_STATISTICS` every tick (the counter resets on read) and opens a
  WARNING per interface with drops. Selftest hooks `PauseSensor` and `ShrinkCapture` exist for
  M10 (ST-SELF-001/002); they are not on the IPC yet.
- **Host reading outside the lock.** A collector reads `/proc`, sysfs, `/etc`, browser prefs and
  the system bus (2 s deadline per read, `NameHasOwner` so no service is activated) every 2 s;
  the evaluation then runs under the daemon lock. A source that fails is listed as a warning and
  its checks are neither reported nor resolved, so a missing bus never clears an alert.
- **Preflight** runs the same evaluation (`checks.EvaluateHost`). `lethe preflight` without the
  passphrase cannot compare with the baseline (HOST-004, HOST-008, NET-014 with hostname): the
  arm, which has the baseline, does.
- **NET-009** decodes the names announced by mDNS, LLMNR, NBNS, NetBIOS datagrams and SSDP and
  raises to CRITICAL when one equals the baseline hostname; the name is sealed and only
  `baseline.hostname` is written in the clear.
- **NET-007** compares the Wi-Fi seen at the arm with the current one; CRITICAL if the new SSID is
  in the baseline. SSIDs and BSSIDs never leave the process memory in the clear.

## Consequences
- GNOME keeps the session layout in dconf, which the agent does not parse; PER-001 then uses the
  system layout. Listed in §22.
- The screencast heuristic depends on node names; a compositor with another naming is missed.
- In the lab, the host's real files are read, so e2e tests must not assume a clean host
  (HOST-005/006 may be open).
