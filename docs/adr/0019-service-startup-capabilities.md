# 0019. Start-up capabilities in the service units

- Status: accepted
- Date: 2026-11-20

## Context
`lethed@<user>.service` died on every start with `ipc: chown /run/lethe: operation not permitted`,
and systemd gave up after five restarts. The unit's `CapabilityBoundingSet=` was exactly the six
capabilities of spec §19.3, which the daemon keeps **after** it drops privileges. But in both
modes the daemon drops them only at the first arm (`HardenAfterArm`), and before that it needs
more:

- `CAP_CHOWN`: `/run/lethe` and the socket go to the operator; `storage.dir/state` and the
  session directory get the operator's group.
- `CAP_DAC_OVERRIDE`: those directories are created inside `storage.dir` (`~/lethe`), which the
  operator owns with mode 0700. `CAP_DAC_READ_SEARCH` only reads.
- `CAP_FSETID`: they are setgid so new files inherit the operator's group; the kernel clears
  that bit when root, who is not in that group, sets it without this capability.

Portable mode (`sudo lethe run`) starts with every capability, so the tests, which follow that
path, never saw this. The unit test only compared the unit with `privsep.Keep`.

## Decision
- `privsep.Startup` lists the three start-up capabilities. Both service units bound the daemon to
  `Keep` plus `Startup`; `Harden` drops `Startup` at the first arm, as in portable mode. The unit
  test now requires exactly that union.
- Spec §19.3 says so.

## Consequences
- Before the first arm, a service-mode daemon holds three capabilities more than after it,
  still fewer than portable mode holds at the same point. After the arm nothing changes: the e2e
  still checks that the bounding set equals `Keep`.
- The panel now says when a started service never answers (`service_no_answer`), with the
  `journalctl` command that shows why, instead of "connects in a moment".
