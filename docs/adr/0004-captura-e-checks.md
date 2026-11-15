# 0004. Capture sensor and check interface details (M5)

- Status: accepted
- Date: 2026-11-15

## Context
Spec §5.4 sketches one generic `Check` interface (`Start`, `Reconfigure`, `Evaluate` over an `Env`),
and §8.1 leaves a few corner cases of the cBPF allowlist open. M5 had to pick concrete shapes.

## Decision
- **Check interface.** `internal/checks.Check` carries only the static metadata of §5.4 (`ID`, `Kind`,
  `DefaultSeverity`, `Sources`, `SelfTestCases`). Each check exposes a typed, pure evaluator for the
  data it needs (`NET003.Evaluate(snapshot, expectIPv6)`, `NET005.Evaluate(routeChange, snapshot)`…).
  The daemon (M7) owns the sensors and the scheduling, and calls the evaluators. Reason: pure
  evaluators are table-testable without goroutines or an `Env` god object.
- **Layout.** `internal/checks` is flat, one file per check (`net001.go`…) plus `registry.go`.
- **cBPF corner cases (fail toward visibility):**
  - non-IP L2 frames other than ARP/EAPOL are delivered and classified as NET-001 subtype `l2`;
  - IPv6 extension headers are not walked in the filter: such packets are delivered and user space
    decides (the classifier walks up to 8 headers);
  - IPv6 LAN prefixes longer than /64 are not compiled into the filter (traffic to them is delivered);
  - IPv4 non-first fragments to an allowed (IP, protocol) are dropped (they carry no ports).
- **Policy rules (NET-005).** `vishvananda/netlink` has no rule subscription, so rules are diffed every
  second; routes and links use RTM_* subscriptions.
- **Attribution (NET-010).** Process lookup scans `/proc/*/fd` directly instead of `prometheus/procfs`
  (one readlink per fd; nothing else from procfs is needed yet). A socket found without a process gives
  `confidence: low` with the socket UID.

## Alternatives considered
- Generic `Start/Evaluate(Env)` per check: every check would need its own goroutine and a shared `Env`
  type before the daemon exists; harder to test.
- Walking IPv6 extension headers in cBPF: costs instructions per endpoint and the 256-endpoint budget.

## Consequences
Spec §5.4 is descriptive, not normative, for the method set; the registry and the metadata stay as
specified. Revisit if the daemon needs per-check lifecycle hooks.
