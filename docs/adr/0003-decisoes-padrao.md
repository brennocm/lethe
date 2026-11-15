# 0003. Default decisions D1–D10 from the spec

- Status: accepted
- Date: 2026-11-15

## Context
The v0.1 spec left open questions that would block implementation.

## Decision
Adopt decisions D1–D10 exactly as written in `spec.md` §25 (name `lethe`, Fyne GUI, optional
institutional keys, single-person `--force` with reason and passphrase, public active-check endpoints
with a generic User-Agent, retention out of scope, manual checklist every session, no dynamic Tor PTs
in strict mode, `apps/` + `internal/` layout, baseline values only inside the age file).

## Alternatives considered
See the "Por quê" column of spec §25 for each item.

## Consequences
Any change to one of these items supersedes this ADR with a new one and updates spec §25.
