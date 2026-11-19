# 0016. A paged panel, from a design study

- Status: accepted
- Date: 2026-11-19

## Context
The panel was one dense window: verdict, route, block notice, the start form, the check grid and the timeline in a split, and the actions at the bottom. A design study (four screens: overview and tunnel, DNS and IP leak test, traffic inspector, kill switch) proposed a sidebar of pages, a top bar with the exit and a kill-switch button, summary cards, a topology of the tunnel and a table of traffic.

About half of what the study shows is not something lethe does, and some of it goes against the spec. The panel must show only what the daemon reports.

## Decision
The panel becomes a sidebar of six pages beside a top bar (spec §16.2):

- **Overview:** the verdict, the guard mode and the fingerprint; Check now and the DNS test; four area cards (packet leaks, DNS, tunnel, machine and persona) with open alerts and the worst severity; the route as a topology with duration, last check, open alerts and sensors; recent events.
- **DNS and IP:** the exit identity, the last DNS test's servers, and the leak surface (IPv4, IPv6, DNS, WebRTC/STUN, local network, exit/persona), each vector naming its checks.
- **Events:** session counters, the event table (time, check, process, protocol, destination, interface, status) filtered by interface, severity, check and "only leaks and blocks", and the selected event's detail.
- **Guard and panic:** the session's mode and what it does, the three modes with the current one marked, the default responses of §10.4 for it, and the selftest.
- **Checks:** the grid by category.
- **Session:** the session (ID, start, protection, fingerprint, acknowledge, selftest, end, reports), or the start form, or the first use.

The top bar keeps Panic apart from every other action and always says where the web sees the operator. The block notice sits under it on every page. A change of situation (no profile, no session, a session, the daemon down) brings the page that fits; otherwise the operator's page stays.

The theme does not change: the logo's colors and the platform font (ADR 0015). The study's palette (graphite, teal, brass, crimson) and its three bundled fonts were not adopted.

Rejected from the study, and why:
- **Server list, switching servers, MultiHop, Onion, a dedicated exit:** a VPN client's job. lethe watches the tunnel the operator already uses.
- **Latency, throughput, bytes sent and received, the transfer graph:** the daemon measures none of it, and measuring would mean generating traffic (principle 5).
- **Every flow in a table, a packet hex dump, PCAP/JSON dump:** lethe records leaks and state changes, never the whole traffic; a record of everything would be a dossier of the operation. Sealed fields stay sealed.
- **A probe against a chosen host:** active traffic to a target the operator types in.
- **A process whitelist by cgroup:** `socket cgroupv2` goes stale when the service restarts and does not run on every kernel (AGENTS.md).
- **A "furtive investigation" mode:** in practice the strict mode; a new mode needs a spec change.
- **Editing the triggers' actions from the GUI:** responses come from the profile; editing the profile from the GUI would be a new feature.
- **The nftables ruleset and per-rule drop counters:** not in the status; it would need a new IPC method. The page shows the block in place and its tables.
- **Search, avatar, "processes isolated", the daemon's PID:** nothing in lethe backs them.

## Consequences
- The view models of the new pages (`AreaOf`, `RowOf`, `FilterEvents`, `EventFields`, `ServerRows`, `Responses`) are pure and tested alone. Text from the daemon is cleaned of control and bidi characters before it is drawn, as the reports are.
- The panel's minimum width is about 1040 px.
- The area cards count unresolved alerts (acknowledged ones included, as the check grid does); the open-alerts counters count open, unacknowledged ones (as the tray does), each with the tone of what it counts.
- The session counters (outside the tunnel, blocked by the guard) add the alerts the status still lists. The engine drops resolved alerts past 1024 (`engine.MaxAlerts`), so in a very long session they count from the oldest alert still listed.
- The panel lays itself out again on every status (a label's new text can change its height), but it does not refresh the whole tree: fyne's objects repaint what moves, and a full refresh would redraw the hidden pages every second. A scroll is refreshed only when its content height changes.
- A row selected in the events table is not kept highlighted: the list moves with every new event, and the highlight would land on another one. The detail keeps the event.
- `lethe-gui` still imports only contracts, ipc, i18n, profile, setup and buildinfo.
- Candidates for a spec change, if wanted: guard drop counters and the `lethe*` tables over IPC, and editing the profile's responses.
