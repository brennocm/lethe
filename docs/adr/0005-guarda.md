# 0005. Guard (nftables) details (M6)

- Status: accepted
- Date: 2026-11-15

## Context
Spec §11 fixes the tables, but leaves gaps that M6 had to close. Some of them came up only on a
real kernel.

## Decision
- **L2 layer filters IP too.** The spec's `netdev lethe_l2` dropped only non-IP frames ("IP already
  went through inet lethe"). That is false for AF_PACKET senders: they never cross the inet hooks
  (§8.2). The fail-closed choice is to give each egress chain the same IP allowlist as inet output
  (endpoints, WireGuard mark, DHCP, NDP/MLD, LAN when allowed), with its own sets updated in the same
  transaction, then `log group 4242 prefix "LETHE-L2 "` and `drop`. The e2e control test shows a raw
  IP frame leaving without the layer and blocked with it. The `socket cgroupv2` exception is not
  allowed in netdev hooks, so it exists only in inet. The OpenVPN client's endpoints must therefore
  be in the endpoint sets (learned via NFLOG, M8) before its traffic can leave.
- **Kernel feature probe.** `guard.Probe` loads throwaway `lethe_probe` tables and deletes them in
  the same transaction to detect the netdev egress hook, `nft_socket` (cgroupv2) and the bridge
  family. The daemon leaves out what is missing and reports it in the preflight; it never arms with a
  ruleset the kernel would reject. (The WSL2 kernel has no `CONFIG_NFT_SOCKET` and no
  `CONFIG_NF_TABLES_BRIDGE`.)
- **NFLOG UID.** NFLOG has no UID/GID flag. The kernel always adds `NFULA_UID/GID` for packets of a
  local full socket. Spec §9.1 is corrected.
- **keep_tunnel panic** = lo + tunnel interfaces + WireGuard mark/VPN cgroup + endpoints (out) and
  lo + tunnel + endpoint sources (in); no internal interfaces, DHCP/NDP or LAN in the inet table. The
  L2 chains keep ARP, endpoints, DHCP and NDP so the tunnel transport keeps working.
- **Bridge** table at priority -210 (bridge filter − 10): ARP passes; DHCP towards egress ports
  passes; every other IP frame towards egress ports is logged and dropped. That includes IPv6 NDP of
  bridged VMs ("except ARP and DHCP", taken literally).
- **Set IDs** are bound at apply time (the library allocates transaction-unique IDs).
- **cgroup watch** polls the cgroup directory's inode (the cgroup v2 ID) every second instead of
  inotify on `cgroup.events`. A restart recreates the directory and changes the inode, and a poll
  sees that.

## Alternatives considered
- Keep L2 non-IP only: leaves raw-socket IP leaks open, contradicting §8.2.
- Fail arm when a feature is missing: makes strict mode unusable on kernels without `nft_socket`,
  although the endpoint allowlist alone is more restrictive.

## Consequences
Two copies of the endpoint sets (inet and netdev) have to stay in sync. `UpdateSets` always writes
both in one transaction. Revisit when eBPF replaces the cBPF/netdev layers (v1.1).
