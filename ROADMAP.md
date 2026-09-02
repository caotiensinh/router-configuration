# Roadmap

## Current foundation

All ten module boundaries exist and the vendor-neutral core is executable, but no production router writer is enabled yet.

| Module | Capability | Status |
| --- | --- | --- |
| M01 | Intent & Device Engine | Foundation implemented + unit tests |
| M02 | State / Diff / Drift Engine | Foundation implemented + unit tests |
| M03 | Configuration Compiler & Secrets | Foundation implemented + plaintext-secret guard |
| M04 | Multi-WAN & Load Balancing | Capacity-weight planner implemented; 10G:1G reference test |
| M05 | Resilience & WAN Health | Weighted health scoring + hysteresis foundation |
| M06 | Security Operations | Baseline validator implemented |
| M07 | Segmentation / PBR / VPN / QoS | Intent models + validator implemented |
| M08 | Yamaha Adapter | Capability/dry-run boundary only |
| M09 | Safe Automation Gate | Apply authorization policy implemented |
| M10 | Omada Adapter | Official/experimental separation + capability preflight |

## v0.1 — MikroTik CCR2116 reference implementation

Next engineering milestones:

1. Define RouterOS capability/facts schema for a tested RouterOS v7 release.
2. Implement read-only RouterOS REST/SSH fact collection.
3. Normalize interfaces, addresses, routes, firewall, WireGuard, and queues into M01/M02 state.
4. Implement RouterOS renderer for a restricted safe subset.
5. Add command-level dry-run fixtures and golden tests written from our own specification.
6. Add backup and management-path preflight.
7. Add lab apply/verify/rollback against RouterOS CHR before physical CCR2116 testing.
8. Add weighted Dual-WAN routing policy for the 10Gbps + 1Gbps reference topology.
9. Add failure simulations: gateway reachable but Internet down, DNS failure, route loss, management-path risk.
10. Only after the above passes, enable an explicit `apply` command behind M09 Safety Gate.

## v0.2 — Yamaha RTX3510

- read running configuration over supported management interface;
- capability discovery;
- diff and safe render for approved features;
- backup/apply/verify/save lifecycle;
- multi-homing and policy-routing coverage.

## v0.3 — TP-Link Omada / ER8411

- official Open API authentication and version discovery;
- controller capability map;
- official API only in production;
- gateway state read and bounded write support where officially exposed.

## Non-goals for early releases

- no undocumented API writes in production;
- no automatic Internet-exposed management configuration;
- no autonomous destructive changes;
- no claim that 10G + 1G makes a single TCP flow 11Gbps;
- no untested vendor commands copied from public repositories.