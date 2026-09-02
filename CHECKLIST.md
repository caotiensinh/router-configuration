# Master Completion Checklist

`PROJECT_PROGRESS.json` is the machine-readable source of truth. This document is its human-readable release checklist.

## Measurement rule

- v1 configuration automation is fixed at **100 weighted points**.
- Points are earned only when repository evidence and the stated acceptance gate exist.
- Documentation alone cannot complete a device-integration item.
- Future AI analytics is excluded; only its safe gateway placeholder is counted.

## Current measured status

**56% complete / 44% remaining.**

Change from previous checkpoint: **+4 points backed by real RouterOS CHR 7.24.1 live-smoke evidence**. GitHub Actions booted the official CHR image in isolated QEMU snapshot mode, reached the real REST service, exercised the project GET-only discovery client across every configured read surface, produced sanitized normalized evidence, and passed evidence-integrity validation. The recorded state reported RouterOS `7.24.1 (stable)`, architecture `x86_64`, no failed surfaces and no missing surfaces. This earns +2 P07, +1 P08 and +1 P13. It does **not** constitute full CHR acceptance because the smoke used isolated loopback HTTP and the factory admin account rather than a dedicated least-privilege reader with HTTPS/TLS verification and manual provenance review. No points were granted for renderer, apply, verify, rollback or physical CCR2116 testing.

| ID | Workstream | Weight | Earned | Status | Next acceptance gate |
| --- | --- | ---: | ---: | --- | --- |
| P01 | Spec / architecture / harness | 8 | 8 | DONE | — |
| P02 | Clean-room / security policy | 4 | 4 | DONE | — |
| P03 | Guided deployment profile | 6 | 6 | DONE | — |
| P04 | Operator workflow CLI | 2 | 2 | DONE | — |
| P05 | Intent/state/diff/drift core | 8 | 8 | DONE | — |
| P06 | Compiler / secret boundary | 4 | 3 | PARTIAL | RouterOS renderer only after full CHR read-only acceptance |
| P07 | RouterOS read-only discovery | 12 | 8 | PARTIAL | dedicated reader + HTTPS/TLS + provenance-reviewed CHR acceptance |
| P08 | RouterOS normalization | 6 | 5 | PARTIAL | populated high-value live surfaces + live RouterOS→core-state review |
| P09 | RouterOS renderer | 13 | 0 | NOT STARTED | deterministic safe-subset rendering after full CHR discovery acceptance |
| P10 | Backup/preflight/apply/verify/rollback | 15 | 5 | PARTIAL | real adapter transaction lifecycle after full CHR discovery acceptance |
| P11 | Dual-WAN / failover | 5 | 2 | PARTIAL | RouterOS compile + lab failover evidence |
| P12 | Security/VLAN/PBR/VPN/QoS | 8 | 1 | PARTIAL | RouterOS compiled policy + integration tests |
| P13 | CHR integration/failure lab | 5 | 1 | PARTIAL | full read-only acceptance, then mutation/failure/rollback lab |
| P14 | CI/regression/golden evidence | 2 | 2 | DONE | — |
| P15 | v1 release/beginner deployment docs | 1 | 0 | NOT STARTED | one-command guided deployment docs |
| P16 | AI observability gateway placeholder | 1 | 1 | DONE | AI engine intentionally deferred |

## Hard release gates

- [x] Product spec, architecture and harness execution contract exist.
- [x] Weighted progress ledger totals exactly 100 points and is machine-readable.
- [x] Guided profile initializer is read-only by construction and defaults to the 10G + 1G reference topology.
- [x] Guided profile compiles to deterministic `config-safe-subset-ir/1` without vendor commands or write transport.
- [x] RouterOS discovery transport has an explicit read-only endpoint allowlist.
- [x] RouterOS live-safe discovery CLI exists without a plaintext password CLI argument.
- [x] Production discovery defaults to HTTPS with TLS verification; insecure modes require explicit lab mode.
- [x] Discovery normalized state redacts private-key/PSK/password/token-like fields.
- [x] Discovery evidence has a second secret boundary, stable state digest and sanitized error codes.
- [x] RouterOS state/evidence verifier detects state, count, platform and capability-summary tampering before preflight.
- [x] Synthetic CI, CHR live and physical CCR2116 evidence classes are explicitly separated.
- [x] Profile-to-evidence preflight blocks model/port/requested-feature mismatches and supplies remediation text.
- [x] Synthetic REST transport integration matches the golden normalized state in CI.
- [x] `network-state/1` provides a stable vendor-neutral state boundary with deterministic RouterOS mapping and idempotent diff input.
- [x] Real RouterOS CHR 7.24.1 firmware/version evidence is recorded from an isolated live CI smoke.
- [x] Live CHR REST GET discovery reached every configured read surface with no failed/missing surfaces.
- [x] Live CHR normalized RouterOS evidence passed state digest and capability-summary verification.
- [x] Repeatable QEMU snapshot topology booted official CHR and preserved auditable sanitized evidence.
- [ ] Full CHR acceptance uses a dedicated least-privilege REST reader.
- [ ] Full CHR acceptance uses HTTPS with certificate verification.
- [ ] Full CHR evidence passes explicit provenance attestation/candidate review.
- [ ] Populated firewall/NAT/WireGuard/QoS objects are reviewed on live CHR or covered by an explicit accepted capability-gap policy.
- [ ] RouterOS renderer has golden tests for every supported operation.
- [ ] Production apply requires real backup evidence.
- [ ] Default-route/firewall/management changes require verified management reachability.
- [ ] Post-apply verification covers WAN, DNS, routing, VPN and management reachability as applicable.
- [ ] Failed verification produces rollback and recovery-verification evidence.
- [ ] Weighted 10G + 1G Dual-WAN behavior is tested in lab.
- [ ] ISP-down, Internet-down-with-link-up, DNS failure and route-loss simulations pass.
- [ ] Full CHR lab passes before physical CCR2116 testing.
- [ ] Physical CCR2116 acceptance evidence is recorded before production writer is enabled.
- [ ] CI is green on the exact release commit.

## Progress reporting contract

Every development handoff reports exact SHA, completed %, remaining %, point delta, checklist changes, test/CI evidence and the next highest-value gate.
