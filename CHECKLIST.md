# Master Completion Checklist

`PROJECT_PROGRESS.json` is the machine-readable source of truth. This document is its human-readable release checklist.

## Measurement rule

- v1 configuration automation is fixed at **100 weighted points**.
- Points are earned only when repository evidence and the stated acceptance gate exist.
- Documentation alone cannot complete a device-integration item.
- Future AI analytics is excluded; only its safe gateway placeholder is counted.

## Current measured status

**77% complete / 23% remaining.**

Change from the previous 75% checkpoint: **+2 points backed by exact-head RouterOS CHR 7.24.1 deferred-secret WireGuard runtime evidence**. The WireGuard configuration slice now has explicit vendor-neutral intent facts, bounded and non-overlapping peer `allowed-address` validation, route containment checks, deterministic RouterOS command templates, unresolved private-key binding, and a product generation boundary that keeps WireGuard out of normal executable `commands` until both secret binding and an authorized transactional apply boundary exist. The accepted exact-head CHR run is `33643366359`, job `100291781530`, artifact `9851773597`, with artifact digest `sha256:7ea6819df9fcd3a33b09708cca7b1882dbcadf2aabc4a2c77f70b6aaea487fdd`. The sanitized evidence is retained in `evidence/chr/2026-09-02-wireguard-baseline-runtime-7.24.1.json`. The exact code SHA `c14f1a550bf9720f3001fd787a35114d5e2d0ea7` passed Python 3.11/3.12/3.13 normal CI in run `33643366356`; the evidence commit `7e76b1556043e507c112cec59a120c2d345e1e32` also passed all three versions in run `33643604804`. This earns +1 P09 and +1 P12. The gate does **not** claim a peer-to-peer WireGuard handshake, encrypted packet transfer, production UDP/51820 firewall admission, Internet reachability, physical CCR2116 behavior, or production writer readiness.

| ID | Workstream | Weight | Earned | Status | Next acceptance gate |
| --- | --- | ---: | ---: | --- | --- |
| P01 | Spec / architecture / harness | 8 | 8 | DONE | — |
| P02 | Clean-room / security policy | 4 | 4 | DONE | — |
| P03 | Guided deployment profile | 6 | 6 | DONE | — |
| P04 | Operator workflow CLI | 2 | 2 | DONE | — |
| P05 | Intent/state/diff/drift core | 8 | 8 | DONE | — |
| P06 | Compiler / secret boundary | 4 | 4 | DONE | Further RouterOS command coverage is tracked under P09 |
| P07 | RouterOS read-only discovery | 12 | 10 | PARTIAL | operator provenance attestation + candidate review |
| P08 | RouterOS normalization | 6 | 6 | DONE | — |
| P09 | RouterOS renderer | 13 | 8 | PARTIAL | QoS renderer slice; production apply remains separately gated |
| P10 | Backup/preflight/apply/verify/rollback | 15 | 5 | PARTIAL | real adapter transaction lifecycle after state-aware generation is complete |
| P11 | Dual-WAN / failover | 5 | 5 | DONE | — |
| P12 | Security/VLAN/PBR/VPN/QoS | 8 | 3 | PARTIAL | QoS, VLAN and PBR; WireGuard handshake/data-plane remains separately unclaimed |
| P13 | CHR integration/failure lab | 5 | 5 | DONE | — |
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
- [x] Real RouterOS CHR 7.24.1 firmware/version evidence is recorded from isolated live CI gates.
- [x] Live CHR REST GET discovery reached every configured read surface with no failed/missing surfaces.
- [x] Live CHR normalized RouterOS evidence passed state digest and capability-summary verification.
- [x] Repeatable QEMU snapshot topology boots official CHR and preserves auditable sanitized evidence.
- [x] Capacity-weighted 10G + 1G PCC distribution, WAN10 failure and recovery behavior passed disposable CHR packet-flow acceptance.
- [x] Enterprise RouterOS input firewall generation passed CHR dry-run, active runtime validity, management-path survival and exact rollback-to-baseline verification.
- [x] Firewall anti-spoofing is ordered before essential-ICMP acceptance and WAN input is default-deny in the accepted managed chain.
- [x] WireGuard explicit intent facts compile to a deferred-secret RouterOS template plan without resolving or serializing the private key.
- [x] WireGuard bounded `allowed-address` policy, RouterOS runtime validity, management-path survival and exact rollback passed disposable CHR 7.24.1 acceptance.
- [x] WireGuard CHR evidence confirms `private_key_recorded=false`, `private_key_serialized=false`, no PSK, no product writer and no product write transport.
- [ ] WireGuard peer-to-peer handshake and encrypted packet transfer are independently proven where required by the v1 acceptance scope.
- [ ] Full CHR acceptance uses a dedicated least-privilege REST reader.
- [ ] Full CHR acceptance uses HTTPS with certificate verification.
- [ ] Full CHR evidence passes explicit provenance attestation/candidate review.
- [ ] Populated NAT/QoS objects are reviewed on live CHR or covered by an explicit accepted capability-gap policy.
- [ ] RouterOS renderer has accepted coverage for every planned v1 operation, including QoS.
- [ ] Production apply requires real backup evidence.
- [ ] Default-route/firewall/management changes require verified management reachability in the production transaction path.
- [ ] Post-apply verification covers WAN, DNS, routing, VPN and management reachability as applicable.
- [ ] Failed production verification produces rollback and recovery-verification evidence.
- [ ] Internet-down-with-link-up, DNS failure and route-loss simulations pass in addition to the accepted WAN failure/recovery gate.
- [x] Disposable CHR integration/failure simulation gates pass for the currently implemented safe-subset slices before physical CCR2116 testing.
- [ ] Physical CCR2116 acceptance evidence is recorded before production writer is enabled.
- [ ] CI is green on the exact release commit.

## Progress reporting contract

Every development handoff reports exact SHA, completed %, remaining %, point delta, checklist changes, test/CI evidence and the next highest-value gate.
