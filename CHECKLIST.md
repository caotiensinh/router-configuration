# Master Completion Checklist

`PROJECT_PROGRESS.json` is the machine-readable source of truth. This document is its human-readable release checklist.

## Measurement rule

- v1 configuration automation is fixed at **100 weighted points**.
- Points are earned only when repository evidence and the stated acceptance gate exist.
- Documentation alone cannot complete a device-integration item.
- Future AI analytics is excluded; only its safe gateway placeholder is counted.

## Current measured status

**79% complete / 21% remaining.**

Change from the previous 77% checkpoint: **+2 points backed by exact-head RouterOS CHR 7.24.1 management-safe PBR runtime evidence and exact-main CI after integration**. The accepted PBR slice provides bounded IPv4 source/destination policy facts, deterministic `/routing rule` rendering with `lookup-only-in-table`, explicit table containment, management-path protection, owned-only rollback, and no mangle routing-mark dependency. Exact integration head `23d2ce014140549fded1f424e1f96f35ca74ed0b` passed Python 3.11/3.12/3.13 in run `33653259829` and official CHR 7.24.1 runtime acceptance in run `33653259614`; artifact `9855744336` has digest `sha256:95dbbcd94816ec68243cdb00e366853325aa66ecc8221741cd211f1d99c0e128`. PR #7 merged as `8729e7cabc481cce1a0b005570cd892781ef0db0`, which then passed exact-main Python 3.11/3.12/3.13 CI in run `33653716319`. The sanitized evidence is retained in `evidence/chr/2026-09-02-pbr-routing-rule-runtime-7.24.1.json`. This earns +1 P09 and +1 P12. The gate does **not** claim PBR route-selection data-plane acceptance, production writer readiness, physical CCR2116 behavior, or any production mutation capability.

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
| P09 | RouterOS renderer | 13 | 9 | PARTIAL | QoS and VLAN renderer/runtime coverage; production apply remains separately gated |
| P10 | Backup/preflight/apply/verify/rollback | 15 | 5 | PARTIAL | real adapter transaction lifecycle after state-aware generation is complete |
| P11 | Dual-WAN / failover | 5 | 5 | DONE | — |
| P12 | Security/VLAN/PBR/VPN/QoS | 8 | 4 | PARTIAL | QoS and VLAN; WireGuard handshake and PBR route-selection data-plane remain separately unclaimed |
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
- [x] Management-safe PBR `/routing rule` generation passed CHR dry-run, runtime validity, management-path survival and exact rollback-to-baseline verification.
- [ ] PBR route-selection data-plane behavior is independently proven where required by the v1 acceptance scope.
- [ ] WireGuard peer-to-peer handshake and encrypted packet transfer are independently proven where required by the v1 acceptance scope.
- [ ] Full CHR acceptance uses a dedicated least-privilege REST reader.
- [ ] Full CHR acceptance uses HTTPS with certificate verification.
- [ ] Full CHR evidence passes explicit provenance attestation/candidate review.
- [ ] Populated NAT/QoS objects are reviewed on live CHR or covered by an explicit accepted capability-gap policy.
- [ ] RouterOS renderer has accepted coverage for every planned v1 operation, including QoS and VLAN.
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
