# Master Completion Checklist

`PROJECT_PROGRESS.json` is the machine-readable source of truth. This document is its human-readable release checklist.

## Measurement rule

- v1 configuration automation is fixed at **100 weighted points**.
- Points are earned only when repository evidence and the stated acceptance gate exist.
- Documentation alone cannot complete a device-integration item.
- Future AI analytics is excluded; only its safe gateway placeholder is counted.

## Current measured status

**91% complete / 9% remaining.**

Change from the previous 90% checkpoint: **+1 P10 point for accepted Internet-down-with-link-up recursive failover/recovery on disposable official RouterOS CHR 7.24.1**. The accepted exact-head behavior is bound to commit `bc7054732d07c02303cc9e0dfc01587c4f24fbbf`; workflow run `34809160558`, job `103866838708`, artifact `10334520218`, digest `sha256:e6682301e9956f8c066af1eae1833e4d650f337cda01809daf62b84450a1299f`. Readiness passed with a 1/1 WAN10 probe after isolating the disposable CHR management DHCP default at distance 250. Direct artifact inspection proved NORMAL 220/220 via WAN10, `tc netem loss 100%` upstream blackhole while host/namespace/RouterOS ether2 remained UP, WAN10 recursive-route withdrawal with WAN1 activation, FAILOVER 220/220 via WAN1, and RECOVERY 220/220 via WAN10. The evidence explicitly retains `production_writer_available=false` and `write_authorized=false`; it does not claim physical-router or production-write readiness.

Change from the previous 87% checkpoint: **+3 weighted points across accepted transaction management-survival and P12 data-plane gates**. P10 earns +1 after official RouterOS CHR 7.24.1 management-survival acceptance on commit `24cab4942d08c5e7180d5335d10966b32febdb36`; run `33722252559`, job `100543633740`, artifact `9880659158`, digest `sha256:3803e0d005b4fea04f1d61f644251fad5c4e164f032310f58d36525b7e14ceee`. An independent REST management session completed 46/46 successful probes, including 40/40 during apply, while the admitted mutation became visible. This does **not** enable a production writer, target a physical router or set `write_authorized=true`.

P12 earns its final +2 and is now DONE after three independent CHR data-plane gates. WireGuard handshake/encrypted transfer passed on run `33745204176`, job `100615967147`, artifact `9889360503`, digest `sha256:215473721fc75298145c1b292234e8cb1286c3081958e68a07a7f58e1e97ca06`, with both peers reporting a handshake and 30/30 encrypted flows while no private key or PSK was recorded. PBR route selection passed on run `33744535536`, job `100613883852`, artifact `9889110242`, digest `sha256:f7d54814298ad36f6a746b695258abce0dd0a2adc07375581989404a7cc26f7c`, with 30/30 flows on the selected policy path and 0/30 in the negative control. In-band VLAN data-plane passed after commit `c19192bf32e73fba8a0dab94bdbdd46e3a2d5f5c` moved L2 warm-up outside the measured window without lowering the strict 30/30 acceptance threshold; run `33725564543`, job `100553643895`, artifact `9881848837`, digest `sha256:9f0a7663b99a37ea013bf469e2c17614c50a988d67e8926528062e3e6092ee42` proved 30/30 tagged VLAN20 flows, 0/30 untagged negative-control flows and exact rollback restoration.

Change from the previous 83% checkpoint: **+4 weighted points across accepted QoS and transaction-runtime gates**. QoS global sibling Queue Tree rendering earns +1 P09 and +1 P12 after PR #17 merged as `e5c6f3c2cf87b356dd66d73b3b3a8380bd64c000`; exact-main Python CI passed in run `33714864826`, and official RouterOS CHR 7.24.1 packet-flow acceptance passed in run `33714864851`, artifact `9878150512`, digest `sha256:ffdf7880d5bf335b286240051967eb30fc21973f69e0850b392ca400177b5a3f`. Direct evidence shows DSCP0 80/80 traversing the unmarked default sibling leaf and DSCP46 80/80 traversing the marked priority sibling leaf, with no default catch-all mangle rule and exact owned rollback restoration. This does **not** claim aggregate WAN shaping, bandwidth guarantees or measured latency improvement.

P10 earns +2 further points for two independent disposable-CHR transaction gates. PR #18 proves fresh-session rollback recovery verification and lifecycle transition to `rolled_back`; exact-head CI run `33718603023` and CHR recovery run `33718603041` passed with artifact `9879476571`, digest `sha256:d9005c7fe25c56c58b955dc359f1325065aac406dee125617f254253b1d330d5`. PR #19 merged as `2eaaa005ce56d19a5ed01f4a64f385e7ef6b6583` and proves fresh-session post-apply verification on the admitted success path; exact-main CI run `33719518370` and CHR post-apply run `33719518415` passed with artifact `9879726318`, digest `sha256:586d71f53fea6a252e5483bbe3cfa66e57ed25e3bf6b2a18caca4810b6ace199`. These credits do **not** claim production backup/apply readiness, operator attestation, a production writer, a physical-router target or `write_authorized=true`.

Change from the previous 82% checkpoint: **+1 P10 point for disposable CHR transaction runtime admission proven on exact `main` before the first mutation-capable runtime call**. PR #14 established repository-safe backup evidence binding without earning a standalone weighted point. PR #15 merged as `7cbf66bddd7294c4b65cae866a5dca3e92598013`; exact-main Python CI passed in run `33696304595`, and official RouterOS CHR 7.24.1 transaction acceptance passed in run `33696304538`, artifact `9871930098`, digest `sha256:481b933033310231fbf6ce84c3c374214908760e56d09e405f31de1afc1a9d9f`. Direct artifact inspection confirmed that transaction admission completed before mutation, the bound pre-state digest matched the runtime baseline and restored rollback digest, controlled failure and exact rollback were observed, and the lifecycle conservatively stopped at `rollback_observed` at that checkpoint.

Change from the previous 79% checkpoint: **+3 points backed by two independent accepted workstreams on exact `main`**. The guided release slice adds the generation-only `routerctl guided-start` entry point and beginner deployment guide without credentials, discovery transport, apply capability or a production writer; PR #9 merged as `fd19ebe32dbc375637a91389ec4f2dc85ba92516`. The management-safe VLAN slice passed official RouterOS CHR 7.24.1 dry-run, runtime validity, management survival and owned-only exact rollback; PR #10 merged as `59981898b564726552554be787284a512a435ac5`. These gates earned +1 P15, +1 P09 and +1 P12.

| ID | Workstream | Weight | Earned | Status | Next acceptance gate |
| --- | --- | ---: | ---: | --- | --- |
| P01 | Spec / architecture / harness | 8 | 8 | DONE | — |
| P02 | Clean-room / security policy | 4 | 4 | DONE | — |
| P03 | Guided deployment profile | 6 | 6 | DONE | — |
| P04 | Operator workflow CLI | 2 | 2 | DONE | — |
| P05 | Intent/state/diff/drift core | 8 | 8 | DONE | — |
| P06 | Compiler / secret boundary | 4 | 4 | DONE | Further RouterOS command coverage is tracked under P09 |
| P07 | RouterOS read-only discovery | 12 | 10 | PARTIAL | dedicated least-privilege HTTPS reader + explicit provenance attestation/candidate review |
| P08 | RouterOS normalization | 6 | 6 | DONE | — |
| P09 | RouterOS renderer | 13 | 11 | PARTIAL | close remaining v1 renderer capability gaps; production apply remains separately gated |
| P10 | Backup/preflight/apply/verify/rollback | 15 | 10 | PARTIAL | DNS-failure and route-loss simulations + production-grade backup/management reachability + applicable WAN/DNS/routing/VPN verification + rollback recovery; production writer remains disabled |
| P11 | Dual-WAN / failover | 5 | 5 | DONE | — |
| P12 | Security/VLAN/PBR/VPN/QoS | 8 | 8 | DONE | — |
| P13 | CHR integration/failure lab | 5 | 5 | DONE | — |
| P14 | CI/regression/golden evidence | 2 | 2 | DONE | — |
| P15 | v1 release/beginner deployment docs | 1 | 1 | DONE | Final v1 release still depends on remaining P07/P09/P10 hard gates |
| P16 | AI observability gateway placeholder | 1 | 1 | DONE | AI engine intentionally deferred |

## Hard release gates

- [x] Product spec, architecture and harness execution contract exist.
- [x] Weighted progress ledger totals exactly 100 points and is machine-readable.
- [x] Guided profile initializer is read-only by construction and defaults to the 10G + 1G reference topology.
- [x] Guided profile compiles to deterministic `config-safe-subset-ir/1` without vendor commands or write transport.
- [x] `routerctl guided-start` produces a beginner-safe planning workspace without credentials, discovery transport, apply capability or production writer.
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
- [x] Management-safe VLAN generation passed CHR dry-run, runtime object validity, VLAN-filtering-last activation, OOB management survival and exact rollback-to-baseline verification.
- [x] RouterOS QoS global sibling Queue Tree rendering passed CHR 7.24.1 packet-flow acceptance for unmarked default traffic and DSCP46 priority traffic with exact owned rollback.
- [x] Disposable CHR transaction runtime admission binds the exact render plan, pre-state digest and repository-safe backup evidence before mutation, with no production writer, physical-router target or production write authorization.
- [x] Disposable CHR rollback recovery is independently verified from a fresh REST session and advances the lifecycle to `rolled_back`.
- [x] Disposable CHR successful post-apply state is independently re-read from a fresh REST session and matches the observed apply state digest.
- [x] Disposable CHR admitted apply preserves an independent management REST session before, during and after mutation.
- [x] PBR route-selection data-plane behavior is independently proven for the accepted v1 PBR scope.
- [x] WireGuard peer-to-peer handshake and encrypted packet transfer are independently proven for the accepted v1 VPN scope.
- [x] In-band VLAN20 tagged-to-access forwarding and the untagged ingress-filter negative control are independently proven on disposable CHR.
- [ ] Full CHR acceptance uses a dedicated least-privilege REST reader.
- [ ] Full CHR acceptance uses HTTPS with certificate verification.
- [ ] Full CHR evidence passes explicit provenance attestation/candidate review.
- [ ] Populated NAT/QoS objects are reviewed on live CHR or covered by an explicit accepted capability-gap policy.
- [ ] RouterOS renderer has accepted coverage for every planned v1 operation.
- [ ] Production apply requires real backup evidence.
- [ ] Default-route/firewall/management changes require verified management reachability in the production transaction path.
- [ ] Post-apply verification covers WAN, DNS, routing, VPN and management reachability as applicable.
- [ ] Failed production verification produces rollback and recovery-verification evidence.
- [x] Internet-down-with-link-up simulation passes while Ethernet/carrier remains UP, with WAN10 recursive-route failure, complete WAN1 failover and WAN10 recovery/failback.
- [ ] DNS failure simulation passes in addition to the accepted WAN failure/recovery gates.
- [ ] Route-loss simulation passes in addition to the accepted WAN failure/recovery gates.
- [x] Disposable CHR integration/failure simulation gates pass for the currently implemented safe-subset slices before physical CCR2116 testing.
- [ ] Physical CCR2116 acceptance evidence is recorded before production writer is enabled.
- [ ] CI is green on the exact release commit.

## Progress reporting contract

Every development handoff reports exact SHA, completed %, remaining %, point delta, checklist changes, test/CI evidence and the next highest-value gate.
