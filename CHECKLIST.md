# Master Completion Checklist

`PROJECT_PROGRESS.json` is the machine-readable source of truth. This document is its human-readable release checklist.

## Measurement rule

- v1 configuration automation is fixed at **100 weighted points**.
- Points are earned only when repository evidence and the stated acceptance gate exist.
- Documentation alone cannot complete a device-integration item.
- Future AI analytics is excluded; only its safe gateway placeholder is counted.

## Current measured status

**50% complete / 50% remaining.**

Change from previous checkpoint: **+1 point** from the completed CI/regression/golden evidence workstream. The new integration test exercises the real RouterOS REST HTTP client against a local synthetic REST server, checks GET-only endpoint behavior, Basic Auth, golden normalized state, secret redaction and evidence verification. No points were granted for live CHR, renderer, apply, verify or rollback because those gates remain unmet.

| ID | Workstream | Weight | Earned | Status | Next acceptance gate |
| --- | --- | ---: | ---: | --- | --- |
| P01 | Spec / architecture / harness | 8 | 8 | DONE | — |
| P02 | Clean-room / security policy | 4 | 4 | DONE | — |
| P03 | Guided deployment profile | 6 | 6 | DONE | — |
| P04 | Operator workflow CLI | 2 | 2 | DONE | — |
| P05 | Intent/state/diff/drift core | 8 | 7 | PARTIAL | vendor-neutral normalized-state schema versioning |
| P06 | Compiler / secret boundary | 4 | 2 | PARTIAL | compile full RouterOS safe subset |
| P07 | RouterOS read-only discovery | 12 | 6 | PARTIAL | live read-only evidence on tested RouterOS v7 CHR |
| P08 | RouterOS normalization | 6 | 4 | PARTIAL | live CHR state/evidence integrity + capability coverage |
| P09 | RouterOS renderer | 13 | 0 | NOT STARTED | deterministic safe-subset rendering after CHR discovery acceptance |
| P10 | Backup/preflight/apply/verify/rollback | 15 | 5 | PARTIAL | real adapter transaction lifecycle after CHR discovery acceptance |
| P11 | Dual-WAN / failover | 5 | 2 | PARTIAL | RouterOS compile + lab failover evidence |
| P12 | Security/VLAN/PBR/VPN/QoS | 8 | 1 | PARTIAL | RouterOS compiled policy + integration tests |
| P13 | CHR integration/failure lab | 5 | 0 | NOT STARTED | repeatable CHR test topology with rollback evidence |
| P14 | CI/regression/golden evidence | 2 | 2 | DONE | — |
| P15 | v1 release/beginner deployment docs | 1 | 0 | NOT STARTED | one-command guided deployment docs |
| P16 | AI observability gateway placeholder | 1 | 1 | DONE | AI engine intentionally deferred |

## Hard release gates

- [x] Product spec, architecture and harness execution contract exist.
- [x] Weighted progress ledger totals exactly 100 points and is machine-readable.
- [x] Guided profile initializer is read-only by construction and defaults to the 10G + 1G reference topology.
- [x] RouterOS discovery transport has an explicit read-only endpoint allowlist.
- [x] RouterOS live-safe discovery CLI exists without a plaintext password CLI argument.
- [x] Production discovery defaults to HTTPS with TLS verification; insecure modes require explicit lab mode.
- [x] Discovery normalized state redacts private-key/PSK/password/token-like fields.
- [x] Discovery evidence has a second secret boundary, stable state digest and sanitized error codes.
- [x] RouterOS state/evidence verifier detects state, count, platform and capability-summary tampering before preflight.
- [x] Synthetic CI, CHR live and physical CCR2116 evidence classes are explicitly separated.
- [x] Profile-to-evidence preflight blocks model/port/requested-feature mismatches and supplies remediation text.
- [x] Synthetic REST transport integration matches the golden normalized state in CI.
- [ ] RouterOS live target firmware/version evidence is recorded from CHR.
- [ ] Live read-only discovery covers interfaces, addresses, routes, routing tables, firewall/NAT, WireGuard and QoS state on CHR.
- [ ] Desired-state diff is deterministic and idempotent against live normalized state.
- [ ] RouterOS renderer has golden tests for every supported operation.
- [ ] Production apply requires real backup evidence.
- [ ] Default-route/firewall/management changes require verified management reachability.
- [ ] Post-apply verification covers WAN, DNS, routing, VPN and management reachability as applicable.
- [ ] Failed verification produces rollback and recovery-verification evidence.
- [ ] Weighted 10G + 1G Dual-WAN behavior is tested in lab.
- [ ] ISP-down, Internet-down-with-link-up, DNS failure and route-loss simulations pass.
- [ ] CHR lab passes before physical CCR2116 testing.
- [ ] Physical CCR2116 acceptance evidence is recorded before production writer is enabled.
- [ ] CI is green on the exact release commit.

## Progress reporting contract

Every development handoff reports exact SHA, completed %, remaining %, point delta, checklist changes, test/CI evidence and the next highest-value gate.
