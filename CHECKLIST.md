# Master Completion Checklist

This checklist is the human-readable companion to `PROJECT_PROGRESS.json`, which is the machine-readable source of truth.

## Measurement rule

- The v1 configuration-automation scope is fixed at **100 weighted points**.
- A point is earned only when repository evidence exists and the acceptance gate for that item has been met.
- Documentation alone does not complete a device-integration item.
- AI analytics/agent implementation is **not part of v1**. Only the safe observability gateway placeholder is counted.
- Completion = sum of `completed_points`; Remaining = `100 - completion`.

## Current measured status

**36% complete / 64% remaining.**

| ID | Workstream | Weight | Earned | Status | Next acceptance gate |
| --- | --- | ---: | ---: | --- | --- |
| P01 | Spec / architecture / harness | 8 | 8 | DONE | — |
| P02 | Clean-room / security policy | 4 | 4 | DONE | — |
| P03 | Guided deployment profile | 6 | 4 | PARTIAL | interactive builder + remediation guidance |
| P04 | Operator workflow CLI | 2 | 2 | DONE | — |
| P05 | Intent/state/diff/drift core | 8 | 7 | PARTIAL | normalized-state schema versioning |
| P06 | Compiler / secret boundary | 4 | 2 | PARTIAL | compile full RouterOS safe subset |
| P07 | RouterOS read-only discovery | 12 | 0 | NOT STARTED | collect approved state surfaces read-only |
| P08 | RouterOS normalization | 6 | 0 | NOT STARTED | fixture-backed normalized state + redaction |
| P09 | RouterOS renderer | 13 | 0 | NOT STARTED | deterministic safe-subset rendering |
| P10 | Backup/preflight/apply/verify/rollback | 15 | 4 | PARTIAL | real adapter transaction lifecycle |
| P11 | Dual-WAN / failover | 5 | 2 | PARTIAL | RouterOS compile + lab failover evidence |
| P12 | Security/VLAN/PBR/VPN/QoS | 8 | 1 | PARTIAL | RouterOS compiled policy + integration tests |
| P13 | CHR integration/failure lab | 5 | 0 | NOT STARTED | repeatable rollback/failure evidence |
| P14 | CI/regression/golden evidence | 2 | 1 | PARTIAL | fixture/golden/integration matrix |
| P15 | v1 release/beginner deployment docs | 1 | 0 | NOT STARTED | one-command guided deployment docs |
| P16 | AI observability gateway placeholder | 1 | 1 | DONE | AI engine intentionally deferred |

## Hard release gates

A v1 production-ready claim is forbidden until all of these are checked:

- [ ] RouterOS target firmware/version matrix is explicitly recorded.
- [ ] Read-only discovery covers interfaces, addresses, routes, routing tables, firewall/NAT, WireGuard and QoS state.
- [ ] Discovery output redacts all secret/private-key material.
- [ ] Desired-state diff is deterministic and idempotent.
- [ ] RouterOS renderer has golden tests for every supported operation.
- [ ] Production apply requires backup evidence.
- [ ] Default-route/firewall/management changes require management-path verification.
- [ ] Post-apply verification covers WAN, DNS, routing, VPN and management reachability as applicable.
- [ ] Failed verification produces rollback and recovery-verification evidence.
- [ ] Weighted 10G + 1G Dual-WAN behavior is tested in lab.
- [ ] ISP-down, Internet-down-with-link-up, DNS failure and route-loss simulations pass.
- [ ] CHR lab passes before physical CCR2116 testing.
- [ ] Physical CCR2116 acceptance evidence is recorded before production writer is enabled.
- [ ] Beginner guided flow provides remediation instructions for every blocking preflight failure.
- [ ] CI is green on the exact release commit.

## Progress reporting contract

Every development handoff should report:

1. exact Git commit SHA;
2. completed percentage;
3. remaining percentage;
4. points gained since the prior checkpoint;
5. checklist items changed;
6. tests/CI evidence;
7. next highest-value gate.
