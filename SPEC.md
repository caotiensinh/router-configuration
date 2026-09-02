# Product Specification

## Product goal

Router Configuration must let an operator with basic router/network knowledge deploy a professional, reviewable and recoverable configuration without needing to memorize vendor CLI syntax.

The product does not replace networking fundamentals. It converts a small, structured set of operator inputs into a safe workflow with expert-grade guardrails.

## Primary user

The primary user can understand:
- WAN versus LAN;
- IPv4 subnet and gateway;
- VLAN purpose;
- basic firewall allow/deny concepts;
- VPN purpose;
- which physical port connects to each ISP and the core switch.

The primary user is not expected to understand:
- vendor-specific CLI syntax;
- policy-routing implementation details;
- PCC/ECMP internals;
- firewall rule ordering;
- rollback mechanics;
- API payloads.

## Reference deployment

Initial reference target:
- MikroTik CCR2116-12G-4S+;
- RouterOS v7 family, exact tested release recorded by evidence;
- WAN1: 10 Gbps;
- WAN2: 1 Gbps;
- Core LAN: 10 Gbps;
- weighted multi-WAN policy;
- automatic failover/failback;
- VLAN segmentation;
- firewall baseline;
- policy routing;
- WireGuard intent;
- QoS intent.

## Operator contract

The operator supplies intent and environment facts. The harness owns execution ordering.

Minimum operator inputs:
1. device identity and management address;
2. vendor/model or discovery permission;
3. physical port mapping;
4. WAN addressing mode and ISP-specific values;
5. LAN/VLAN subnets;
6. traffic-policy intent;
7. VPN intent when required;
8. maintenance window and environment classification;
9. explicit authorization before writes.

The system must not silently invent unknown ISP parameters, gateway addresses, credentials, VLAN IDs or security exceptions.

## Mandatory safety invariants

1. **Read before write.** No plan is valid without current-state inspection.
2. **No hidden mutation.** Only operations present in the approved plan may be executed.
3. **Writes disabled by default.** A deployment spec must explicitly enable writes.
4. **Production backup is mandatory.** Production changes cannot enter preflight without a successful recovery artifact.
5. **Management path must be proven.** Network-path/security changes require a verified management path before apply.
6. **Capability validation is mandatory.** Unsupported vendor/device/firmware operations are blocked before apply.
7. **Baseline before change.** Connectivity/service checks are captured before apply and reused during verification.
8. **Verify before persist.** Configuration is persisted only after post-change verification succeeds.
9. **Failed post-change verification enters rollback handling.** It cannot be dismissed as a warning.
10. **Secrets are references.** Plaintext credentials, private keys and tokens are not accepted in Git-backed intent.
11. **Evidence is machine-readable.** Every gate produces a structured result that can be audited later.
12. **AI has no direct actuator path.** Future AI analysis may create recommendations or change proposals only; execution still passes through the same plan and safety harness.

## Deployment stages

`CREATED -> DISCOVER -> INSPECT -> PLAN -> VALIDATE -> BACKUP -> PREFLIGHT -> APPROVAL -> APPLY -> VERIFY -> SAVE -> COMPLETE`

Failure after a possible mutation routes to `ROLLBACK` until recovery evidence succeeds.

## Required evidence by stage

| Entering stage | Required evidence |
| --- | --- |
| INSPECT | device facts |
| PLAN | normalized actual state |
| VALIDATE | immutable change plan |
| BACKUP | successful plan validation |
| PREFLIGHT | production backup |
| APPROVAL | capability check + management path + connectivity baseline |
| APPLY | approval for the exact plan |
| VERIFY | apply result |
| SAVE | successful verification |
| COMPLETE | successful save/persist result |
| COMPLETE after rollback | successful rollback result |

## Expert behavior encoded in the product

The system should automatically perform the checks an experienced network engineer normally remembers to do:
- identify device/firmware and supported features;
- snapshot the current state;
- calculate semantic diff;
- identify risky default-route, firewall and management changes;
- verify recovery path;
- preserve a pre-change backup;
- verify both WAN paths independently;
- distinguish link-up from Internet health;
- confirm DNS and service reachability;
- validate VPN and policy-routing intent;
- compare post-change behavior with the pre-change baseline;
- persist only a verified configuration;
- retain evidence for incident review.

## Scope for current phase

Current phase focuses on deterministic configuration and automation.

In scope:
- intent;
- discovery/read-only state;
- planning/diff;
- validation;
- backup/preflight;
- vendor rendering;
- bounded apply;
- verification;
- rollback;
- execution evidence.

Deferred:
- AI diagnosis;
- autonomous optimization;
- packet-capture analysis;
- traffic forecasting;
- predictive maintenance;
- automated upgrade recommendations.

Only a stable AI/observability gateway contract is reserved now so future AI can be connected without bypassing the configuration safety model.

## Definition of done for v0.1

v0.1 is not production-ready until all of the following are recorded for a tested RouterOS version:
- read-only discovery integration tests;
- deterministic normalized state;
- golden plan/render tests created from this specification;
- backup and restore test;
- management-path preflight test;
- 10G:1G multi-WAN plan test;
- WAN failure/failback simulations;
- firewall and PBR verification tests;
- WireGuard verification test when enabled;
- apply/verify/rollback lab test against CHR;
- physical CCR2116 acceptance evidence;
- no plaintext secrets in test artifacts or logs.
