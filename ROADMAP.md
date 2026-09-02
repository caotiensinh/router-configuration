# Roadmap

## Delivery principle

Configuration and automation come first. AI analysis is deferred behind the reserved gateway contract.

No production writer is enabled until read-only discovery, deterministic rendering, preflight, verification and rollback have passed lab and physical-device acceptance gates.

## Phase 0 — Harness foundation

Status: **FOUNDATION COMPLETE**

Delivered:
- clean-room research policy;
- product specification;
- ten-module architecture;
- deterministic deployment harness;
- guided stage explanations;
- production backup gate;
- capability/management/connectivity preflight contract;
- rollback routing on failed post-change verification;
- guided deployment profile validator;
- 10G + 1G reference profile;
- CLI profile validation and workflow guidance;
- advisory-only future AI/observability gateway contract;
- CI across supported Python versions.

Still intentionally disabled:
- production router writes;
- direct AI device writes;
- raw packet payload in AI gateway.

## Phase 1 — RouterOS read-only discovery

Target: MikroTik CCR2116-12G-4S+ / tested RouterOS v7 release.

Deliverables:
1. exact supported RouterOS version/capability matrix;
2. read-only transport interface;
3. REST collector where officially supported;
4. SSH/CLI collector for required read-only gaps;
5. normalized device identity;
6. normalized interface/link state;
7. addresses/subnets;
8. routes and routing tables;
9. NAT/firewall state;
10. WireGuard state without secrets;
11. QoS/queue state;
12. WAN health inputs;
13. redacted discovery evidence;
14. fixture-driven tests from our own specification.

Exit gate:
- same router state produces stable normalized output;
- no write-capable command is used;
- no secret is emitted to logs/fixtures;
- CI PASS.

## Phase 2 — RouterOS plan and restricted renderer

Deliverables:
- adapter-neutral operation dependency graph;
- RouterOS renderer for a deliberately small safe subset;
- command golden tests written from official documentation and our own spec;
- idempotency tests;
- unsupported-operation blockers;
- plan digest binding for approval/evidence.

Initial safe subset:
- interface naming/metadata where non-destructive;
- VLAN primitives;
- addresses;
- routing tables/static routes;
- bounded NAT/firewall rules;
- WireGuard objects without plaintext key persistence;
- QoS primitives required by the reference policy.

No apply command yet.

## Phase 3 — Backup, preflight and verification engine

Deliverables:
- RouterOS export/backup contract;
- backup artifact validation;
- management-path probe;
- WAN1/WAN2 connectivity baseline;
- DNS baseline;
- route/PBR baseline;
- VPN baseline when enabled;
- post-change verifier;
- failure reason classification;
- structured execution evidence.

Exit gate:
- every reference change has explicit preflight and verification checks.

## Phase 4 — Lab apply/verify/rollback

Target: RouterOS CHR laboratory environment.

Deliverables:
- explicit write-enabled lab profile;
- plan-bound approval;
- bounded apply executor;
- stop-on-first-unsafe-failure behavior;
- automatic rollback handling after failed verification;
- recovery verification;
- failure simulations.

Required simulations:
- interface link up but Internet unavailable;
- WAN gateway reachable but DNS broken;
- default-route loss;
- policy-routing mistake;
- firewall change that risks management;
- WAN1 failure and WAN2 failover;
- failback with hysteresis;
- partial apply failure.

## Phase 5 — 10G + 1G production reference acceptance

Target: physical CCR2116-12G-4S+.

Reference topology:
- WAN1 10 Gbps;
- WAN2 1 Gbps;
- Core 10 Gbps;
- capacity weight 10:1;
- automatic failover/failback;
- VLAN/security/PBR/VPN/QoS reference intent.

Acceptance evidence:
- device/firmware identity;
- pre-change backup;
- exact plan digest;
- preflight PASS;
- apply evidence;
- WAN/path tests;
- security checks;
- VPN checks;
- QoS checks;
- failover/failback test;
- final state reread;
- rollback drill evidence;
- no secret leakage.

Only after this phase may MikroTik production write support be considered production-ready.

## Phase 6 — Guided operator experience

After the execution engine is proven:
- interactive profile wizard;
- safe topology questionnaire;
- vendor/model auto-discovery;
- plain-language risk explanation;
- pre-change checklist UI;
- deployment report;
- recovery instructions;
- reusable site templates.

The wizard may simplify presentation but may not remove safety gates.

## Phase 7 — Yamaha RTX3510

- read running configuration over supported interfaces;
- capability discovery;
- normalized state;
- bounded render/apply;
- backup/verify/save/rollback lifecycle;
- multi-homing/PBR coverage;
- guided profile mapping.

## Phase 8 — TP-Link Omada / ER8411

- official Open API authentication/version discovery;
- controller capability map;
- gateway read state;
- bounded writes only where officially exposed;
- official API only in production;
- experimental/undocumented surfaces remain disabled.

## Deferred AI/observability phase

The gateway contract exists now; the AI engine does not.

Future work may analyze:
- bandwidth trends;
- flows and packet metadata;
- interface errors/drops;
- WAN health history;
- route changes;
- QoS statistics;
- firewall events;
- VPN health;
- redacted logs;
- configuration drift;
- incident history.

Outputs remain advisory or proposed intent. Proposed intent must pass the same harness as human-authored intent.

## Non-goals for early releases

- no undocumented API writes in production;
- no Internet-exposed management by default;
- no autonomous destructive changes;
- no secret-bearing fixtures/logs;
- no claim that 10G + 1G makes a single TCP flow 11 Gbps;
- no public-repository script copied into implementation;
- no AI direct actuator path.
