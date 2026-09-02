# Router Configuration

Router Configuration is a clean-room, vendor-neutral network configuration control system.

Its goal is to let an operator with basic router/network knowledge deploy a professional configuration through guided intent, deterministic planning, safety gates, verification and rollback instead of memorizing vendor CLI syntax.

## Current focus

Configuration and automation first.

Reference platform:
- MikroTik CCR2116-12G-4S+;
- WAN1 10 Gbps;
- WAN2 1 Gbps;
- Core uplink 10 Gbps.

Target capabilities:
- weighted Dual-WAN load distribution;
- automatic failover/failback;
- static and policy routing;
- VLAN/zone segmentation;
- firewall and management-plane hardening;
- WireGuard/IPsec intent where supported;
- QoS/traffic classes;
- desired-state diff/drift;
- backup, preflight, verify and rollback.

## Deployment harness

All writes must eventually follow:

`DISCOVER -> INSPECT -> PLAN -> VALIDATE -> BACKUP -> PREFLIGHT -> APPROVAL -> APPLY -> VERIFY -> SAVE`

Failed verification after a possible mutation enters `ROLLBACK` handling.

Writes remain disabled by default in deployment profiles.

See:
- `SPEC.md` — product requirements and safety invariants;
- `HARNESS.md` — deployment harness contract;
- `WORKFLOW.md` — detailed operator/execution workflow;
- `ARCHITECTURE.md` — module/layer architecture;
- `AI_GATEWAY.md` — reserved advisory-only future AI boundary;
- `THIRD_PARTY_RESEARCH.md` — clean-room research policy.

## Safe commands available now

Install the package in a development environment and use `routerctl`.

Validate the reference deployment profile without changing a router:

```bash
routerctl profile-check --profile examples/rd-10g-1g/deployment-profile.json
```

Inspect guided behavior for a stage:

```bash
routerctl workflow --stage preflight
```

Derive WAN weights:

```bash
routerctl multiwan --wan wan10g=10000 --wan wan1g=1000
```

Compare desired and actual JSON state:

```bash
routerctl plan --desired desired.json --actual actual.json
```

No production router writer is enabled yet.

## Ten capability modules

1. M01 Intent & Device Engine
2. M02 State / Diff / Drift Engine
3. M03 Configuration Compiler & Secrets
4. M04 Multi-WAN & Load Balancing
5. M05 Resilience & WAN Health
6. M06 Security Operations
7. M07 Segmentation / PBR / VPN / QoS
8. M08 Yamaha Adapter
9. M09 Safe Automation Gate
10. M10 Omada Adapter & API Compatibility

MikroTik is the first adapter to be completed as a production reference.

## Future internal AI

Only a gateway contract is reserved now. Future internal AI may analyze counters, flows, packet metadata, logs, WAN health and configuration evidence and may produce maintenance/capacity/security recommendations.

AI has no direct router-write path. Any proposed intent must re-enter normal planning, validation, safety and approval.

## Project status

Foundation/harness phase. Do not use this repository to mutate a production router until the RouterOS reference adapter passes lab apply/verify/rollback testing and physical CCR2116 acceptance evidence is recorded.
