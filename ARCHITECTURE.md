# Architecture

## Product definition

Router Configuration is a vendor-neutral network configuration control system. The core expresses intent, calculates a safe change plan, and verifies outcomes. Vendor adapters translate approved operations into vendor-specific actions.

The core must never require vendor command syntax to make a policy decision.

## Architectural objective

A user who understands basic router/network concepts should be able to produce an expert-grade deployment because safety and workflow knowledge are encoded in the system rather than left to operator memory.

## Top-level architecture

```text
                     Operator / Future UI
                            |
                            v
                 Guided Deployment Harness
                            |
             +--------------+---------------+
             |                              |
             v                              v
       Intent / State                  Evidence Bus
             |                              |
             v                              +------> Observability Gateway
       Plan / Validate                                |
             |                                        +--> future internal AI
             v                                             advisory only
        Safety Gate
             |
             v
     Adapter-neutral operations
             |
       +-----+------+----------------+
       |            |                |
       v            v                v
   MikroTik       Yamaha           Omada
   Adapter         Adapter          Adapter
       |            |                |
       +------------+----------------+
                    |
                 Routers
```

The future AI/observability path is parallel to the execution path. It cannot call a device writer directly.

## Design principles

1. **Intent before commands** — users describe desired behavior, not vendor syntax.
2. **Read before write** — current facts/state are mandatory before planning.
3. **Harness-owned ordering** — adapters execute; they do not decide safety order.
4. **Plan before apply** — every mutation belongs to an immutable plan.
5. **Safety before convenience** — backup, management reachability, validation and rollback are execution requirements.
6. **Idempotent reconciliation** — already-satisfied intent produces no mutation.
7. **Vendor isolation** — vendor syntax stays behind adapter boundaries.
8. **Observable execution** — every gate and operation produces machine-readable evidence.
9. **Secrets by reference** — secret values do not belong in Git-backed intent.
10. **Official interfaces first** — undocumented interfaces are research-only and disabled by default.
11. **No hidden remediation** — no unplanned configuration changes.
12. **AI advisory boundary** — AI recommendations must re-enter the normal planning and safety flow.

## Layer model

### Experience layer

Responsibilities:
- guided questionnaire;
- deployment profile;
- human-readable explanation;
- review/approval surface.

### Deployment harness

Responsibilities:
- deterministic stage machine;
- evidence requirements;
- guided success/failure criteria;
- write-disabled-by-default policy;
- rollback routing.

Implementation foundation: `src/router_configuration/harness.py`.

### Control plane

- M01 Intent & Device Engine
- M02 State / Diff / Drift Engine
- M03 Configuration Compiler & Secrets
- M09 Safe Automation Gate

### Network intelligence

- M04 Multi-WAN & Load Balancing
- M05 Resilience & WAN Health
- M06 Security Operations
- M07 Segmentation / PBR / VPN / QoS

### Device adapters

- MikroTik adapter — reference implementation target;
- M08 Yamaha adapter;
- M10 Omada adapter;
- QNAP adapter — future/capability-limited.

### Evidence and observability

All stages should emit normalized evidence. Future collectors may add counters, state changes and redacted logs.

### Future AI gateway

`src/router_configuration/ai_gateway.py` defines an advisory-only boundary. It accepts redacted normalized telemetry and recommendations but exposes no device apply method.

## Ten capability modules

### M01 — Intent & Device Engine
- device inventory and normalized facts;
- capability discovery;
- normalized interface/platform model;
- transport-independent identity.

### M02 — State / Diff / Drift Engine
- normalize desired and actual state;
- semantic diff;
- drift detection;
- ordered immutable plan.

### M03 — Configuration Compiler & Secrets
- validate intent schemas;
- resolve secret references only at execution time;
- compile intent into adapter-neutral operations;
- reject forbidden plaintext secrets.

### M04 — Multi-WAN & Load Balancing
- model WAN capacity/preference;
- derive weighted flow policy;
- pin traffic/policy routes;
- never treat aggregate capacity as single-flow throughput.

Reference: WAN1 10 Gbps + WAN2 1 Gbps.

### M05 — Resilience & WAN Health
- multi-signal probes;
- health scoring;
- hysteresis;
- failover/failback decisions;
- distinguish physical link from end-to-end health.

### M06 — Security Operations
- baseline deny/allow;
- management-plane restrictions;
- anti-spoofing/bogon policy;
- threat-list lifecycle model;
- logging/audit requirements;
- backup/update security policy.

This is not an antivirus/EDR/NGFW signature engine.

### M07 — Segmentation / PBR / VPN / QoS
- VLAN/zone intent;
- inter-zone policy;
- policy-based routing;
- VPN path intent;
- traffic classes/QoS.

### M08 — Yamaha Adapter
- map normalized operations to supported RTX interfaces;
- read running state;
- render/apply bounded supported changes;
- verify and save only after validation;
- preserve rollback.

### M09 — Safe Automation Gate
- risk classification;
- read/plan/change permissions;
- dry-run;
- impact analysis;
- approval requirements;
- preflight;
- verification/rollback decision.

Risk levels:
- L0 read only;
- L1 plan only;
- L2 bounded change;
- L3 network-path/security change;
- L4 critical management/default-route/destructive change.

### M10 — Omada Adapter & API Compatibility
- official Open API integration;
- controller-version capability map;
- explicit official/experimental separation;
- compatibility tests.

Undocumented APIs are never enabled in production by default.

## Execution state machine

```text
CREATED
  -> DISCOVER
  -> INSPECT
  -> PLAN
  -> VALIDATE
  -> BACKUP
  -> PREFLIGHT
  -> APPROVAL
  -> APPLY
  -> VERIFY
  -> SAVE
  -> COMPLETE
```

Any failed verification after a possible mutation routes to `ROLLBACK` until recovery evidence succeeds.

See `HARNESS.md` and `WORKFLOW.md` for the detailed operating contract.

## Data/control separation

```text
Intent data        Secret references       Runtime facts
     \                   |                     /
      +------------------+--------------------+
                         |
                     Compiler
                         |
                normalized operations
                         |
                    Safety/Harness
                         |
                       Adapter
```

The intent repository never needs device passwords/private keys.

## Future AI data flow

```text
Read-only state/counters/logs
             |
       normalize/redact
             |
       AI Gateway contract
             |
     internal AI analysis
             |
 recommendation/proposed intent
             |
       normal PLAN workflow
```

No AI component is a configuration actuator.

## Reference acceptance target: v0.1

Target: MikroTik CCR2116-12G-4S+.

Required:
- WAN1 10 Gbps;
- WAN2 1 Gbps;
- 10 Gbps core uplink;
- weighted Dual-WAN;
- automatic failover/failback;
- static/PBR routing;
- VLAN segmentation;
- firewall baseline;
- WireGuard intent;
- QoS intent;
- management isolation;
- backup, dry-run, diff, verify, rollback;
- harness evidence for every gate.

No module is production-ready until unit tests, adapter tests and target-firmware integration evidence are recorded.
