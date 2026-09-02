# Architecture

## Product definition

Router Configuration is a vendor-neutral network configuration control system. The core expresses intent, calculates a safe change plan, and verifies outcomes. Vendor adapters translate the approved plan into vendor-specific operations.

The core must never require vendor command syntax to make a policy decision.

## Design principles

1. **Intent before commands** — users describe desired network behavior rather than a sequence of CLI commands.
2. **Read before write** — collect facts and current state before producing a plan.
3. **Plan before apply** — every mutation is represented as an immutable change plan.
4. **Safety before convenience** — management reachability, backup, validation, and rollback are part of the execution contract.
5. **Idempotent reconciliation** — applying an already-satisfied intent must produce no change.
6. **Vendor isolation** — vendor-specific syntax stays behind an adapter boundary.
7. **Observable execution** — every operation produces machine-readable evidence.
8. **Secrets by reference** — secret values do not belong in Git-backed intent files.
9. **Official interfaces first** — supported APIs/CLIs are preferred; undocumented interfaces are research-only and disabled by default.
10. **No hidden remediation** — the system may not perform unplanned changes outside the approved plan.

## Ten capability modules

### M01 — Intent & Device Engine

Responsibilities:
- device inventory and normalized facts;
- capability discovery;
- normalized interface and platform model;
- transport-independent device identity.

Input: inventory + discovered facts.
Output: `NormalizedDevice` and `DeviceCapabilities`.

### M02 — State / Diff / Drift Engine

Responsibilities:
- normalize desired and actual state;
- calculate semantic diff;
- identify drift;
- create an ordered immutable plan.

Input: desired state + actual state.
Output: `ChangePlan`.

### M03 — Configuration Compiler & Secrets

Responsibilities:
- validate intent schemas;
- resolve secret references at execution time;
- compile normalized intent into adapter-neutral operations;
- reject embedded plaintext secrets where policy forbids them.

### M04 — Multi-WAN & Load Balancing

Responsibilities:
- model WAN capacity and preference;
- derive weighted flow-distribution policy;
- support pinning and policy routing;
- avoid assuming that aggregate WAN capacity equals single-flow throughput.

Reference case: WAN1 10 Gbps + WAN2 1 Gbps.

### M05 — Resilience & WAN Health

Responsibilities:
- multi-signal health probes;
- health scoring;
- failure/recovery hysteresis;
- failover and failback decisions;
- distinguish physical link state from end-to-end Internet health.

### M06 — Security Operations

Responsibilities:
- baseline deny/allow policy;
- management-plane restrictions;
- anti-spoofing and bogon policy;
- threat-list lifecycle model;
- audit/logging requirements;
- backup/update security policy.

This module is not an antivirus/EDR/NGFW signature engine.

### M07 — Segmentation / PBR / VPN / QoS

Responsibilities:
- zone/VLAN intent;
- inter-zone access policy;
- policy-based routing intent;
- VPN path intent;
- traffic classes and QoS policy.

### M08 — Yamaha Adapter

Responsibilities:
- map normalized operations to supported Yamaha RTX interfaces;
- retrieve running configuration;
- render/apply supported changes;
- verify and save only after successful validation;
- preserve rollback capability.

### M09 — Safe Automation Gate

Responsibilities:
- risk classification;
- read-only / plan-only / change permissions;
- dry-run;
- impact analysis;
- approval requirements;
- preflight checks;
- post-change verification and rollback decision.

Risk levels:
- L0: read only;
- L1: plan only;
- L2: low-risk bounded change;
- L3: network-path/security change;
- L4: critical management/default-route/destructive change.

### M10 — Omada Adapter & API Compatibility

Responsibilities:
- official Open API integration;
- controller-version capability map;
- explicit separation of official and experimental surfaces;
- compatibility testing.

Undocumented APIs are never enabled in production mode by default.

## Layer model

```text
CONTROL PLANE
  M01 Intent & Device
  M02 State / Diff / Drift
  M03 Compiler & Secrets
  M09 Safety Gate

NETWORK INTELLIGENCE
  M04 Multi-WAN
  M05 Resilience
  M06 Security
  M07 Traffic Policy

DEVICE ADAPTERS
  MikroTik adapter (reference implementation)
  M08 Yamaha adapter
  M10 Omada adapter
  QNAP adapter (future, capability-limited)
```

## Execution state machine

```text
DISCOVER
  -> INSPECT
  -> PLAN
  -> VALIDATE
  -> BACKUP
  -> PREFLIGHT
  -> APPLY
  -> VERIFY
  -> SAVE
```

Any failure after `APPLY` transitions to `ROLLBACK_REQUIRED` unless the adapter can prove that no mutation occurred.

## Reference acceptance target: v0.1

Target platform: MikroTik CCR2116-12G-4S+.

Required capabilities:
- WAN1 10 Gbps;
- WAN2 1 Gbps;
- 10 Gbps core uplink;
- weighted Dual-WAN policy;
- automatic failover/failback;
- static and policy routing;
- VLAN segmentation;
- firewall baseline;
- WireGuard intent;
- QoS intent;
- management isolation;
- backup, dry-run, diff, verify, rollback.

No module is production-ready until unit tests, adapter tests, and a target-firmware integration test are recorded.