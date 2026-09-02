# Configuration Workflow and Operating Logic

## Objective

The workflow must make expert network-change discipline available to an operator who only understands basic routing/network concepts.

The operator answers structured questions. The system performs ordering, validation, risk classification, backup, verification and rollback logic.

## Phase A — Describe the network

The guided workflow collects:
1. site name;
2. router management address;
3. vendor/model or permission to discover it;
4. physical port mapping;
5. each ISP connection type and capacity;
6. LAN/VLAN networks;
7. required inter-zone access;
8. VPN requirements;
9. traffic priorities/QoS intent;
10. environment: lab, staging or production.

The system must ask for missing facts instead of guessing them.

### Example reference answers

```text
Site: R&D
Router: CCR2116-12G-4S+
WAN1: sfp-sfpplus1, 10,000 Mbps
WAN2: ether1, 1,000 Mbps
Core: sfp-sfpplus2, 10,000 Mbps
LAN: 192.168.11.0/24
Multi-WAN: weighted + failover
VPN: WireGuard required
Operator mode: guided
Environment: production
```

## Phase B — Discover and understand current state

### DISCOVER

Read-only collection:
- model;
- firmware/RouterOS version;
- interfaces;
- capability map;
- management methods.

### INSPECT

Normalize:
- interface state;
- addresses;
- routes/routing tables;
- VLANs;
- NAT;
- firewall;
- VPN;
- QoS/queues;
- WAN state.

No mutation is allowed in either stage.

## Phase C — Plan professionally

### PLAN

Compute desired versus actual state.

The plan must answer:
- what will be created;
- what will be changed;
- what will be removed;
- which traffic path may change;
- maximum risk level;
- which vendor capabilities are required.

The plan is immutable for a given approval. If desired state changes, approval becomes stale and a new plan is required.

### VALIDATE

Validation layers:
1. schema validation;
2. device capability validation;
3. interface/port conflict validation;
4. address/subnet conflict validation;
5. route/PBR consistency validation;
6. firewall safety validation;
7. VPN validation;
8. QoS sanity validation;
9. secret/reference validation;
10. management-path risk validation.

## Phase D — Prepare safe execution

### BACKUP

Production requires a recoverable pre-change state.

Evidence should eventually include:
- backup type;
- device ID;
- firmware/version;
- artifact digest;
- timestamp;
- restore method validation status.

### PREFLIGHT

Preflight is the professional checklist the operator should not need to remember manually.

Required checks:
- target device identity matches intent;
- firmware capabilities match planned operations;
- management path is reachable;
- alternate/console recovery path is known when required;
- WAN1 baseline captured;
- WAN2 baseline captured;
- DNS baseline captured;
- default route baseline captured;
- VPN baseline captured when relevant;
- core/LAN reachability baseline captured;
- backup evidence exists in production.

### APPROVAL

Approval must be bound to the exact plan, not just the device name.

Future evidence should include a plan digest so an edited plan cannot reuse an old approval.

## Phase E — Apply in bounded steps

A change is executed in dependency order, not as a random command list.

Recommended high-level order:

```text
management safety
  -> interface prerequisites
  -> VLAN/LAN primitives
  -> WAN primitives
  -> routing tables/routes
  -> NAT
  -> firewall/security
  -> VPN
  -> QoS
  -> monitoring hooks
```

Actual operation order is calculated from dependencies and vendor behavior.

The executor must stop at the first unsafe failure.

## Phase F — Verify like an expert

Verification compares both **desired configuration** and **service behavior**.

Configuration checks:
- intended objects exist;
- unintended objects were not changed;
- route/table selection is correct;
- firewall order/state is correct;
- VPN configuration is present;
- QoS policy is attached as intended.

Service checks:
- management reachability;
- LAN gateway reachability;
- WAN1 Internet test;
- WAN2 Internet test;
- DNS test;
- default-route test;
- policy-routing test;
- failover test when maintenance policy allows;
- VPN handshake/path test when enabled;
- critical service reachability.

## Phase G — Persist or rollback

### PASS

Only after verification:
- save/persist configuration;
- reread state;
- record final evidence;
- mark run complete.

### FAIL

If apply may have changed device state:
- enter rollback;
- restore last known-good state;
- verify management path;
- verify baseline services;
- preserve failure evidence;
- do not silently continue with remaining operations.

## Failure decision matrix

| Failure point | Default action |
| --- | --- |
| Discover/inspect | Stop, no mutation |
| Plan/validate | Stop, fix intent |
| Backup | Block production change |
| Preflight | Block apply |
| Approval | Block apply |
| Apply before any mutation | Stop |
| Apply after possible mutation | Rollback handling |
| Verify | Rollback handling |
| Save | Keep run incomplete and require recovery/persistence check |

## Beginner mode versus expert mode

Modes alter presentation, not safety.

Guided mode:
- explains each field;
- provides safe examples;
- hides unnecessary vendor syntax;
- shows expected result and failure action;
- warns when an answer is unknown.

Expert mode may expose more normalized details and adapter diagnostics, but it does not bypass mandatory gates.

## AI later, configuration now

Current workflow ends at deterministic evidence collection.

The reserved AI gateway can consume that evidence later. It may recommend changes, but any proposed change must restart at PLAN and follow this same workflow.
