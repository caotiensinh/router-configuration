# Network Sandbox Runtime — Hardware-Free Acceptance Mode

Status: **active engineering policy while physical network hardware is unavailable**.

This document defines how `caotiensinh/Network_Sandbox_Runtime` is used by
`caotiensinh/router-configuration` during the current hardware-free phase.

It does not weaken `MASTER_RULES.md`, vendor-specific rules, production
authorization requirements, or physical-device acceptance requirements.

## Purpose

The current project stage has no guaranteed access to the target physical
routers, switches, controllers, or access points. Engineering work must still
produce durable behavioral evidence instead of stopping at unit tests.

`Network_Sandbox_Runtime` is therefore the preferred virtual acceptance
backend for network behavior that can be represented without proprietary
physical hardware.

The bridge is cross-repository and exact-SHA bound.

## Evidence ceiling

The project uses the evidence classes defined in
`src/router_configuration/device_backend.py`.

| Network Sandbox fidelity | Router Configuration ceiling | Meaning |
| --- | --- | --- |
| L0 | not accepted by this contract | schema/representation only |
| L1 | `VIRTUAL_VERIFIED` | deterministic logical behavior |
| L2 | `VIRTUAL_VERIFIED` | packet/event/timer/convergence behavior |
| L3 | `PROTOCOL_VERIFIED` | isolated Linux/FRR/real-packet protocol behavior |
| L4 | separate vendor-golden gate | licensed vendor virtual/real reference required |

No sandbox result may set:

- `hardware_verified=true`;
- `physical_device_verified=true`;
- `production_write_authorized=true`;
- `production_writer_available=true`.

Physical-hardware acceptance remains an external dependency and is deferred, not
silently converted to PASS.

## Required provenance

Every promoted sandbox acceptance record must bind at least:

- exact `router-configuration` source SHA;
- exact `Network_Sandbox_Runtime` source SHA;
- Network Sandbox release/version label;
- fidelity level;
- scenario identifier;
- SHA-256 digest of the scenario;
- SHA-256 digest of the result/evidence bundle;
- tested logic/capabilities;
- durable evidence references;
- the exact claims the evidence is allowed to support.

The cross-repository record is itself SHA-256 bound.

Implementation:
`src/router_configuration/network_sandbox_acceptance.py`.

## Current Network Sandbox baseline

At the time this integration was introduced:

- repository: `caotiensinh/Network_Sandbox_Runtime`;
- validated frozen baseline: Packet-Tracer-Class Headless Parity v6;
- release: `0.6.0`;
- frozen v6 SHA: `f17c508d18ebdf11c372c4d9a819790aeb213fef`;
- active main inspected for this integration:
  `a9658656efa3b20ae233b1be92d99fda70de4fcc`.

The active sandbox revision must always be recorded in evidence; this document
does not authorize treating a moving `main` reference as reproducible proof.

## Vendor use during the hardware-free phase

### MikroTik RouterOS

Use Network Sandbox for:

- cross-feature behavioral regression;
- dual-WAN and routing-policy logic;
- VLAN/firewall/NAT/VPN/QoS interaction scenarios where the simulator has
  verified coverage;
- fault injection, convergence, replay, fuzzing, and scale tests;
- protocol/open-backend differential tests.

Official RouterOS CHR evidence remains stronger for RouterOS-specific runtime
behavior and should continue to be retained. Network Sandbox does not replace
CHR version-specific RouterOS evidence.

Physical CCR2116 acceptance remains deferred.

### Cisco IOS XE

Use Network Sandbox for:

- router and switch forwarding logic;
- IPv4 routing behavior;
- access/trunk VLAN semantics;
- STP/LACP/routing protocol behavior within verified simulator scope;
- packet-path assertions;
- failure/recovery logic;
- cross-protocol and cross-feature regression.

Existing Cisco integration:
`src/router_configuration/vendors/cisco/network_sandbox_adapter.py`.

Simulation must not be fed into the live IOS XE YANG normalizers as if it came
from a device. NETCONF/RESTCONF/YANG capability admission still requires an
appropriate live or licensed vendor runtime.

Physical Cisco acceptance remains deferred.

### Yamaha RTX3510

Use Network Sandbox for:

- planner and dependency behavior;
- routing outcome validation where standards-based behavior is sufficient;
- failure/recovery scenarios;
- packet/protocol verification independent of Yamaha CLI implementation.

Do not use generic sandbox behavior to claim exact RTX3510 CLI, firmware,
default, management-plane, or hardware behavior. Those remain vendor/live gates.

### TP-Link Omada

Use Network Sandbox together with the existing virtual contracts for:

- `VirtualSwitch`;
- `VirtualGateway`;
- `VirtualAP`;
- `VirtualBridge`;
- VLAN/routing/firewall/forwarding behavior;
- topology and failure propagation;
- packet/protocol evidence;
- rollback/recovery logic.

Controller/API/device-specific behavior remains bound to verified Omada
knowledge and controller evidence.

## Current-stage definition of done

A hardware-free engineering task may be marked complete when all testable
engineering gates pass with appropriate evidence, even when a hardware-only gate
is unavailable.

The correct terminal state is:

```text
ENGINEERING_COMPLETE
VIRTUAL_OR_PROTOCOL_ACCEPTANCE_COMPLETE
HARDWARE_ACCEPTANCE_DEFERRED
PRODUCTION_WRITE_AUTHORIZED = false
```

It is incorrect to use:

```text
HARDWARE_VERIFIED
PRODUCTION_READY
```

solely because simulation succeeded.

## Recommended acceptance flow

```text
AUTHORITATIVE VENDOR KNOWLEDGE
        ↓
INTENT / DESIRED STATE
        ↓
DETERMINISTIC PLAN / RENDER
        ↓
NETWORK SANDBOX L1/L2
        ↓
PACKET / FAILURE / RECOVERY EVIDENCE
        ↓
NETWORK SANDBOX L3 WHERE APPLICABLE
        ↓
PROTOCOL_VERIFIED
        ↓
OPTIONAL LICENSED VENDOR VIRTUAL L4
        ↓
HARDWARE ACCEPTANCE — DEFERRED UNTIL AVAILABLE
```

Simulation success remains evidence, not production authorization.
