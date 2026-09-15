# Vendor-Neutral Network Device Test Harness

## Purpose

The project must not rebuild a separate test system for every router, firewall, controller, or network appliance vendor.

This document defines one reusable test contract for MikroTik, Cisco, TP-Link/Omada, Yamaha, Fortinet/FortiGate, and future vendors while preserving strict vendor isolation in configuration generation and execution.

The shared harness owns only test orchestration, scenario classification, evidence strength, and acceptance accounting. Vendor-specific syntax, transports, credentials, commands, firmware behavior, and authoritative documentation remain inside vendor-specific adapters/domains.

## Architecture boundary

```text
Common test scenarios
        |
        v
Vendor-neutral Test Harness
        |
        +--> backend capability declaration
        +--> deterministic scenario eligibility
        +--> evidence-strength classification
        +--> deferred hardware-only accounting
        |
        v
Vendor Test Adapter
        |
        +--> VM / virtual appliance
        +--> software controller
        +--> simulator / behavior model
        +--> physical device
        |
        v
Vendor-specific implementation
```

The test harness MUST NOT become a cross-vendor configuration engine.

## Backend classes

A backend declares what kind of environment is actually under test:

- `behavior_model`: deterministic mock/replay/model used to test orchestration and contracts only;
- `simulator`: protocol or vendor-behavior simulator with no claim of running the vendor network OS;
- `software_controller`: vendor/controller software without a claim that forwarding hardware is present;
- `virtual_appliance`: vendor network OS or official/authorized virtual appliance supplied outside the repository;
- `physical_device`: real supported hardware.

The repository must never bundle proprietary vendor images, license keys, credentials, or restricted firmware.

## Evidence fidelity

Evidence is classified by the strongest environment that produced it:

1. `contract` — schemas, orchestration, deterministic planners, mocks and replay;
2. `behavior` — simulator/controller behavior without vendor-OS equivalence;
3. `vendor_os` — vendor operating system running in a virtual appliance;
4. `physical` — real hardware.

A lower-fidelity backend must never be promoted into a higher-fidelity claim.

Examples:

- a mock can prove the rollback state machine is deterministic;
- a vendor VM can prove software routing/firewall/failover behavior where supported;
- only real hardware can prove ASIC/offload, physical optics, PoE, port electrical behavior, thermal/power behavior, or hardware throughput.

## Current official backend candidates

The common harness is intentionally independent of product availability, but the following vendor-supplied environments are current practical candidates for higher-fidelity tests. Exact image/version/licensing eligibility must still be checked by the vendor-specific adapter before each run.

| Vendor family | Candidate backend | Harness classification | Safe default claim boundary |
| --- | --- | --- | --- |
| MikroTik | Cloud Hosted Router (CHR) | `virtual_appliance` / `vendor_os` | RouterOS software behavior; no RouterBOARD hardware certification |
| Cisco | Catalyst 8000V | `virtual_appliance` / `vendor_os` | IOS XE software behavior; no physical platform/ASIC certification |
| Yamaha | vRX | `virtual_appliance` / `vendor_os` | vRX software behavior; no Yamaha hardware-router certification |
| Fortinet | FortiGate-VM | `virtual_appliance` / `vendor_os` | FortiOS VM behavior; no FortiGate appliance hardware certification |
| TP-Link / Omada | Omada Software Controller | `software_controller` / `behavior` | Controller/API/management behavior only; it is not a gateway forwarding-plane VM |

Authoritative product references used for this classification:

- MikroTik CHR: `https://help.mikrotik.com/docs/spaces/ROS/pages/18350234/Cloud+Hosted+Router+CHR`
- Cisco Catalyst 8000V: `https://www.cisco.com/c/en/us/td/docs/routers/C8000V/Configuration/c8000v-installation-configuration-guide/cisco-catalyst-8000v-virtual-routers/introduction.html`
- Yamaha vRX: `https://network.yamaha.com/products/routers/vrx/spec`
- Fortinet FortiGate-VM: `https://www.fortinet.com/products/private-cloud-security/fortigate-virtual-appliances`
- TP-Link Omada Software Controller: `https://www.tp-link.com/jp/business-networking/management-platform/omada-software-controller/v4/`

These references identify candidate execution environments only. They do not grant permission to redistribute images, firmware, or licenses.

## Common scenario catalog

The reusable baseline catalog is:

- `read_only_discovery`
- `render_validate`
- `configuration_roundtrip`
- `backup_restore`
- `management_survival`
- `wan_failover`
- `dns_failure`
- `default_route_loss`
- `vpn_recovery`
- `rollback_recovery`
- `hardware_dataplane`
- `performance_capacity`

Vendor adapters may add vendor-specific scenarios, but they must not weaken the common acceptance semantics.

## Capability-driven planning

Every backend declares capabilities. The planner decides whether each requested scenario is:

- `run` — backend fidelity and capabilities satisfy the scenario contract;
- `deferred` — the scenario cannot be honestly proven in the current backend.

A deferred scenario is not a failure and is not a pass. It preserves the missing acceptance boundary explicitly.

Typical capability labels include:

- `discovery`
- `render_validate`
- `config_roundtrip`
- `config_backup`
- `config_restore`
- `management_probe`
- `routing`
- `dns`
- `multiwan`
- `vpn`
- `hardware_dataplane`
- `performance`

Fault injection and snapshot/restore are backend safety properties, not vendor syntax capabilities.

## Disposable-target policy

Any scenario that may mutate configuration or intentionally disturb service must run only against a backend explicitly declared `lab_disposable=true`.

This includes at least:

- `configuration_roundtrip`
- `backup_restore`
- `management_survival`
- `wan_failover`
- `dns_failure`
- `default_route_loss`
- `vpn_recovery`
- `rollback_recovery`

Fault-injection scenarios additionally require `fault_injection_allowed=true`. Rollback-recovery scenarios that depend on an external recovery checkpoint additionally require `snapshot_restore_available=true`.

The common runner never upgrades a non-disposable target into a mutation-capable target.

## Shared executor boundary

The shared planner decides scenario eligibility. A vendor-specific executor only implements the mechanics for one declared backend.

```text
plan_vendor_tests(backend)
        |
        v
RUN / DEFERRED decision
        |
        v
execute_vendor_test_plan(plan, vendor_executor)
        |
        +--> executes RUN scenarios only
        +--> rejects vendor mismatch
        +--> rejects backend-id mismatch
        +--> never sends DEFERRED scenarios to the executor
        |
        v
evaluate_vendor_test_results(...)
```

The executor protocol intentionally contains no production authorization field. Credentials and transports, when eventually required by a vendor adapter, remain outside the common evidence object and must follow that vendor's security rules.

## Software acceptance versus hardware certification

Project completion must distinguish software acceptance from hardware certification.

A vendor can reach software acceptance when all required software scenarios have accepted evidence at the required fidelity. Hardware-only scenarios may remain deferred when no physical device is available.

Example reporting:

```text
Software implementation:         COMPLETE
Virtual/vendor-OS acceptance:    PASS
Production writer:               DISABLED
Physical hardware certification: DEFERRED
Reason: no physical target available
```

This is not a waiver. The harness must keep every deferred physical requirement visible until real hardware evidence exists.

## Required safety invariants

The common harness must:

- default to no production write authorization;
- never contain device credentials or secret-bearing connection material;
- never fabricate physical-device evidence;
- never treat mock/simulator evidence as vendor-OS evidence;
- never treat virtual-appliance evidence as hardware certification;
- preserve exact backend identity and evidence fidelity in every result;
- keep fault injection confined to declared lab/disposable targets;
- require lab/disposable declaration before mutating test scenarios;
- make unsupported scenarios explicit instead of silently skipping them;
- keep proprietary images and licenses outside the repository;
- leave vendor syntax authority to the vendor-specific domain.

## Vendor onboarding workflow

Adding another vendor should require only:

1. create an isolated vendor domain/adapter;
2. declare one or more test backends for that vendor;
3. declare backend capabilities and evidence fidelity;
4. run the common scenario planner;
5. implement the `VendorTestExecutor` boundary only for scenarios the backend can support;
6. emit vendor-neutral evidence records plus vendor-specific raw evidence outside secret boundaries;
7. leave unsupported hardware tests deferred until a suitable physical target exists.

No common scenario should need to be rewritten merely because a new vendor is added.

## Initial target vendor families

The harness accepts canonical vendor identifiers without hard-coding the test engine to only these values:

- `mikrotik`
- `cisco`
- `tp-link`
- `omada`
- `yamaha`
- `fortinet`
- `fortigate`

Known aliases normalize to a canonical family for reporting, while unknown future vendor identifiers remain accepted. Vendor-specific implementation remains isolated.

## Acceptance accounting

A test plan reports at least:

- backend id;
- vendor family;
- backend kind;
- evidence fidelity;
- runnable scenarios;
- deferred scenarios;
- exact defer reason for each scenario;
- whether hardware is present;
- whether the target is lab/disposable;
- whether fault injection is allowed;
- whether snapshot/restore is available;
- `production_writer_available=false`;
- `write_authorized=false`.

A result assessment additionally binds results to the exact plan SHA-256 and rejects evidence that claims fidelity above the backend that produced it.

This contract does not add production credentials or an unrestricted writer.