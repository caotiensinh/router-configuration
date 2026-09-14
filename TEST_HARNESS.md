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
- `management_probe`
- `routing`
- `dns`
- `multiwan`
- `vpn`
- `fault_injection`
- `snapshot_restore`
- `hardware_dataplane`
- `performance`

The labels describe test capability, not vendor command syntax.

## Software acceptance versus hardware certification

Project completion must distinguish software acceptance from hardware certification.

A vendor can reach software acceptance when all required software scenarios have accepted evidence at the required fidelity. Hardware-only scenarios may remain deferred when no physical device is available.

Example reporting:

```text
Software implementation:        COMPLETE
Virtual/vendor-OS acceptance:   PASS
Production writer:              DISABLED
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
- make unsupported scenarios explicit instead of silently skipping them;
- keep proprietary images and licenses outside the repository;
- leave vendor syntax authority to the vendor-specific domain.

## Vendor onboarding workflow

Adding another vendor should require only:

1. create an isolated vendor domain/adapter;
2. declare one or more test backends for that vendor;
3. declare backend capabilities;
4. run the common scenario planner;
5. implement vendor-specific executors only for scenarios the backend can support;
6. emit vendor-neutral evidence records plus vendor-specific raw evidence outside secret boundaries;
7. leave unsupported hardware tests deferred until a suitable physical target exists.

No common scenario should need to be rewritten merely because a new vendor is added.

## Initial target vendor families

The harness must accept canonical vendor identifiers without hard-coding the test engine to only these values:

- `mikrotik`
- `cisco`
- `tp-link`
- `omada`
- `yamaha`
- `fortinet`
- `fortigate`

Aliases may normalize to a canonical family for reporting, but vendor-specific implementation remains isolated.

## Acceptance accounting

A test plan must report at least:

- backend id;
- vendor family;
- backend kind;
- evidence fidelity;
- runnable scenarios;
- deferred scenarios;
- exact defer reason for each scenario;
- whether hardware is present;
- whether fault injection is allowed;
- whether snapshot/restore is available;
- `production_writer_available=false`;
- `write_authorized=false`.

This contract is planning and evidence accounting only. It does not add router transports, production credentials, or an unrestricted writer.