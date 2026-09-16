# Cisco IOS XE Domain

## Purpose

Build Cisco router and switch automation as an independent vendor/OS domain under the repository-wide governance model.

The initial Cisco scope is **IOS XE only**. Cisco NX-OS and IOS XR are intentionally excluded because they have different platform semantics, feature sets, configuration models, and operational behavior.

## V1 platform families

Documentation-scoped router/edge families:

- Catalyst 8000V
- Catalyst 8200
- Catalyst 8300
- Catalyst 8500

Documentation-scoped campus switch families:

- Catalyst 9200
- Catalyst 9300
- Catalyst 9400
- Catalyst 9500
- Catalyst 9600

Initial documentation trains:

- IOS XE 17.18.x
- IOS XE 26.x.x

These are documentation baselines, not blanket feature-support claims. Exact model, version, advertised YANG models, enabled management transports, license/capability state, and current device state must be discovered before a feature can be admitted.

## Architecture invariant

```text
USER INTENT
    -> DEVICE IDENTITY / IOS XE VERSION
    -> OFFICIAL CISCO SOURCE MANIFEST
    -> DEVICE-ADVERTISED YANG CAPABILITIES
    -> READ-ONLY NORMALIZED STATE
    -> DETERMINISTIC FEATURE MODEL
    -> DEPENDENCY / CONFLICT VALIDATION
    -> CHANGESET + HASH
    -> LAB / MODEL VALIDATION
    -> HUMAN APPROVAL
    -> SAFE APPLY
    -> READ-BACK VERIFY
    -> ROLLBACK / RECOVERY EVIDENCE
```

AI does not own Cisco CLI or YANG truth.

## Management strategy

Prefer model-driven management when the requested feature is represented by validated YANG models and is actually advertised by the target device:

- NETCONF
- RESTCONF
- YANG capability discovery
- later: model-driven telemetry / gNMI where separately admitted

CLI is not forbidden, but it is a separate deterministic renderer path. An IOS XE CLI operation may only enter the active catalog after exact Cisco documentation, platform/version scope, mode/context, dependency rules, validation, verification, and rollback behavior are encoded and tested.

## Safety boundary

Current Cisco phase is **read-only foundations**.

The following remain false:

```text
production_write_authorized = false
physical_device_verified = false
automatic_feature_support_inference = false
```

No code in the initial Cisco domain may convert documentation coverage into production write authority.

## Planned acceptance sequence

1. Governance and official-source manifest.
2. Platform/IOS XE version classifier.
3. NETCONF read-only capability/identity discovery.
4. RESTCONF read-only discovery.
5. Router normalized state: interfaces, addressing, routes, neighbors/capabilities where authoritative models are available.
6. Switch normalized state: interfaces, VLANs, trunks, L2 state, STP-relevant state where authoritative models are available.
7. Deterministic desired-state and diff contracts.
8. Feature-by-feature YANG/CLI renderer admission with authoritative references.
9. Lab validation on an identified IOS XE virtual target; virtual evidence remains separate from physical hardware evidence.
10. Backup, transaction, rollback/recovery, post-change verification, and physical-device gates before any production write authorization.

## Authoritative baseline

The bundled source manifest references Cisco's official IOS XE programmability and configuration-guide pages. Runtime operation must remain offline-first after validated knowledge is promoted into the repository.
