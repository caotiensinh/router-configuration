# Cisco IOS XE Virtual Lab Acceptance (C09)

## Purpose

C09 is the first Cisco stage that may prove an **apply** operation, but only on an identified, disposable IOS XE virtual appliance. It does not authorize production writes and it does not certify physical Cisco hardware.

The initial adapter is deliberately bounded to **Cisco Catalyst 8000V**. Cisco documents Catalyst 8000V as a software-based IOS XE virtual router and provides installation guidance for supported virtual environments, including KVM. The Cisco image and licensing material must be acquired by the operator from Cisco and must remain outside this repository.

Authoritative source manifest entry: `CISCO-C8000V-INSTALL`.

## Reuse the common lab

Cisco plugs into the existing repository-wide lab defined by `LAB_TEST_ENVIRONMENT.md` and `src/router_configuration/test_lab.py`. It does not create a second WAN/LAN/fault framework.

The standard attachment contract remains:

1. isolated adapter-defined management attachment;
2. `wan_primary`;
3. `wan_backup`;
4. `lan`.

The evidence bridge binds the observed lab topology to `StandardLabTopology.build().as_dict()["topology_sha256"]`.

## Required acceptance chain

A C09 live evidence record must bind to the exact C08 approval fingerprint and therefore transitively to the C07 rendered candidate.

The bridge requires all of these bindings to match:

- opaque target identity;
- admitted model and exact IOS XE version;
- C08 `pre_state_sha256`;
- C07/C08 `payload_digest_sha256`;
- observed YANG inventory digest;
- exact C08 `approval_sha256`;
- common lab topology digest;
- source commit SHA, lab/workflow run id and artifact digest.

Changing the target, pre-state, candidate payload, schema inventory, model/version or approval fingerprint invalidates the evidence.

## Required scenarios

The first C09 slice requires four common-harness scenarios, all at `vendor_os` fidelity:

| Scenario | C09 meaning |
| --- | --- |
| `read_only_discovery` | prove the running target is an admitted IOS XE Catalyst 8000V instance |
| `render_validate` | prove the exact source-bound candidate remains the one under test |
| `configuration_roundtrip` | prove lab-only apply plus intended-state verification on the disposable VM |
| `management_survival` | prove management remains observable through an explicitly lab-scoped fault |

C09 intentionally does **not** claim C10 backup/rollback/recovery completion. Recovery is a later canonical stage.

## Evidence schema

The accepted source schema is `cisco-iosxe-virtual-lab-evidence/1`.

Minimum safety properties include:

- `evidence_origin = live_iosxe_virtual_appliance`;
- `backend_kind = virtual_appliance`;
- `identity_observed = true`;
- `lab_disposable = true`;
- `fault_injection_lab_only = true`;
- `lab_change_approved = true`;
- `intended_state_verified = true`;
- `management_survived_fault = true`;
- `target_discarded_or_sanitized_after_run = true`;
- `image_embedded_in_repository = false`;
- `license_material_present = false`;
- `hardware_present = false`;
- `physical_hardware_claimed = false`;
- `production_writer_available = false`;
- `production_write_authorized = false`.

Evidence references must be opaque and sanitized; URLs, credentials, tokens and private-key material are not accepted by the bridge.

## Synthetic CI boundary

Unit tests exercise positive and negative validator paths using fixtures. Those fixtures are **contract tests only**.

`.github/workflows/cisco-iosxe-virtual-lab.yml` persists only `contract_only_status()` and explicitly records:

- `synthetic_fixture_can_complete_c09 = false`;
- `live_virtual_iosxe_observed = false`;
- `c09_complete = false`.

Therefore a green CI run for the C09 contract does not earn C09 ledger points. C09 may move to complete only after sanitized evidence from a real, identified IOS XE virtual appliance is ingested and independently verified against the exact source SHA and artifact provenance.

## Image and license boundary

The repository must never contain Cisco `.qcow2`, `.iso`, `.ova`, `.vmdk`, license keys, entitlement data or credentials. The CI contract scans tracked Cisco/IOS XE/C8000V paths for common virtual-appliance image extensions and fails if an image is committed.

## Production boundary

A disposable VM may perform an explicitly approved lab-only configuration roundtrip for C09. This does not create production authorization. Production mutation remains blocked until the later canonical production-write/handover gate is independently satisfied.
