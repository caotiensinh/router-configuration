# Cisco IOS XE C11 — Physical Read-Only Acceptance Contract

## Purpose

C11 is the final read-only physical-device acceptance gate for the Cisco IOS XE domain. It is intentionally separate from virtual-lab acceptance. A C8000V or any other virtual target can exercise parser, transport and transaction behavior, but virtual evidence cannot satisfy C11.

This contract validates sanitized metadata for a possible human acceptance review. It does not automatically assert that a physical device was observed, and contract CI cannot award C11 points.

## Required evidence shape

A candidate physical evidence bundle must identify:

- physical target kind: `physical_router` or `physical_switch`;
- admitted IOS XE model and exact version;
- read-only transport: `netconf` or `restconf`;
- exact repository source SHA;
- sanitized YANG inventory digest;
- sanitized observation digest;
- minimized target-identity digest;
- human-attestation digest;
- evidence origin exactly `operator_attested_physical_iosxe`;
- `human_attested=true`;
- `read_only=true`;
- `write_attempted=false`;
- `virtualization=false`.

The target kind must agree with the admitted platform role. Unsupported models, unsupported trains, malformed digests, role conflicts, virtual targets, write attempts and non-approved transports fail closed.

## Privacy and evidence minimization

Raw credentials, passwords, secrets, private keys, SNMP communities and production configuration are not part of this contract. Device identity should be represented by a digest over the minimum operator-approved identity material rather than by publishing raw serial numbers or other unnecessary identifiers.

The human attestation itself may be retained outside the repository; the repository-facing bundle stores only its SHA-256 digest plus the sanitized evidence metadata needed for deterministic verification.

## Acceptance boundary

A structurally valid claim may set:

```text
eligible_for_human_acceptance=true
```

It deliberately retains:

```text
synthetic_fixture_can_complete_c11=false
c11_complete=false
physical_device_verified=false
production_write_authorized=false
```

The validator proves that a claim is well formed and consistent with repository admission rules. It does not prove the real-world fact that a human observed a physical device.

C11 can close only when a human reviewer accepts an identified, sanitized, read-only physical IOS XE evidence bundle under the repository governance process. A unit-test fixture, CI artifact generated from synthetic values, virtual appliance, screenshot without traceable evidence, or contract-only PASS cannot satisfy C11.

## Relationship to other Cisco gates

- C03/C04 provide live read-only NETCONF/RESTCONF discovery contracts and live probes.
- C09 proves IOS XE virtual-lab behavior without making physical claims.
- C11 consumes human-attested physical evidence and remains read-only.
- C12 is a separate production-write/handover gate. C11 acceptance does not authorize production writes.
