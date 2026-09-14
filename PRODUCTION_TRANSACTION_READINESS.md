# Production Transaction Readiness Contract

This document defines the production-readiness verification boundary for RouterOS transactions. It does **not** enable a production writer, expose credentials, create a device transport, or authorize configuration changes.

## Authority

The contract implements the safety requirements from `MASTER_RULES.md`, `governance/EXECUTION_POLICY.md`, `governance/SECURITY_POLICY.md`, and `vendors/mikrotik/VENDOR_RULES.md`.

Production execution remains disabled until all repository, CHR, physical-device, operator-attestation, approval, and runtime acceptance gates are satisfied.

## Goal

Before a future production adapter can even be considered, a transaction candidate must prove that the evidence and verification plan required to protect the device and management path already exist.

The readiness path is:

`AUTHORIZED TRANSACTION -> DUAL PRE-CHANGE BACKUP -> MANAGEMENT GUARD -> VERIFICATION CONTRACT -> ROLLBACK/RECOVERY CONTRACT -> READINESS EVIDENCE`

A readiness PASS means only:

> The candidate has the required evidence contracts for a future separately authorized production execution boundary.

It does **not** mean:

- production apply is available;
- credentials are available;
- a router transport exists;
- human approval can be bypassed;
- physical CCR2116 acceptance is complete;
- deployment success has been proven.

## Pre-change backup requirements

Two independent backup evidence records are required and both must bind to the exact pre-change state digest:

1. `sanitized_export`
   - repository-safe human-readable export reference;
   - SHA-256 digest;
   - no binary backup bytes.
2. `protected_ephemeral_binary`
   - opaque protected-storage reference only;
   - SHA-256 digest;
   - binary payload never enters repository evidence or model context.

The transaction envelope's bound backup evidence must be present in this dual-backup set.

## Management-path guard

Production readiness requires explicit evidence that:

- management reachability is confirmed before change;
- an independent management probe exists;
- management reachability will be monitored during apply;
- post-apply management verification is mandatory;
- rollback recovery verification is mandatory.

The evidence may contain references, booleans, and digests only. URLs, credentials, commands, methods, shell fragments, secrets, and transport objects are forbidden.

## Verification contract

The minimum required post-apply checks are:

- `management`;
- `wan`;
- `dns`;
- `routing`.

`vpn` is additionally required when the deployment profile enables WireGuard.

Every required check must declare:

- `required=true`;
- `readback_required=true`;
- `behavior_verification_required=true`;
- an evidence reference.

A successful command response is never sufficient.

## Rollback and recovery contract

The contract must require:

- stop further changes on verification failure;
- assess actual state before rollback;
- rollback after failed verification;
- verify restored state;
- preserve incident evidence.

## Post-apply outcome

Only two terminal evidence states are accepted by the evaluator:

### Verified success

The transaction lifecycle is `verified` and every required verification check reports `ok=true` with evidence.

### Failure recovered

The transaction lifecycle is `rolled_back`, failure evidence is present, and management/connectivity/managed-object recovery checks all pass.

A recovered failure is **not** deployment success. It is evidence that the safety/rollback path worked.

## Safety invariants

Every readiness and outcome payload must retain:

- `transport_present=false`;
- `apply_available=false`;
- `production_writer_available=false`;
- `write_authorized=false`;
- no credential or secret values;
- deterministic SHA-256 integrity binding.

The future production adapter must remain a separate implementation and acceptance gate.