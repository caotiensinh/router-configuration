# Yamaha Vendor Rules

**Scope:** Yamaha RTX3510 router automation only.  
**Authority:** Subordinate to `MASTER_RULES.md`; mandatory for Yamaha RTX3510 work.

## 1. Technical truth

Current official Yamaha Network product documentation and official Yamaha RTpro technical information are the primary technical authority. Product-, model-, and firmware-matched specifications, manuals, command references, firmware listings, release notes, and validated offline copies outrank AI prior knowledge or community examples.

Facts from another Yamaha router model or firmware revision MUST NOT be silently reused for RTX3510.

## 2. Initial platform scope

The initial Yamaha domain is deliberately restricted to:

- model: `RTX3510`;
- firmware: `Rev.23.01.03`;
- role: router;
- admission: documentation-scoped, read-only first.

A model or revision appearing in a shared command reference proves documentation scope only. It does not prove that every feature, command, default, dependency, or operational behavior is available or appropriate for every configuration.

Unknown models or firmware revisions fail closed.

## 3. Version and capability discovery

Before any generated operation is treated as executable, the system MUST discover and record the exact model and firmware revision from the target device and compare them with the validated Yamaha knowledge package.

Feature availability, enabled services, interface state, routing state, licenses or subscriptions, and other device facts MUST be discovered or source-bound. They MUST NOT be inferred from the product name alone.

## 4. Read-only admission first

The Yamaha domain MUST establish read-only discovery before any write path. Initial admission should prove at least:

- exact model and firmware identity;
- interface and link-state visibility;
- routing-state visibility;
- configuration/readback visibility sufficient for deterministic normalization;
- secret-field exclusion;
- least-privilege behavior;
- deterministic normalized output.

Read-only discovery evidence and synthetic fixtures do not authorize configuration mutation.

## 5. AI boundary

AI may normalize operator intent, select among already-validated Yamaha operations, explain evidence, and propose ordering. AI MUST NOT invent Yamaha commands, parameters, defaults, feature availability, device facts, firmware behavior, or write authorization.

## 6. Configuration safety

Before any production write, the system MUST have current state, desired state, deterministic diff, dependency/conflict analysis, management-path analysis, backup, rollback, verification criteria, and changeset-specific human approval.

## 7. Verification

A successful command return or management-session response is not deployment success. Actual state and behavior MUST be read back and verified against desired state and Yamaha-documented expectations.

## 8. Lab and simulation evidence

Simulation or synthetic fixtures may validate parsers, planners, renderers, dependency logic, and recovery logic. They MUST NOT be represented as physical RTX3510 evidence.

If physical hardware is unavailable, hardware-only acceptance is recorded as an external dependency and does not block completion of testable engineering scope.

## 9. Current write boundary

This baseline does not authorize Yamaha configuration writes. `production_write_authorized` and `physical_device_verified` MUST remain false until separately proven by governed acceptance evidence.
