# Cisco IOS XE C09 — Live Virtual-Lab Evidence Ingestion

## Scope

This layer sits in front of the existing C09 semantic validator. Its job is to treat a downloaded or externally produced live-lab JSON artifact as untrusted input before any C09 claim is evaluated.

It does not contact a device, download Cisco software, execute a lab, approve a change, or promote a CI fixture into live evidence.

## Ingestion boundary

The ingestor accepts UTF-8 JSON text or bytes with a maximum size of 128 KiB. Before calling the existing C09 validator it:

- rejects invalid UTF-8;
- rejects malformed JSON;
- rejects duplicate JSON keys;
- requires the root to be an object;
- enforces the exact top-level C09 evidence field set;
- rejects missing top-level fields;
- recursively rejects sensitive key names such as password, secret, token, private key, community and credential fields.

After structural admission, the payload is passed to `build_cisco_virtual_lab_bundle()`, which already binds the candidate evidence to the exact C08 target, model, IOS XE version, schema inventory, pre-state, rendered payload, approval fingerprint, topology and required vendor-OS scenarios.

## Two-stage claim model

A semantically valid payload can produce a candidate bundle that internally claims:

```text
live_virtual_iosxe_observed=true
c09_complete=true
```

That is the meaning of the external candidate evidence after validation. The ingestion layer deliberately does **not** turn that statement into repository acceptance by itself. Its repository-facing record remains:

```text
repository_live_evidence_accepted=false
repository_c09_complete=false
physical_hardware_claimed=false
production_writer_available=false
production_write_authorized=false
```

A later evidence-verification step must verify the external run/artifact provenance and repository acceptance policy before the canonical C09 ledger can move.

## Why this is separate from the C09 validator

Separating artifact ingestion from semantic validation reduces the blast radius of untrusted files. JSON framing, duplicate-key behavior, unexpected fields, size limits and secret-like fields are checked at the boundary, while IOS XE/C08/topology/scenario semantics stay in the existing C09 validator.

This also makes the work independently testable and keeps a parser-hardening change from modifying the virtual-lab acceptance logic.

## CI boundary

The dedicated workflow exercises only synthetic contract fixtures. Its evidence explicitly states that the fixture is not live evidence and that C09 remains incomplete. A workflow PASS proves parser and boundary behavior only.
