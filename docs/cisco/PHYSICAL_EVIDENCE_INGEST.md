# Cisco C11 Physical Evidence Ingest

This layer is the untrusted JSON boundary for operator-attested physical IOS XE read-only evidence. It rejects duplicate/unknown fields, secret-like metadata, virtual platform families, write attempts, non-read-only sessions, missing attestation, and self-promotion of acceptance flags.

`Catalyst 8000V` is explicitly rejected from the physical acceptance path even if an input incorrectly declares `virtualization=false`. Physical router claims must use an admitted physical router family such as Catalyst 8200/8300/8500.

A successful ingest record is only eligible for human acceptance review. It keeps `repository_physical_evidence_accepted=false`, `c11_complete=false`, `physical_device_verified=false`, and `production_write_authorized=false` until canonical physical evidence review is performed.
