# Omada verified Phase 3.9-3.12 payload

This directory contains the repository-safe snapshot of all artifacts verified and read back for Omada Phase 3.9 through 3.12 on 2026-09-15.

`OMADA_PHASE3_VERIFIED_3.9-3.12.tar.gz` contains the complete original 15-file snapshot, including the three large source files that are additionally kept in the persistent project Library:

- `OMADA_HARDWARE_FIRMWARE_LIMITATION_REGISTRY.yaml`
- `OMADA_LIFECYCLE_STATUS_MATRIX.yaml`
- `OMADA_MASTER_TASKLIST.md`

Extract with:

```bash
tar -xzf OMADA_PHASE3_VERIFIED_3.9-3.12.tar.gz
```

The archive also contains the directly committed schema/summary files so the payload can be integrity-checked or reconstructed without relying on chat history.

Do not treat this packaging choice as a change to Omada evidence semantics. The persistent Library remains the source-of-truth workspace while this commit is the durable Git checkpoint.
