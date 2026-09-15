# Omada Phase-3 Relational Database Schema

**Task:** 3.12 — Normalize into database schema  
**Observed:** 2026-09-15  
**Status:** VALIDATED

## Architecture

The database uses a normalized exact-scope model instead of a flattened product row:

`product -> hardware_revision / region_scope / firmware_release / management_mode / controller_platform -> target_scope -> observation -> evidence`

Domain tables extend observations for physical interfaces, performance/capacity/power/environment metrics, controller compatibility, management-mode features, limitations, lifecycle notices and conflict reconciliation.

## Safety invariants

- Exact model is the base identity; aliases never imply equality.
- Raw hardware, region and firmware notations remain queryable.
- Multiple official observations may coexist for one fact.
- Conflict decisions never delete the underlying observations.
- `UNKNOWN`, `NOT_PUBLISHED`, `NOT_APPLICABLE`, `SOURCE_CONFLICT` and `FAIL_CLOSED` are first-class states.
- Every automation-relevant fact can link to official evidence.
- Lifecycle remains revision/region scoped.
- Bundle, passive accessory, controller-host and controller-platform roles remain separate.

## Database objects

The SQLite-compatible DDL defines **23 normalized tables** plus `v_effective_observations`.

## Mapping and validation

`OMADA_PHASE3_DATABASE_MAPPING.yaml` maps Phase 3.1–3.11 artifacts to tables.

`OMADA_PHASE3_DATABASE_VALIDATION.md` records an executable SQLite smoke test with all **230 exact products** and **44 revision-scoped lifecycle notices**.

## Next

3.13 — Cross-check against datasheet + hardware guide + compatibility source.
