# Cisco IOS XE Transaction Backup, Rollback, and Recovery (C10)

## Scope

C10 defines the transaction/recovery safety boundary that follows C08 approval binding and C09 virtual-lab acceptance. The first slice is a **deterministic planning contract**, not an executor.

It does not open a NETCONF session, carry credentials, expose a device endpoint, apply configuration, or authorize production changes.

## Authoritative IOS XE behavior

The existing Cisco source manifest entries `CISCO-IOSXE-17.18-NETCONF` and `CISCO-IOSXE-26-NETCONF` document the candidate datastore and confirmed candidate commit behavior used here.

For the candidate workflow Cisco documents this order:

1. lock the running datastore;
2. lock the candidate datastore;
3. modify the candidate through NETCONF `edit-config`;
4. commit candidate to running;
5. unlock candidate and running.

Cisco also documents confirmed commit semantics: a confirmed commit temporarily applies the candidate and starts a timer. If a permanent commit is not issued before the timeout, IOS XE restores the previously committed configuration. The documented default timeout is **600 seconds (10 minutes)**.

RESTCONF does not support confirmed commit, so the C10 recovery path is NETCONF-only.

## Why confirmed commit is the recovery primitive

C10 must not invent a vendor-independent CLI rollback script when IOS XE already exposes a source-bound transactional mechanism.

The intended future executor behavior is therefore:

1. revalidate the exact target, IOS XE version, schema inventory, pre-state and C08 approval fingerprint;
2. revalidate a readable sanitized pre-change snapshot;
3. lock running;
4. lock candidate;
5. apply the exact approved candidate;
6. issue confirmed commit using the documented default timeout;
7. verify management path;
8. verify the connectivity baseline;
9. verify intended state;
10. permanently confirm the commit **only if every verification passes**;
11. on any failed verification, withhold final confirmation and allow IOS XE automatic rollback;
12. verify recovered management, connectivity and pre-change state;
13. unlock the datastores.

C10 completion requires live evidence that the failure/rollback/recovery path actually occurred. A generated plan does not satisfy that gate.

## Capability admission

A future executor may use this plan only when live NETCONF discovery observed:

- `urn:ietf:params:netconf:capability:candidate:1.0`;
- exactly one confirmed-commit capability whose URI begins with `urn:ietf:params:netconf:capability:confirmed-commit:`.

The contract deliberately records the observed confirmed-commit URI instead of guessing whether a target advertises version `1.0`, `1.1`, or another future source-supported form.

## Cisco-specific backup evidence

The repository already contains older transaction helpers whose schema names are RouterOS-specific. C10 does not silently reuse those schemas for Cisco.

`CiscoBackupEvidence` uses `cisco-transaction-backup-evidence/1` and binds:

- target id;
- model and exact IOS XE version;
- pre-state SHA-256;
- sanitized snapshot reference;
- snapshot SHA-256;
- canonical evidence digest.

The snapshot reference is opaque (`artifact:`) and may not contain URLs, credentials, tokens, secrets, or private-key material. Binary configuration bytes are not embedded in repository evidence.

## Cross-stage binding

`CiscoRecoveryPlan` is bound to all of the following:

- exact C08 target;
- exact C08 pre-state;
- exact C08 payload digest;
- exact C08 approval fingerprint;
- C09 accepted live-bundle SHA-256;
- Cisco backup evidence SHA-256;
- management baseline SHA-256;
- connectivity baseline SHA-256;
- observed candidate capability;
- observed confirmed-commit capability.

A mismatch causes fail-closed rejection.

## C08 approval state remains pre-write

C08 creates an immutable approval fingerprint but does not itself turn on execution. C10 therefore rejects a C08 binding that has been mutated to claim `human_approved`, `apply_authorized`, `write_authorized`, or `production_write_authorized`.

Later execution authorization must be represented by a separate, scoped runtime gate rather than mutating the C08 artifact.

## Synthetic CI boundary

Unit tests exercise backup and recovery-plan logic with deterministic fixtures. Those fixtures cannot close C10.

`.github/workflows/cisco-transaction-recovery.yml` records only `contract_only_status()` with:

- `synthetic_fixture_can_complete_c10 = false`;
- `live_rollback_observed = false`;
- `restored_state_verified = false`;
- `c10_complete = false`;
- `apply_available = false`;
- `production_writer_available = false`;
- `production_write_authorized = false`.

C10 ledger points may be awarded only after identified live IOS XE evidence proves backup, management survival, induced verification failure, automatic rollback, restored-state verification, and recovery.
