# Cisco IOS XE C10 — Transaction Executor Boundary

## Purpose

The recovery plan already defines how IOS XE candidate/confirmed-commit recovery must work. This layer freezes that plan into a deterministic state-machine contract before any real NETCONF executor is introduced.

It deliberately contains no NETCONF client, socket, credentials, endpoint, configuration write method or commit RPC implementation.

## Bound execution order

A future authorized executor must preserve the exact recovery order:

1. revalidate target, IOS XE version, schema, pre-state and approval;
2. revalidate the repository-safe pre-change snapshot;
3. lock running;
4. lock candidate;
5. apply the exact approved candidate;
6. issue confirmed commit using the documented 600-second default timeout;
7. verify management path;
8. verify connectivity baseline;
9. verify intended state;
10. permanently confirm only when every verification passes;
11. otherwise withhold confirmation and allow automatic rollback;
12. verify recovered management, connectivity and pre-change state;
13. unlock candidate and running.

The execution contract binds the exact recovery-plan digest, approval fingerprint, C09 bundle digest, backup evidence digest and observed confirmed-commit capability.

## Fail-closed rules

The boundary rejects a recovery plan when:

- its plan digest no longer matches its contents;
- transport is not NETCONF;
- candidate or confirmed-commit capability binding is wrong;
- confirmed-commit timeout differs from the source-bound plan;
- phase order changes;
- RESTCONF confirmed commit is enabled;
- automatic rollback is no longer mandatory;
- permanent confirmation no longer depends on all verification gates;
- the pre-executor plan claims C10 completion, apply availability or production-write authority.

## What this does not do

This contract does not execute any phase. In particular it does not lock a device, send candidate configuration, issue confirmed commit, confirm a commit, cause a rollback, or verify a restored live state.

Contract output therefore remains:

```text
executor_implementation_present=false
live_execution_observed=false
live_rollback_observed=false
restored_state_verified=false
c10_complete=false
production_writer_available=false
production_write_authorized=false
```

A CI PASS proves only that the future-executor state machine is deterministic and fail closed. C10 remains incomplete until an authorized disposable IOS XE target provides accepted live backup/apply/fault/rollback/restored-state evidence.
