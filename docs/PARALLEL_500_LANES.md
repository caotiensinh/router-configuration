# Parallel 500-Lane Development Orchestration

## Purpose

This repository supports a deterministic orchestration capacity of **500 independent lanes** for development work. A lane is an assignment slot, not an AI process, GitHub runner, or promise that 500 workers are currently executing.

Actual concurrency is limited by the workers/runners that are really connected and by dependency/conflict rules. The scheduler must never report lane capacity as active-worker count.

## Safety model

Parallelism must not weaken `MASTER_RULES.md`.

The orchestration layer:

- does not invent vendor commands, paths, APIs, defaults, capabilities, or version facts;
- does not grant production-write authority;
- does not bypass vendor/source validation;
- does not bypass CI, governance, review, or evidence gates;
- does not write directly to `main`;
- treats a task as writable only when its repository write paths are declared before scheduling;
- serializes tasks that touch overlapping repository paths;
- serializes tasks sharing a semantic `conflict_key`, even when paths differ;
- honors declared dependencies before scheduling downstream work.

Vendor technical truth remains owned only by validated vendor knowledge and evidence.

## Lane IDs

The fixed lane namespace is:

```text
LANE-0001
...
LANE-0500
```

The canonical capacity manifest is `orchestration/parallel_lanes_capacity.json`.

## Task contract

A writable task must declare at least:

```json
{
  "task_id": "CISCO-C04-LIVE-PROBE",
  "mode": "write",
  "write_paths": [
    "src/router_configuration/vendors/cisco/live_restconf_probe.py",
    "tests/test_cisco_live_restconf_probe.py"
  ],
  "dependencies": [],
  "conflict_keys": [
    "vendor:cisco",
    "ledger:CISCO_PROGRESS"
  ],
  "priority": 100
}
```

A read-only research/review task uses:

```json
{
  "task_id": "CISCO-C04-SOURCE-REVIEW",
  "mode": "read_only",
  "write_paths": [],
  "dependencies": [],
  "conflict_keys": [],
  "priority": 50
}
```

`write_paths` are repository ownership declarations for the task. They are not vendor device paths.

## Conflict rules

Two write tasks cannot run in the same wave when one write path is the same as, or a descendant of, the other.

For example:

```text
src/router_configuration/vendors/cisco
src/router_configuration/vendors/cisco/restconf_readonly.py
```

conflict and are serialized.

`conflict_keys` protect shared logical resources that path matching alone cannot safely model. Typical examples are progress ledgers, shared generated registries, the same PR metadata, or the same acceptance artifact.

Read-only tasks do not reserve repository write paths, but they still may use conflict keys when they rely on an exclusive external resource.

## Dependencies

A task is runnable only when all declared dependencies have completed in earlier waves. Cycles and references to unknown task IDs fail closed.

## Planning

Given a JSON task document:

```json
{
  "base_sha": "0123456789012345678901234567890123456789",
  "tasks": []
}
```

generate a plan with:

```bash
python -m router_configuration.parallel_lanes plan \
  --tasks tasks.json \
  --output plan.json \
  --max-lanes 500
```

The resulting plan records:

- exact base SHA when supplied;
- lane capacity;
- requested concurrency cap;
- deterministic waves;
- lane/task assignments;
- declared write ownership;
- semantic conflict keys;
- `worker_processes_started: 0`.

The last field is deliberate: planning a lane does not claim a worker has been launched.

## Worker protocol

An external AI/worker consuming a lane should:

1. read the current `MASTER_RULES.md` and applicable scoped/vendor rules;
2. verify that its task base SHA is still valid;
3. use its own branch/worktree, normally containing the lane and task ID;
4. modify only the task's declared write paths unless the task is re-planned;
5. run the task-specific tests and required governance gates;
6. persist PASS evidence and commit it in the same working session;
7. integrate through a PR/review path rather than direct uncontrolled writes to `main`.

A worker that discovers a new dependency or shared write target must stop and return the task for re-planning instead of silently expanding its scope.

## Scaling behavior

The scheduler is contract-tested with **500 pairwise-independent write tasks in one wave**. A 501st task is placed in a later wave when `max_lanes=500`.

This proves deterministic scheduling capacity. It does **not** prove the presence of 500 CPU processes, 500 GitHub-hosted runners, or 500 AI agents. Those resources must be supplied by the execution environment.

## Why this improves development speed

The design allows work to scale horizontally without turning the repository into a merge-conflict queue:

- independent files/modules can move at the same time;
- shared ledgers and integration surfaces are serialized deliberately;
- prerequisites are explicit rather than discovered late during merge;
- each worker receives narrow ownership;
- integration remains evidence-gated.

The target is useful parallelism, not maximum thread count at the cost of repository integrity.
