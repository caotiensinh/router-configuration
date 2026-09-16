# Cisco Progress Measurement Standard

## Purpose

`CISCO_PROGRESS.json` is the canonical fixed 100-point work-completion ledger for the Cisco IOS XE router/switch domain.

Schema `2.0` replaces stage-level all-or-nothing scoring with fixed weighted sub-gates. It records evidence-backed work completion without pretending that implementation progress is the same thing as live acceptance, delivery readiness, or production authorization.

## Canonical scoring rules

1. The denominator is always **100 points**.
2. Existing C01-C12 stage weights remain fixed.
3. Every stage is divided into small, pre-weighted sub-gates.
4. A sub-gate is binary: `pass` earns its full fixed weight; `pending` or `blocked` earns zero.
5. No free-form partial percentage is allowed inside a sub-gate.
6. A `pass` requires evidence.
7. Engineering gates may use source-bound repository artifacts, deterministic tests, integration evidence, and CI.
8. Acceptance gates are hard gates. CI, commits, repository files, and synthetic fixtures alone cannot satisfy them.
9. Live, human, physical, and production gates require the corresponding real evidence class.
10. Planning, branch creation, documentation-only intent, waiting for CI, synthetic-only work, assumptions, and blocker diagnosis by themselves earn zero.
11. `overall_percent` remains the legacy-compatible weighted work-completion percentage because the denominator is exactly 100.
12. Weighted work completion MUST NOT be reported as delivery readiness or production readiness.
13. Project progress does not imply production authorization.

## Four distinct reporting dimensions

The project must not compress fundamentally different states into one percentage.

### 1. Weighted work completion

This is the canonical 100-point ledger value:

```text
earned canonical points / 100
```

It answers:

> How much of the predefined engineering + acceptance work has evidence-backed PASS status?

Current value: **79/100 = 79%**.

### 2. Engineering completion

The engineering budget is **79 points**.

Current value: **79/79 = 100%**.

This means the currently defined engineering sub-gates are complete. It does **not** mean the Cisco domain is accepted for production.

### 3. Acceptance completion

The acceptance budget is **21 points**.

Current value: **0/21 = 0%**.

Acceptance requires real live/human/physical/production evidence. Engineering artifacts cannot substitute for those gates.

### 4. Delivery readiness

Delivery readiness is a **gated status**, not a synthetic percentage.

Use:

```text
READY
```

only when all required acceptance gates pass and the corresponding physical-device and production-authorization conditions are satisfied.

Otherwise use:

```text
BLOCKED
```

and name the exact blocking gates or required inputs.

Current status: **BLOCKED**.

## Fixed budgets

- **Engineering: 79 points** — implementation, source binding, deterministic tests, CI, evidence plumbing, review tooling, and integration.
- **Acceptance: 21 points** — live-device evidence, changeset-specific human approval, physical-hardware acceptance, verified rollback, production deployment, and final handover.

The weights MUST NOT be changed merely to make a session appear productive.

## Schema 1.0 reconciliation

The old ledger reported 12/100 because only C01 and C02 were fully closed. It assigned zero to substantial merged work in C03-C12.

Schema 2.0 re-scored already-existing evidence against fixed sub-gates:

- Previous canonical score: **12/100**
- Reconciled evidence-backed score: **74/100**
- Measurement reclassification delta: **+62 points**
- New work after the reconciled baseline: **+5 points**
- Current canonical score: **79/100**

The +62 was not new code. It recognized work that had already been merged and verified but was invisible to the old all-or-nothing formula.

## Blocker-resolution standard

A blocker is not automatically a coding task. Before opening implementation lanes, classify it.

Allowed blocker classes:

```text
INTERNAL_CODE
ENVIRONMENT_INPUT
HUMAN_APPROVAL
LIVE_DEVICE_ACCESS
PHYSICAL_HARDWARE
PRODUCTION_AUTHORIZATION
VENDOR_KNOWLEDGE
EXTERNAL_SERVICE
```

### INTERNAL_CODE

Use the evidence-first engineering loop:

```text
REPRODUCE
  -> READ LOGS
  -> ADD TARGETED LOGGING IF EVIDENCE IS MISSING
  -> TRACE LOCAL LOGIC
  -> TRACE CROSS-FILE LOGIC IF REQUIRED
  -> FORM MULTIPLE ROOT-CAUSE HYPOTHESES
  -> APPLY THE SMALLEST SAFE FIX
  -> TEST
  -> EXACT-HEAD CI
  -> RE-RUN THE ORIGINAL FAILURE PATH
  -> VERIFY
```

Only after verification may the fix be labeled PASS.

### External/input/approval/hardware blockers

Once evidence proves the blocker is external to the codebase, do **not** keep creating wrappers merely to show activity.

Instead produce an explicit unblock contract containing:

- blocker class;
- exact failing gate;
- observed evidence;
- required missing input/action;
- owner or authority able to provide it;
- safe next command/workflow/run to execute after unblocking;
- expected PASS evidence;
- security boundary;
- whether production write remains disabled.

Then stop unnecessary coding until the external condition changes, unless a code change measurably reduces future operator work or removes an independent defect.

## Multiple-solution rule

For a difficult internal blocker, do not repeatedly retry one path without new evidence.

After one failed remediation attempt:

1. capture the new logs/evidence;
2. update the dependency/root-cause model;
3. identify at least two technically valid solution paths when available;
4. compare safety, reversibility, blast radius, and verification cost;
5. choose the smallest path that can prove the target gate;
6. preserve working behavior outside that scope.

The target is **gate completion**, not persistence with one preferred implementation.

## Blocker diagnosis versus completion points

Blocker investigation is valuable engineering work, but diagnosis alone does not earn canonical completion points unless a predefined sub-gate transitions to PASS.

Checkpoint reports therefore separate:

- canonical score delta;
- blocker state change;
- implementation/CI evidence;
- exact next unblock action.

Example:

```text
CANONICAL DELTA: +0 points
BLOCKER CHANGE: unknown -> ENVIRONMENT_INPUT confirmed
EVIDENCE: live workflow preflight artifact
NEXT ACTION: configure the named repository secrets, then rerun exact-SHA read-only acceptance
```

This avoids both false stagnation and false progress inflation.

## Current blocker interpretation

At the current Cisco baseline:

- C03 and C04 dispatch paths are executable and exact-source pinned.
- Their current live workflows stop at secret/input preflight before device network access.
- Missing credentials or platform-binding inputs are `ENVIRONMENT_INPUT` blockers, not evidence that additional device-execution code is required.
- A separate dispatcher HTTP-response handling defect is `INTERNAL_CODE` and may be fixed/tested independently.
- Production write remains disabled.

## Update procedure

For every future work session:

1. Re-fetch the canonical branch and ledger.
2. Identify the smallest sub-gate or blocker transition that can be independently verified.
3. Classify blockers before deciding whether coding is appropriate.
4. Parallelize only independent ownership lanes.
5. Add evidence only after the work exists and required tests/CI pass.
6. Change a sub-gate from `pending`/`blocked` to `pass` only when its predefined evidence requirement is actually satisfied.
7. Set `earned` to the gate's full fixed weight.
8. Recalculate stage/category/top-level totals.
9. Run `python -m router_configuration.vendors.cisco.progress_ledger CISCO_PROGRESS.json --repo-root .`.
10. Run unit tests and required exact-head CI.
11. Re-run the original failing path for root-cause fixes.
12. Merge only after the validator, governance checks, required tests, and target-path verification are green.

If new scope is discovered, map it into the fixed 100-point model only through an explicit measurement-policy change. Existing completed work must not be silently diluted.

## Human checkpoint reporting rule

Every checkpoint should report these separately:

```text
WEIGHTED WORK COMPLETION: X / 100 = Y%
ENGINEERING: A / 79 = B%
ACCEPTANCE: C / 21 = D%
DELIVERY READINESS: READY | BLOCKED
CANONICAL DELTA THIS SESSION: +Z points
BLOCKER CHANGE: <previous> -> <current>
NEXT UNBLOCK ACTION: <one concrete action>
```

For compatibility with the owner's short three-line summary, use:

- `HOÀN THÀNH: X / 100 = Y%` meaning **weighted work completion**;
- `CÒN LẠI: 100-X / 100`;
- `TIẾN ĐỘ CẢI THIỆN PHIÊN VỪA RỒI: +Z điểm %` only for newly earned canonical sub-gate points.

Always append engineering, acceptance, and delivery-readiness state when acceptance is not complete.
