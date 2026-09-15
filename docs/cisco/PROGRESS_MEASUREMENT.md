# Cisco Progress Measurement Standard

## Purpose

`CISCO_PROGRESS.json` is the canonical 100-point progress ledger for the Cisco IOS XE router/switch domain.

Schema `2.0` replaces stage-level all-or-nothing scoring with fixed weighted sub-gates. This fixes the previous measurement defect where implemented, tested, merged engineering work remained at zero until an entire live/physical acceptance stage was complete.

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
10. Planning, branch creation, documentation-only intent, waiting for CI, synthetic-only work, and unsupported assumptions earn zero.
11. `overall_percent` equals earned points because the denominator is exactly 100.
12. Project progress does not imply production authorization.

## Two progress layers

The fixed budget is:

- **Engineering: 79 points** — implementation, source binding, deterministic tests, CI, evidence plumbing, review tooling, and integration.
- **Acceptance: 21 points** — live-device evidence, changeset-specific human approval, physical-hardware acceptance, verified rollback, production deployment, and final handover.

Engineering progress can advance without pretending that live or physical acceptance is complete.

## Schema 1.0 reconciliation

The old ledger reported 12/100 because only C01 and C02 were fully closed. It assigned zero to substantial merged work in C03-C12.

Schema 2.0 re-scores already-existing evidence against fixed sub-gates:

- Previous canonical score: **12/100**
- Reconciled evidence-backed score: **67/100**
- Reclassification delta: **+55 points**
- New work created by the reclassification itself: **0 points**

The +55 is not new code. It is recognition of work that was already merged and verified but invisible to the old all-or-nothing formula.

## Current baseline

- Overall: **67/100 = 67%**
- Engineering: **67/79 = 84.8%**
- Acceptance: **0/21 = 0%**
- Remaining overall: **33%**
- Production write authorization: **false**
- Physical device verification: **false**

## Update procedure

For every future work session:

1. Work on one or more pre-defined sub-gates.
2. Do not change a sub-gate weight merely to make progress look better.
3. Add evidence only after the work exists and required tests/CI pass.
4. Change the sub-gate from `pending`/`blocked` to `pass`.
5. Set `earned` to the gate's full fixed weight.
6. Recalculate stage/category/top-level totals.
7. Run `python -m router_configuration.vendors.cisco.progress_ledger CISCO_PROGRESS.json --repo-root .`.
8. Run unit tests and required CI.
9. Merge only after the progress validator and normal project governance are green.

If new scope is discovered, map it into the fixed 100-point model through an explicit measurement-policy change. Existing completed work must not be diluted silently.

## Reporting rule

Human checkpoint reports use:

- `HOÀN THÀNH: X%`
- `CÒN LẠI: Y%`
- `TIẾN ĐỘ CẢI THIỆN PHIÊN VỪA RỒI: +Z điểm %`

`+Z` means new sub-gate points actually earned in that work session. Measurement reconciliation is reported separately and must not be presented as new work.
