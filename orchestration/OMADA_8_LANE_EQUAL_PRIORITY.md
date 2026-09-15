# Omada — 8 Equal-Priority Parallel Lanes

Status: ACTIVE
Activated: 2026-09-15
Durable baseline at activation: 195 / 340 = 57.35%

## Execution model

All eight lanes are released simultaneously and have equal priority. There is no primary lane, fallback lane, or waiting order.

Research, coding, tests and lane-owned commits may progress independently. Only convergence into canonical Library state and GitHub `main` is serialized where shared paths or dependencies conflict.

Progress is counted only after: PASS + Library persistence/read-back where applicable + `main` commit/push + exact SHA verification + CI/Governance success.

## Active lanes

| Lane | Branch | Issue | Draft PR | Scope |
|---|---|---:|---:|---|
| AGENT-01 | `lane/agent-01` | #48 | #65 | governance remainder, 4.15–4.20, 5.01–5.06 |
| AGENT-02 | `lane/agent-02` | #49 | #66 | 5.07–5.16, 6.01–6.07 |
| AGENT-03 | `lane/agent-03` | #50 | #67 | 6.08–6.12, 7.01–7.12 |
| AGENT-04 | `lane/agent-04` | #51 | #68 | 7.13–7.15, Phase 8, 9.1–9.4 |
| AGENT-05 | `lane/agent-05` | #52 | #69 | 9.5–9.13, 10.1–10.8 |
| AGENT-06 | `lane/agent-06` | #53 | #70 | 10.9–10.10, Phase 11, 12.1–12.4 |
| AGENT-07 | `lane/agent-07` | #54 | #71 | 12.5–12.9, Phase 13, 14.1–14.2 |
| AGENT-08 | `lane/agent-08` | #55 | #72 | 14.3–14.16, VLAB.8–VLAB.10 |

Convergence/release tail is tracked in issue #56 and owns only dependency reconciliation, merge sequencing when required, CI/Governance rechecks, and VLAB.11–VLAB.20. It does not prioritize any lane.

## Lane isolation

- Each lane owns its branch and lane-specific artifacts.
- Shared canonical files must not be edited concurrently by lane branches.
- A lane may research or implement future tasks before prerequisites are durable, but such work remains dependency-blocked and cannot be promoted as complete.
- No agent may infer vendor commands, APIs, model support, firmware support, or security behavior without official evidence.
- Draft PR status is expected while a lane is incomplete.

## Evidence truthfulness

The orchestration model represents eight independent work queues/branches. It does not claim eight external AI worker processes exist unless external workers are actually connected and executing those queues.
