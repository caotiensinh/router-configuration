# Cisco Acceptance Lessons Learned

**Status:** Active engineering guidance  
**Scope:** Cisco IOS XE acceptance, GitHub convergence, CI diagnostics, simulation evidence, and future AI/human work on this repository.  
**Authority:** Subordinate to `MASTER_RULES.md`, governance policies, and `vendors/cisco/VENDOR_RULES.md`.

## Why this document exists

The Cisco acceptance work exposed several failure modes that are easy to repeat when a long-running task spans GitHub mutations, CI, self-hosted runners, remote labs, simulator evidence, and human/physical acceptance gates. These lessons are persisted so future humans and AI agents start from the evidence-based workflow instead of rediscovering the same problems.

This document does not change canonical acceptance weights. `CISCO_PROGRESS.json` remains the source of truth for canonical progress.

## Lesson 1 — A UI or message-delivery timeout does not prove the backend mutation failed

A client-side message such as `Message delivery timed out. Please try again.` is an **UNKNOWN** outcome for any mutation.

Never retry a mutating action immediately. First re-read live remote state:

```text
TIMEOUT / AMBIGUOUS RESPONSE
        ↓
REFETCH TARGET BRANCH / REF
        ↓
REFETCH COMMIT / PR
        ↓
REFETCH WORKFLOW RUN OR ARTIFACT
        ↓
DETERMINE WHAT ACTUALLY PERSISTED
        ↓
RETRY ONLY THE MISSING OPERATION
```

**Rule:** never retry a mutating action after a delivery timeout without first reading live remote state.

This prevents duplicate commits, duplicate branches, duplicate workflow dispatches, duplicate acceptance requests, and accidental state divergence.

## Lesson 2 — Do not patch before root-cause analysis

The required debugging sequence is:

```text
REPRODUCE
  ↓
READ EXISTING LOGS / STATUS / HTTP RESPONSE / CI OUTPUT
  ↓
ADD TARGETED INSTRUMENTATION IF EVIDENCE IS INSUFFICIENT
  ↓
TRACE LOCAL FUNCTION LOGIC
  ↓
TRACE CROSS-FILE / CROSS-WORKFLOW LOGIC
  ↓
FORM MULTIPLE HYPOTHESES
  ↓
TEST THE CHEAPEST / SAFEST HYPOTHESES FIRST
  ↓
IDENTIFY ROOT CAUSE
  ↓
APPLY THE SMALLEST SAFE FIX
  ↓
RE-RUN THE ORIGINAL FAILURE PATH
```

A green secondary path is not proof that the original failure path was fixed.

## Lesson 3 — Distinguish the root blocker from downstream blockers

A blocked later stage does not imply that the later-stage code is the place to change.

Build a dependency graph first. For example, a final handover or production gate may be blocked by missing live discovery, approval, virtual-lab evidence, rollback evidence, or physical acceptance. Fixing the downstream decision code would only hide the real dependency.

**Rule:** trace blocker dependencies backward to the earliest unsatisfied gate before changing code.

## Lesson 4 — Self-hosted runner does not imply host privilege

A self-hosted runner may still lack capabilities required by a workflow. Examples observed during this work include host resources whose ownership/mode require membership in privileged groups and environments where `sudo` is unavailable.

Never infer:

```text
self-hosted runner => root / KVM / Docker / arbitrary host access
```

Probe the exact capability required by the job and fail closed with useful diagnostics.

## Lesson 5 — Do not weaken a security boundary to make CI green

A workflow identity mismatch is not a reason to relax owner or authorization checks.

When a dispatch path changes actor identity, redesign the workflow so authorized identity and provenance remain explicit. The safe pattern is to preserve owner-triggered intent, validate the dispatch request, bind exact source SHA, and call the privileged/self-hosted execution path without broadening the security gate.

**Rule:** fix workflow architecture before weakening `owner_gate`, approval, provenance, or authorization checks.

## Lesson 6 — Simulation is not physical hardware and physical hardware is not production

Evidence classes must remain separate:

1. deterministic/synthetic logic tests;
2. qualified simulation or open emulation;
3. identified vendor virtual appliance evidence;
4. physical Cisco IOS XE evidence;
5. explicitly authorized production deployment evidence.

Simulation may validate software logic, state transitions, simulated protocol/network behavior, fault handling, and rollback behavior within the simulator's declared fidelity.

Simulation does **not** prove physical ASIC behavior, transceiver/port behavior, exact proprietary firmware behavior, hardware timing, vendor defects, or production behavior.

The machine-readable enforcement lives in `src/router_configuration/vendors/cisco/simulation_evidence.py` and its tests. Simulation evidence must keep physical and production claims false and cannot promote canonical acceptance gates.

## Lesson 7 — Do not fake progress

Canonical progress increases only when the canonical sub-gate defined by `CISCO_PROGRESS.json` becomes PASS with the evidence class that gate requires.

Do not add canonical points merely because:

- code was written;
- a commit or PR exists;
- documentation was added;
- CI passed;
- a diagnostic branch succeeded;
- a simulator scenario passed;
- a blocker was understood.

Engineering completion and acceptance completion are separate measurements.

## Lesson 8 — Hardware limitations must not erase real software readiness

The inverse mistake is also harmful. If engineering and simulation readiness are complete but physical hardware is unavailable, report that accurately instead of describing the software as unfinished.

Use separate status dimensions such as:

```text
Engineering Readiness
Simulation Readiness
Vendor-Virtual Validation
Physical Hardware Validation
Production Validation
Canonical Acceptance
```

When a required physical environment does not exist, use an explicit external/deferred state such as `DEFERRED_EXTERNAL` or `NOT_EXECUTED_PHYSICAL_LIMITATION` when the governing schema supports it. Do not relabel it PASS or code failure.

## Lesson 9 — Cross-repository simulator evidence needs exact provenance

When `caotiensinh/Network_Sandbox_Runtime` is used, evidence must bind the exact revisions and inputs used by the run.

At minimum retain:

```text
router-configuration source SHA
Network_Sandbox_Runtime source SHA
simulation profile / scenario identity
input or scenario digest where produced
pre-state digest where produced
post-state digest where produced
evidence scope/class
physical_device_verified = false
production_write_authorized = false
```

A simulator update can change behavior. Evidence without exact simulator provenance is not reproducible enough to support later engineering review.

## Lesson 10 — Diagnostic branches are investigation tools, not automatic production candidates

A diagnostic branch may contain temporary probes, instrumentation, environment-specific assumptions, or deliberately narrow experiments.

After RCA:

```text
reusable validated logic -> clean implementation / canonical branch
throwaway diagnostic code -> keep out of production merge
```

The existence of a diagnostic branch or successful diagnostic run is not itself progress.

## Lesson 11 — Break long work into independently verifiable units

Prefer:

```text
Task N.1
IMPLEMENT
  ↓
PERSIST
  ↓
TEST
  ↓
VERIFY
  ↓
PASS / FAIL
  ↓
INTEGRATE
```

Then move to N.2.

Avoid one long mutation chain that mixes RCA, implementation, CI, merging, runtime acceptance, and reporting. Small units reduce ambiguous timeout recovery and make exact provenance easier.

## Lesson 12 — Repository live state outranks conversation memory

Re-read live state before consequential GitHub mutations:

- before creating or updating a branch;
- after any timeout or ambiguous mutation;
- before merging;
- before workflow dispatch;
- before moving a ref;
- before reporting that code is on `main`.

Never trust an old SHA from a previous chat or checkpoint if the repository may have moved.

## Enforcement already present

These lessons are not documentation-only guidance. The Cisco implementation already contains fail-closed controls that enforce important parts of them:

- `simulation_evidence.py` rejects physical/production claims from simulation evidence;
- simulation evidence cannot promote canonical physical/production acceptance gates;
- exact source SHA and simulator SHA are validated;
- record digests detect post-generation tampering;
- `CISCO_PROGRESS.json` separates engineering points from acceptance points;
- Cisco workflows and acceptance code preserve explicit physical/production boundaries;
- exact-head CI and governance workflows provide machine-verifiable integration evidence.

Future changes should add enforcement when a lesson can be checked deterministically instead of relying only on prose.

## Mandatory AI/human operating checklist for similar incidents

Before mutation:

```text
[ ] Read current MASTER_RULES.md
[ ] Read applicable governance and vendor rules
[ ] Re-fetch current branch/ref/PR state
[ ] Identify exact acceptance gate and evidence class
[ ] Confirm the planned mutation does not weaken security boundaries
```

After a failure or timeout:

```text
[ ] Treat outcome as UNKNOWN until remote state is inspected
[ ] Read logs/status/HTTP evidence before retrying
[ ] Add targeted instrumentation if evidence is insufficient
[ ] Test multiple plausible root-cause hypotheses
[ ] Retry only after evidence or method changed
```

Before PASS/integration:

```text
[ ] Test the original failure path
[ ] Verify exact head SHA
[ ] Verify CI/governance for that exact head
[ ] Confirm evidence class matches the gate being promoted
[ ] Ensure PASS work is persisted
[ ] Re-fetch target branch before merge
[ ] Never force-push for convergence unless separately and explicitly authorized by governance
```

After integration:

```text
[ ] Re-fetch main
[ ] Verify the expected commit/content is reachable from main
[ ] Report canonical progress from live CISCO_PROGRESS.json
[ ] Keep simulation, physical, and production status separate
```

## Reusable core principle

> **Repo truth before retry. Evidence before change. Root cause before patch. PASS means persisted and verified. Simulation never impersonates hardware, and hardware never impersonates production.**
