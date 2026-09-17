# Hardware-Unavailable Validation Policy

## Purpose

This repository must continue software, controller, compiler, diagnostic, rollback, reporting, and virtual-validation development when target physical Omada hardware is unavailable.

Hardware absence is an external validation limitation. It is not a software defect and must not be reported as a failed software task.

## Required status semantics

Hardware-only acceptance uses these machine-readable states:

- `not_requested`: no physical-only scenario is in the requested validation scope.
- `deferred_external_hardware`: physical-only scenarios exist but no physical device is available.
- `ready`: a physical backend is present and the requested physical scenarios are runnable.
- `verified`: physical scenarios ran at physical evidence fidelity and passed.
- `failed`: physical scenarios were runnable and evaluated but did not achieve physical certification.
- `blocked`: hardware is present but another prerequisite prevents physical validation.

`deferred_external_hardware` must never be converted to PASS, FAIL, or `hardware_certified=true` merely to close a software milestone.

## Software completion boundary

Software acceptance is independent of physical certification.

When all requested non-hardware scenarios pass and the only remaining unavailable scope is physical-only validation, the correct project state is:

- software/virtual scope: PASS for the evidence fidelity actually exercised;
- physical hardware scope: `deferred_external_hardware`;
- physical certification: false.

The absence of hardware must not block unrelated software lanes, knowledge normalization, deterministic compiler work, diagnostics, reporting, replay tests, fault injection, or virtual regression.

## Evidence ceiling

Evidence may never be promoted above the backend that produced it.

- behavior model evidence does not become vendor-OS evidence;
- software-controller evidence does not become forwarding-plane evidence;
- virtual-appliance evidence does not become physical-device evidence;
- vendor documentation does not prove physical runtime behavior by itself.

Physical-only claims include, at minimum, ASIC forwarding fidelity, line-rate throughput, PoE electrical negotiation, real RF/roaming behavior, thermal behavior, optical margin, bootloader/watchdog behavior, and physical-device performance.

## VLAB.10 interpretation

`VLAB.10 Run hardware-in-the-loop acceptance when physical devices become available` remains open while physical hardware is unavailable.

Its open state is classified as `deferred_external_hardware`, not as a software failure and not as an implementation blocker for the remaining software/virtual scope.

When suitable hardware becomes available, the same deterministic test plan must be re-run through a `PHYSICAL_DEVICE` backend and only successful physical-fidelity evidence may transition the hardware state to `verified`.

## Implementation

`src/router_configuration/hardware_acceptance.py` provides the deterministic status classifier and validation-scope summary used to keep software acceptance separate from physical certification.

The policy is fail-closed: no code path introduced here authorizes production writes or creates physical certification without physical evidence.
