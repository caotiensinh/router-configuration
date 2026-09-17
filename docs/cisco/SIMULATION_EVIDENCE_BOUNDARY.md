# Cisco simulation evidence boundary

## Purpose

This repository may use a simulator or emulation runtime when physical Cisco IOS XE hardware is not available. Simulation is useful and valid evidence for the logic that was actually exercised, but it is not evidence that the same behavior has been verified on a physical Cisco device or in production.

The required reporting rule is therefore explicit:

> **Simulation/logic validation only. Physical Cisco hardware validation was not performed because physical hardware is unavailable in this environment.**

The absence of physical hardware is a test-scope limitation, not a reason to relabel simulation as physical evidence.

## Evidence classes

| Evidence class | What it may prove | What it must not claim |
| --- | --- | --- |
| deterministic simulation | configuration/state-machine logic, validation rules, intended transitions, deterministic fault/recovery behavior inside the simulator | real Cisco IOS XE execution, real hardware behavior, production readiness |
| realistic/open emulation | real packets/processes in the declared isolated backend, plus the simulator/emulator behavior actually observed | physical Cisco hardware or exact proprietary IOS XE behavior unless independently validated |
| live virtual IOS XE appliance | the behavior observed on the identified licensed virtual IOS XE target and bounded C09 scenarios | physical hardware verification or production deployment |
| physical Cisco evidence | only the behavior actually observed on an identified physical device under the C11 contract | production write authorization unless separately granted |
| production evidence | only an explicitly authorized deployment/readback/verification run | broader platform/device claims not supported by that evidence |

## Machine-readable invariant

Simulation evidence produced through `simulation_evidence.py` must contain all of these facts:

- `evidence_scope = simulation_logic_only`
- `physical_validation_performed = false`
- `physical_device_verified = false`
- `physical_validation_blocked_reason = physical_hardware_unavailable`
- `production_validation_performed = false`
- `production_write_authorized = false`
- `canonical_acceptance_promoted = false`
- the explicit physical-hardware limitation disclosure

The validator fails closed if a simulation record attempts to elevate itself into canonical acceptance evidence.

## Reproducible cross-repository provenance

When evidence is produced with `caotiensinh/Network_Sandbox_Runtime`, a successful simulation result is not sufficient by itself. The evidence record must bind the exact inputs and state transition that produced the result.

The fail-closed minimum provenance is:

```text
router_configuration_sha
network_sandbox_sha
simulation_profile
scenario_digest
input_digest
pre_state_digest
post_state_digest
environment_kind
```

Both Git revisions must be full 40-character source SHAs. The scenario, input, pre-state and post-state values must be 64-character SHA-256 digests. `router_configuration_sha` must match the legacy `source_sha` binding and `network_sandbox_sha` must match `simulator.source_sha`; contradictory provenance is rejected.

`environment_kind` is restricted to simulation/emulation classes accepted by the simulation evidence validator. A simulation record cannot relabel itself as physical hardware or production evidence.

The complete record is itself protected by `record_sha256`, so changing any provenance field after generation invalidates the evidence.

## Canonical acceptance boundary

Simulation evidence does **not** satisfy canonical live, human, physical, or production acceptance gates merely because the simulated logic passes. In particular it cannot satisfy:

- `C11.physical_evidence`
- `C11.physical_repository_acceptance`
- `C12.verified_production_deployment`
- `C12.final_handover_acceptance`

The current physical verifier remains a separate boundary and requires real physical evidence. A future simulation-readiness measurement may report simulation completion separately, but it must not rewrite or dilute the canonical 79/21 acceptance weights without an explicit governed measurement-policy change.

## Network Sandbox Runtime

When `caotiensinh/Network_Sandbox_Runtime` is used as the lab backend, its evidence must retain the exact simulator source revision, the router-configuration source revision, the selected simulation profile, scenario/input digests, and pre/post-state digests. Tests should report only the fidelity actually exercised by that runtime. Logical, packet/event, or realistic open-backend success is valuable test evidence; it is not a statement that a physical Cisco product was tested.

## Required test wording

Tests and evidence reports that run without physical hardware should make the limitation visible to humans as well as machines. The standard disclosure is:

> Simulation/logic validation only. Physical Cisco hardware validation was not performed because physical hardware is unavailable in this environment.

This wording should remain present in generated simulation evidence even when every simulated scenario passes.
