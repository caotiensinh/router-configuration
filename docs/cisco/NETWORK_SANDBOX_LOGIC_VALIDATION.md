# Cisco logic validation with Network_Sandbox_Runtime

Status: **simulation-only engineering evidence; not live IOS XE acceptance**

## Qualified runtime

- Runtime repository: `caotiensinh/Network_Sandbox_Runtime`
- Runtime SHA: `e933712b9add6ee089fb57bddc014aab945b1fd5`
- `NetworkRuntime.snapshot()` blob: `4172bceb55665b9595ae7d9d8dd1b3fb789104e2`
- GitHub Actions run: `35172921884`
- Self-hosted CI rerun attempt: `2`
- Rerun job: `105060398790`
- Result: `SUCCESS`

The exact-SHA rerun passed the Network Sandbox CI suite, including Cisco IOS XE
vendor-contract checks, L2/snapshot behavior, snapshot replay, chaos/fault
qualification, packet evidence, and related regression lanes.

## Boundary

The adapter in
`src/router_configuration/vendors/cisco/network_sandbox_adapter.py` consumes
the public `NetworkRuntime.snapshot()` contract directly. It **does not**
translate simulated data into fake IOS XE YANG observations and it **does not**
call the live C05/C06 normalizers with fabricated schema inventory.

Simulation evidence remains bound by
`src/router_configuration/vendors/cisco/simulation_evidence.py`:

- physical validation remains false;
- production validation remains false;
- production writes remain unauthorized;
- canonical acceptance is never promoted;
- claimed canonical acceptance gates remain empty.

## Gate classification

| Gate | Simulation result | Remaining live requirement |
|---|---|---|
| C05 router normalized state | `PARTIAL_SIMULATION_PASS` | Live IOS XE YANG inventory, interface admin/oper state, IPv6 operational state |
| C06 switch normalized state | `PARTIAL_SIMULATION_PASS` | Live IOS XE YANG inventory, VLAN operational state, MAC table, STP operational state |
| C10 rollback/recovery | `SIMULATION_PASS` when a fault changes state and exact canonical state is restored | Live IOS XE rollback/recovery evidence |

C05 and C06 are intentionally partial because the current Network Sandbox
snapshot contract exposes configured IPv4 interfaces/routes and L2
access/trunk/native/allowed VLAN semantics, but not the listed IOS XE
operational/YANG surfaces.

C10 simulation logic requires both:

1. the injected fault must produce a different canonical snapshot; and
2. the recovered snapshot must exactly match the pre-fault canonical snapshot.

A no-op fault or incomplete restore fails the simulation gate.

## Hard blockers that this runtime cannot replace

The Network Sandbox cannot replace:

- C03 live IOS XE NETCONF evidence;
- C04 live IOS XE RESTCONF evidence;
- C08 accepted human approval;
- C09 licensed/live virtual IOS XE acceptance;
- C11 physical Cisco hardware evidence;
- C12 production deployment and final handover.

Those remain explicit external dependencies rather than reasons to stop other
testable work.

## Canonical progress

This work improves simulation readiness and evidence quality only. It does not
change `CISCO_PROGRESS.json`; canonical Cisco progress remains **79/100** until
the required live/human/physical/production evidence is obtained.
