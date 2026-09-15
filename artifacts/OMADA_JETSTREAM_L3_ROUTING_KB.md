# Omada / JetStream L3 Routing Knowledge

**Task:** 4.17  
**Status:** COMPLETE candidate for current official evidence scope  
**Observed:** 2026-09-16

## Normalized behavior

The 2026 Omada switch-controller guide exposes per-switch static routing under **Devices > Device List > switch > Manage Device > Config > Routing > Static Route**. A route has explicit enable state, IP version, destination prefix, next hop and distance. The cited guide allows IPv4 and IPv6; distance is 1–255 and 255 is described as unreachable.

Routing state is not inferred from configuration acceptance. The controller Network View exposes routing-table information and must be used as operational read-back. The same 6.1.0 guide exposes VRF and OSPF only for certain models, so those capabilities are fail-closed behind exact model/hardware/firmware/controller/runtime checks.

## Safety

Before any routing mutation, snapshot the active route set, connected paths, management route and recovery path. Reject an unreachable next hop, an unsourced L3 capability, or a management/default-route mutation without independent recovery. `Apply` is only `EXECUTED_UNVERIFIED`.

PASS requires exact route read-back, expected routing-table state, next-hop reachability, intended positive traffic, unrelated negative/control traffic, and continued controller/management reachability.

## Rollback

Restore the exact pre-change route set and L3 feature state. Re-read the routing table and prove management plus representative data-plane reachability before persistence.

## Official sources

1. TP-Link / Omada, **Manage Switches via the Omada Controller**, REV6.1.0, 2026-02-28, routing pages visually verified (PDF pages 18–19 in the retrieved file).
2. TP-Link, **Omada SDN Controller User Guide — Configure the Network with Omada SDN Controller**, current web guide.

## Closure

**4.17 = COMPLETE candidate** for current official evidence scope. Durable promotion still requires Library read-back, exact repository bytes, main fast-forward/concurrency checks, CI and Governance PASS.
