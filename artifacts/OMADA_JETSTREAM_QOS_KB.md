# Omada / JetStream Quality of Service (QoS)

**Task:** 4.13 — QoS  
**Observed:** 2026-09-15  
**Status:** COMPLETE for current official managed-switch QoS evidence scope

## Execution model

Phase 4.13 used **16 read-only evidence lanes** plus one serialized integration lane. Evidence methods: current Omada web guides, parsed official CLI PDF text, required PDF screenshot attempts, Library dependency cross-checks, and GitHub byte-hash/CI gates. The 500-lane namespace is capacity, not a claim of external worker processes.

## Normalized state

Keep these planes separate: trust/classification, 802.1p/DSCP mapping and remap, queue selection, scheduler, queue minimum bandwidth, ingress/egress bandwidth control, Controller QoS rule objects, and TCAM/resource state. Configuration acceptance alone is not PASS.

The May 2026 Managed Switches CLI Reference documents `qos trust mode { dot1p | dscp | untrust }`, `qos port-priority <0..7>`, `qos cos-map`, `qos dot1p-remap`, `qos dscp-map`, queue scheduling, queue minimum bandwidth on supported devices, and QoS read-back. Eight queues are exposed as **TC0..TC7**. SP can starve lower queues; WRR uses weights; cited scopes support mixed SP+WRR. Scheduler scope is model-dependent: global on some devices and per-interface on others.

The official PDF contains a DSCP-remap syntax inconsistency between formal syntax text and examples. Exact writes therefore remain blocked until runtime CLI help/read-back resolves the exact-device syntax.

Current standalone guidance distinguishes Port Priority, Trust 802.1p, and Trust DSCP. 802.1p is L2 VLAN-tag priority `0..7`; DSCP is IP-header priority `0..63`. Current Controller 6.1 guidance says adoption automatically pushes **trust DSCP** in its cited scope and exposes Switch QoS with DSCP mapping, queue scheduling, and Network/Port/Custom rules. Controller objects are not blindly translated into standalone CLI.

Chapter 64 bandwidth and storm-control features are adjacent but separate from QoS classification. Family-scoped conflicts such as ingress rate control versus storm control are not generalized without exact-device evidence. QoS/OUI and ACL/QoS resource interactions, VLAN tagging, and logical-LAG authority are verified independently.

## PASS / rollback

Before writes, resolve exact model/hardware/region/firmware/management mode/Controller version, target port or LAG, global-vs-interface scheduler scope, current trust/maps/remaps/scheduler/weights/rate limits, Controller rules, and TCAM/resource conflicts. Analyze SP starvation and critical management/control traffic.

PASS requires read-back plus representative traffic/congestion behavior where feasible, no unintended starvation/rate drop, and healthy management/Controller reachability. Apply/command acceptance alone is `EXECUTED_UNVERIFIED`. Standalone persistence follows task 4.02 only after running-state verification.

Rollback restores exact pre-change trust, port priority, mappings/remaps, queue modes/weights/minimum bandwidth, VLAN QoS hooks, rate limits, Controller rule bindings/remark state, and resource assumptions. Generic reset-all QoS actions are not rollback.

Required PDF screenshots returned cache-miss; parsed official PDF text was still used. This artifact records `visual_screenshot_verified=false` and keeps exact runtime applicability mandatory.

## Official sources

1. TP-Link / Omada — **CLI Reference Guide — Managed Switches**, REV2.0.0, May 2026.
2. **How to configure QoS on Omada Switches in Standalone Mode**, 2026-04-04 — `https://support.omadanetworks.com/us/document/106188/`
3. **How to Configure Switch QoS in Controller Mode**, 2026-08-17 — `https://support.omadanetworks.com/en/document/112040/?app=web`
4. **Omada Controller User Guide_V6.0** — `https://support.omadanetworks.com/en/document/111217/`
5. **How to configure Class of Service (CoS) through Omada Controller**, 2024-10-22 — `https://support.omadanetworks.com/en/document/13255/?app=deco`
6. **Omada Agile (Easy Managed) Switch (New VI)_User Guide** — `https://support.omadanetworks.com/en/document/46791/`

## Closure

**4.13 = COMPLETE** for the current official switch-QoS evidence scope. **Next: 4.14 — Port security / 802.1X / authentication.**
