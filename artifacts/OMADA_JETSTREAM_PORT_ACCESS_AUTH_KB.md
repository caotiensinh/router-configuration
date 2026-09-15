# Omada / JetStream Port Security and 802.1X

**Task:** 4.14 — Port security / 802.1X / authentication  
**Status:** COMPLETE for current official managed-switch port-access evidence scope

## Model

Phase 4.14 uses **16 read-only evidence lanes** plus one serialized integration lane. Port Security, 802.1X authorization, MAC-Based port method, MAB, RADIUS, Guest VLAN, dynamic VLAN assignment and session state remain separate.

**Port Security is MAC-learning/count enforcement, not authentication.** Current 2026 guidance says it cannot coexist with 802.1X on the same port and cannot be enabled on a LAG member. The cited current guide documents a `0..64` learned-MAC limit (default 64), `forward/drop/disable` behavior, and dynamic/static/permanent persistence. Sticky behavior is described, but exact sticky CLI syntax remains runtime-gated because the shown syntax is not fully aligned with the explanation.

## 802.1X / MAB

The 2026 CLI reference documents global `dot1x system-auth-control`, PAP/EAP, per-port `dot1x`, `auto / authorized-force / unauthorized-force`, `mac-based / port-based`, MAB, timers, Guest VLAN, VLAN Assignment, and `show dot1x ...` read-back.

`authorized-force` and `unauthorized-force` are explicit administrative states—not proof of automatic RADIUS-down fail-open/fail-closed behavior.

Controller MAC-Based means each client authenticates individually. Port-Based can authorize other clients after one client succeeds. MAB is distinct: for non-802.1X endpoints, the cited workflow sends the client MAC to RADIUS as username/password.

## RADIUS / failure boundary

Current Controller guidance supports up to four authentication servers so another can continue when one fails or is unreachable. `802.1X Only`, `MAB Only`, and `Both` are distinct; in cited `Both` behavior, MAB starts/retries every 30 seconds when 802.1X is not initiated or fails. Guest VLAN handles failed/timed-out authentication where the required version/firmware supports it.

The normalized sources **do not establish a universal automatic allow policy when all RADIUS servers are unreachable**. Automation blocks assumed fail-open until exact device/firmware/runtime evidence proves it.

RADIUS VLAN Assignment may create/add VLAN membership and change PVID in cited CLI scope. It therefore requires explicit intent, VLAN/PVID snapshot, post-auth verification and exact rollback.

## PASS / rollback

PASS requires exact configuration read-back plus actual session behavior: intended authorized clients pass; unauthorized clients are denied or enter only an explicitly intended Guest VLAN; MAB applies only to intended endpoints; configured RADIUS redundancy works; management/uplink/Controller paths stay healthy. Apply alone is `EXECUTED_UNVERIFIED`.

Troubleshooting verifies global/port 802.1X, RADIUS profile/server group/IP/shared secret/port, reachability, MAB/MAC format, ACL/IMPB/MAC-filter conflicts and client method. `radtest` distinguishes Access-Accept, Access-Reject and no-reply/connectivity cases.

Rollback restores exact Port Security, 802.1X, MAB, timer, Guest VLAN, RADIUS association, and any explicitly modified VLAN/PVID state. Generic disable-all or authorized-force-all is not rollback.

Required CLI PDF screenshot attempts returned cache-miss; parsed official PDF text was used and `visual_screenshot_verified=false` is retained.

## Official sources

1. TP-Link / Omada, **CLI Reference Guide — Managed Switches**, REV2.0.0, May 2026.
2. **How to configure Port Security on Omada Switches** — `https://support.omadanetworks.com/us/document/116672/?app=omada`
3. **How to Build an 802.1X Access Authentication System Using Switches in Omada Controller** — `https://support.omadanetworks.com/en/document/12898/`
4. **How to Troubleshoot 802.1X (Dot1X) Authentication Failures on Omada Switches** — `https://support.omadanetworks.com/us/document/13180/?app=tether`
5. **How to Troubleshoot RADIUS Authentication Failures on Omada Networks** — `https://support.omadanetworks.com/en/document/13177/?app=deco`
6. **Omada Controller User Guide_V6.0** — `https://support.omadanetworks.com/en/document/111217/`

**4.14 = COMPLETE. Next: 4.15 — LLDP / discovery.**
