# Omada / JetStream Access Control Lists (ACL)

**Task:** 4.12 — ACL  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the current official switch-ACL evidence scope

## Execution model

Phase 4.12 used **12 independent read-only evidence lanes** and one serialized integration lane. The 500-lane repository capacity is an assignment namespace, not a claim of external worker processes.

Four state planes stay separate: **ACL object/rules**, **binding**, **evaluation order**, and **hardware resource installation**. A valid ACL object is not PASS if it is unbound or cannot be installed in available TCAM.

## 2026 CLI normalization

The May 2026 Managed Switches CLI Reference Guide REV2.0.0, Chapter 78 documents:

```text
access-list create <ACL_ID> [ name <ACL_NAME> ]
```

Source-scoped ID ranges are MAC `0..499`, IPv4 `500..999`, Combined `1000..1499`, IPv6 `1500..1999`, and Packet Content `2000..2499` (certain devices only).

MAC ACLs include MAC masks, EtherType, 802.1p, VLAN and time range. IPv4 ACLs include IPv4 masks, DSCP/ToS/precedence, protocol/L4 ports, TCP flags, time range and VRF; fragment matching is capability-scoped. Combined ACLs join MAC/VLAN and IPv4/L4 fields. IPv6 and Packet Content remain exact-capability records; the cited CLI requires applicable `enterpriseV6` SDM state before IPv6 ACL binding.

The compiler always emits explicit `permit` or `deny` intent.

## Ordering is management-plane specific

Controller V6 Switch ACL evaluates rules top-down: **first match wins** and unmatched traffic is covered by **implicit Permit All**. Current scenario guidance therefore places narrow Permit exceptions above broad Deny rules.

Standalone CLI independently exposes:

```text
access-list mode action-stop
no access-list mode action-stop
```

With action-stop enabled, evaluation stops at the first matched ACL. With it disabled, later matching actions may override earlier matches in the cited CLI scope. **Controller first-match semantics must never be copied into standalone CLI without discovering the exact action-stop state.**

## Binding is required

```text
access-list bind <ACL> interface { vlan <VLAN_LIST> | fastEthernet <PORT_LIST> | gigabitEthernet <PORT_LIST> | ten-gigabitEthernet <PORT_LIST> }
```

The cited VLAN range is `1..4094`. Controller Switch ACL likewise takes effect only after binding to All Ports, Custom Ports, or a VLAN. Do not invent additional interface tokens from unrelated CLI chapters.

## Controller and standalone boundary

Controller V6 exposes `Network Config > Security > ACL > Switch ACL` with Permit/Deny, protocol, source/destination, time range, EtherType and optional Bi-Directional behavior; Bi-Directional creates a reverse rule in the cited guide.

The 2026 standalone Management VLAN guide uses `Security > Access Security > Access control` for IP-based management access such as HTTP/HTTPS. That is a **management-plane ACL example**, not proof that the object is identical to a Controller transit Switch ACL.

## TCAM / SDM resource gate

Current Omada Network v6.2.10+ guidance documents finite shared TCAM resources and templates including `omada`, `omada-enterpriseV4`, `omada-enterpriseV6`, and `omada-enterpriseMix` in supported scope. Rule creation does not prove hardware installation. SDM must never be changed automatically merely to make an ACL fit.

## PASS gate

Canonical CLI read-back includes:

```text
show access-list <ACL_ID_OR_NAME>
show access-list bind
show access-list status
show access-list <ACL_ID_OR_NAME> counter
```

PASS requires exact rules/order/policy, correct binding, adequate resource state, counters where meaningful, representative permitted traffic succeeding, intended denied traffic failing, and healthy management/Controller connectivity. Command/UI acceptance alone is `EXECUTED_UNVERIFIED`.

## Cross-feature boundary

The CLI exposes ACL action hooks for QoS remark/policing, mirroring and PBR redirect. Phase 4.12 records those dependencies only: QoS is **4.13**, PBR/routing is **4.17**, and authentication/port security is **4.14**.

## Management safety and rollback

Before broad Deny rules, discover existing order/evaluation mode, bindings and resources; identify the live management path; stage required management Permit exceptions; keep a recovery path; and obtain production-write approval. After change, test both positive and negative traffic and verify Controller/SSH/HTTPS reachability. Persist standalone CLI via the 4.02 save contract only after enforcement is verified.

Rollback restores the exact pre-change ACL objects, rule IDs/order, match/policy/log/time state, action-stop state, bindings, resource assumptions and management path. `delete all ACLs` and `permit all` are not generic rollback procedures.

## Evidence note

The official 2026 PDF text was parsed. Representative screenshot calls against Chapter 78 returned backend/cache errors, so this artifact **does not claim visual screenshot verification**; runtime applicability remains mandatory.

## Official sources

1. TP-Link / Omada — **CLI Reference Guide — Managed Switches**, REV2.0.0, May 2026.  
   `https://static.tp-link.com/upload/manual/2026/202607/20260724/1900003588_Managed%20SwitchMulti-model_CLI.pdf`
2. **Omada Controller User Guide_V6.0** — `https://support.omadanetworks.com/en/document/111217/`
3. **Recommended ACL Configurations on Omada Switch for Common Scenarios**, 2026-08-24 — `https://support.omadanetworks.com/en/document/13238/?app=wifi-toolkit`
4. **How to Configure Management VLAN on Omada Smart and Managed Switches Using the New GUI**, 2026-07-17 — `https://support.omadanetworks.com/us/document/13135/?app=t`
5. **What Is the SDM Template for Omada Switches Managed by an Omada Network**, 2026-08-17 — `https://support.omadanetworks.com/au/document/114354/?app=iframe`

## Closure

**4.12 = COMPLETE** for the current official switch-ACL evidence scope. **Next: 4.13 — QoS.**
