# Omada / JetStream Trunk and Tagged VLAN Configuration

**Task:** 4.06 — Trunk/tagged VLAN configuration  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the current official trunk/tagged VLAN evidence scope

## Parallel-lane execution

Phase 4.06 was decomposed into **10 independent read-only evidence lanes**: CLI tagged syntax, standalone GUI, Controller trunk/uplink, tagged-set semantics, native/PVID separation, read-back, management-path risk, rollback/persistence, applicability/version, and validation. One serialized integration lane owns the artifacts.

The repository's 500-lane scheduler still reports assignment capacity rather than worker count; this work does **not** claim ten external worker processes.

## Canonical trunk model

A trunk/uplink is normalized as an exact VLAN membership design, not as the shortcut “all VLANs”.

For the official generic JetStream CLI example, the router-facing port is configured with:

```text
switchport general allowed vlan 20,30,40 tagged
```

The guide's read-back then shows VLANs 20, 30, and 40 with `Egress-rule: Tagged`, while the same port still has **PVID 1**. This proves that the **tagged VLAN set and native/PVID state are separate fields**.

## Standalone GUI

The Smart/Managed standalone example uses the same separation: the inter-switch/uplink port is **Tagged** in VLANs 10, 20, and 30 while its PVID remains 1.

Therefore the compiler must never treat “add VLAN X tagged” as an implicit PVID/native-VLAN change.

## Controller mode

The current Omada Controller VLAN guide documents a router uplink where:

- VLAN 1 is native/untagged.
- VLANs 10 and 20 are tagged.
- When a VLAN is created, an unselected port that remains in **Trunk** mode automatically carries that VLAN as tagged traffic in the cited workflow.

That automatic behavior is **Controller-workflow scoped**. It is not promoted into a generic rule that every Trunk port on every switch carries every VLAN.

The cited workflow states Omada Controller **v6.0+** and the documented Omada Access / Access Plus / Access Pro / Access Max / Aggregation / Campus switch classes.

## Read-back and PASS criteria

CLI read-back:

```text
show interface switchport
show interface switchport <exact-interface>
```

PASS requires:

1. every intended VLAN is present on the exact target port;
2. every intended trunk VLAN has the expected `Tagged` egress rule;
3. native/PVID state matches the intended design and did not change unintentionally;
4. required router/controller/management reachability remains acceptable.

A partial tagged set is not PASS.

## VLAN 1 and native-VLAN boundary

The generic CLI guide configures tagged VLANs first and handles removal of VLAN 1 in a **separate section**. Task 4.06 therefore does not silently generate:

```text
no switchport general allowed vlan 1
```

Membership removal/default-VLAN behavior remains **4.07**.

Likewise, task 4.06 does not synthesize a native/PVID change solely because a port is called a trunk.

## Safe transaction

1. Resolve exact model + hardware revision + region + firmware + management mode + port.
2. Verify every target VLAN exists.
3. Read current tagged/untagged/non-member membership and native/PVID state.
4. Detect router/controller/management-uplink dependency and preserve a verified recovery path.
5. Confirm exact write applicability/privilege and obtain production-write approval.
6. Apply only the intended tagged-membership delta.
7. Read back every intended tagged VLAN plus native/PVID.
8. Verify required uplink and management reachability.
9. Persist verified standalone CLI running state through the **4.02 save contract** when durability is required.

## Rollback and deferrals

Rollback restores the exact pre-change tagged set plus native/PVID and other affected membership state. It does not assume “all VLANs”, VLAN 1, or an empty tagged set.

LAG/LACP construction remains **4.10**. VLAN membership/removal/default-VLAN semantics remain **4.07**. VLAN interface / switch management IP remains **4.08**.

## Official sources

1. TP-Link / Omada — **Typical CLI Configuration Examples for TP-Link Omada / JetStream Switch**.  
   `https://support.omadanetworks.com/kr/document/13117/`
2. TP-Link / Omada — **How to Configure 802.1Q VLAN on Smart and Managed Switches Using the New GUI**.  
   `https://support.omadanetworks.com/en/document/12981/`
3. TP-Link / Omada — **How to Configure 802.1Q VLAN on Omada Agile/Easy Managed Switches in Standalone Mode**, 2026-07-25.  
   `https://support.omadanetworks.com/en/document/129217/`
4. TP-Link / Omada — **How to Configure 802.1Q VLAN on Omada Switches in Controller Mode**, 2024-07-11.  
   `https://support.omadanetworks.com/en/document/13215/`

## Closure

**4.06 = COMPLETE** for official trunk/tagged VLAN semantics with exact tagged-set, native/PVID separation, mode boundaries, read-back, uplink protection, rollback and persistence gates retained.

**Next:** 4.07 — VLAN membership/removal/default VLAN behavior.
