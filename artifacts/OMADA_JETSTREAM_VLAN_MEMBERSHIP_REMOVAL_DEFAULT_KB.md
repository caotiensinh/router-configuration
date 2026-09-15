# Omada / JetStream VLAN Membership, Removal, and Default VLAN Behavior

**Task:** 4.07 — VLAN membership/removal/default VLAN behavior  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the current official VLAN membership/removal/default evidence scope

## Parallel-lane execution

Phase 4.07 uses **12 independent read-only evidence lanes**: CLI add/remove, VLAN-object deletion, generic VLAN-1 removal, Agile/Easy default-VLAN rules, Smart/Managed GUI membership, Controller membership, tagged↔untagged/non-member transitions, PVID dependency, read-back, management-path risk, rollback/persistence, and applicability/validation. One serialized integration lane owns the artifacts.

The repository's 500-lane scheduler is assignment capacity, **not worker count**; this work does not claim twelve external worker processes.

## Canonical membership model

Membership is not a boolean. A port may be `Tagged`, `Untagged`, or `Non-member`, and **PVID remains a separate ingress-classification field**.

For the official generic JetStream CLI example:

```text
switchport general allowed vlan <VLAN_LIST> tagged
switchport general allowed vlan <VLAN_LIST> untagged
no switchport general allowed vlan <VLAN_LIST>
```

The first two add/configure membership with an egress rule; the `no` form removes the port from the corresponding VLAN. Deleting the VLAN object itself is a distinct operation:

```text
no vlan <VLAN_ID>
```

A compiler must never collapse **remove one port from VLAN X** and **delete VLAN X** into the same action.

## VLAN 1 — explicit action, not hidden side effect

The generic CLI guide handles VLAN-1 removal in a **separate step** after trunk configuration:

```text
no switchport general allowed vlan 1
```

Therefore VLAN-1 removal is generated only when explicitly requested and exact applicability is verified. It is not silently appended to access-port or trunk configuration.

The generic guide's statement that switch ports are generally members of VLAN 1 is retained only as guide-scope behavior, not promoted into an exact-device invariant.

## Agile / Easy Managed default-VLAN rules

The current Agile/Easy Managed User Guide explicitly states, for that product scope:

- all ports are in VLAN 1 by default;
- a port may be removed from VLAN 1 only when it is also a member of another VLAN;
- removing a port from all current VLANs automatically returns it to VLAN 1;
- VLAN 1 cannot be deleted.

These are **source-scoped rules**. They are not copied to all JetStream/Omada managed switches.

The same guide states that PVID takes effect only when 802.1Q mode is enabled and that the corresponding VLAN must exist before a PVID can be specified.

## PVID/dependency safety

Removing membership and changing PVID are separate operations. If the requested removal or VLAN-object deletion affects the VLAN currently referenced by a port PVID, the system must **fail closed** until exact applicable post-removal behavior is known.

Likewise, VLAN-object deletion must first discover dependent port membership, PVID/native state, controller objects, and any VLAN interface / management-IP dependency. SVI/management-IP behavior remains **4.08** and is never cascade-deleted here.

## Read-back and PASS criteria

CLI read-back:

```text
show interface switchport
show interface switchport <exact-interface>
```

PASS requires the exact requested post-state to be read back per port and per VLAN, including the expected egress rule and unchanged/explicitly intended PVID/native state. Batch or range operations are verified independently; mixed results remain mixed.

## Safe transaction

1. Resolve exact model + hardware revision + region + firmware + management mode + port.
2. Read VLAN objects, current membership/egress state, and PVID/native state.
3. Resolve management/uplink, PVID, controller, and 4.08 interface/IP dependencies.
4. Confirm exact write applicability and privilege; obtain production-write approval.
5. Apply only the requested membership transition/removal or VLAN-object delete.
6. Re-read membership and PVID/native state; verify required reachability.
7. Persist verified standalone CLI running state through the **4.02 save contract** when durability is required.

An accepted command/UI action without semantic read-back is `EXECUTED_UNVERIFIED`, not PASS.

## Rollback

Rollback restores the **exact observed pre-change VLAN object, membership, and PVID/native state**. It does not assume VLAN 1, Non-member, or any other vendor default is the correct recovery target.

## Official sources

1. TP-Link / Omada — **Typical CLI Configuration Examples for TP-Link Omada / JetStream Switch**.  
   `https://support.omadanetworks.com/kr/document/13117/`
2. TP-Link / Omada — **Omada Agile (Easy Managed) Switch (New VI)_User Guide**.  
   `https://support.omadanetworks.com/en/document/46791/`
3. TP-Link / Omada — **How to Configure 802.1Q VLAN on Omada Agile/Easy Managed Switches in Standalone Mode**, 2026-07-25.  
   `https://support.omadanetworks.com/en/document/129217/`
4. TP-Link / Omada — **How to Configure 802.1Q VLAN on Smart and Managed Switches Using the New GUI**.  
   `https://support.omadanetworks.com/en/document/12981/`
5. TP-Link / Omada — **How to Configure 802.1Q VLAN on Omada Switches in Controller Mode**.  
   `https://support.omadanetworks.com/en/document/13215/`

## Closure

**4.07 = COMPLETE** for official VLAN membership/removal/default behavior with explicit VLAN-1 operations, source-scoped defaults, PVID/dependency gates, read-back, management-path protection, rollback and persistence retained.

**Next:** 4.08 — VLAN interface / switch management IP.
