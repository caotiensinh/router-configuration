# Omada / JetStream Access-Port and PVID Configuration

**Task:** 4.05 — Access-port/PVID configuration  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the current official access-port/PVID evidence scope

## Parallel-lane execution

Phase 4.05 was decomposed into **9 independent read-only research/review lanes** (CLI, standalone GUI, Controller, PVID semantics, read-back, rollback/persistence, management-path risk, applicability, and validation) followed by **1 serialized integration lane**.

The repository's 500-lane scheduler contract is respected: these are assignment slots, **not a claim that nine external worker processes were running**. Parallel research never grants concurrent write ownership.

## Canonical access-port model

An access-port change is **not just a PVID write**.

For the official generic JetStream CLI example, the common access-port configuration is a pair:

```text
switchport general allowed vlan <VLAN_ID> untagged
switchport pvid <VLAN_ID>
```

The first operation establishes untagged egress membership for the VLAN. The second establishes the port PVID used for untagged ingress classification. These are separate state fields and both must be read back before PASS.

## CLI workflow and verification

The official JetStream CLI example creates the VLAN first, enters the exact interface, adds it to the VLAN as `untagged`, then sets the PVID.

Canonical read-back:

```text
show interface switchport
show interface switchport <exact-interface>
```

The output exposes at least the port **PVID** and VLAN membership / egress-rule information needed to verify the access-port state.

### Important boundary: do not silently remove VLAN 1

The vendor's access-port examples for ports 2–4 add the intended untagged VLAN and set the PVID, but **do not remove VLAN 1** in that step.

Therefore task 4.05 does **not** synthesize:

```text
no switchport general allowed vlan 1
```

Default-VLAN membership/removal behavior remains **4.07**.

## Standalone GUI

The current Smart/Managed GUI guide uses the same two-state idea:

1. create/select the VLAN and make the intended client port an untagged member;
2. open Port Config and set the port PVID to that VLAN;
3. apply/save;
4. re-read VLAN membership and PVID before PASS.

GUI evidence does not authorize CLI syntax.

## Controller mode

The current Controller VLAN guide lets administrators select client-facing ports as **Access** ports. Its verification guidance treats the client-facing VLAN as native/untagged and verifies that a client receives an address from the expected VLAN subnet.

The cited Controller workflow currently states applicability to Omada Access / Access Plus / Access Pro / Access Max / Aggregation / Campus switch classes with **Omada Controller v6.0+**. This is Controller evidence only; it is not copied into standalone CLI behavior.

## Safe transaction

1. Resolve exact model + hardware revision + region + firmware + management mode + port.
2. Verify the target VLAN already exists in the active management plane.
3. Read current PVID and tagged/untagged/non-member membership.
4. Detect whether the target carries the active management/controller path.
5. Confirm exact write applicability and privilege, then obtain production-write approval.
6. Apply only the intended access-VLAN membership/PVID delta.
7. Read back both PVID and untagged membership.
8. Verify required link/client behavior.
9. If durable standalone CLI state is required, apply the **4.02 running → startup save contract** only after running-state verification.

A command/UI action that was accepted but cannot be read back semantically is `EXECUTED_UNVERIFIED`, not PASS.

## Rollback

Rollback must restore the **exact observed pre-change PVID and membership**, not an assumed VLAN 1/default state. If the target port is on the management path, a verified recovery path is mandatory before mutation.

For multi-port changes, verify every port independently; partial range execution remains a mixed result, never atomic PASS.

## Official sources

1. TP-Link / Omada — **Typical CLI Configuration Examples for TP-Link Omada / JetStream Switch** (current 2026 publication surface).  
   `https://support.omadanetworks.com/kr/document/13117/`
2. TP-Link / Omada — **How to Configure 802.1Q VLAN on Smart and Managed Switches Using the New GUI**, 2026-08-13.  
   `https://support.omadanetworks.com/en/document/12981/`
3. TP-Link / Omada — **Omada Switch DHCP Relay Configuration Guide**.  
   `https://support.omadanetworks.com/en/document/13175/`
4. TP-Link / Omada — **How to Configure 802.1Q VLAN on Omada Switches in Controller Mode**.  
   `https://support.omadanetworks.com/en/document/13215/`
5. TP-Link / Omada — **How to edit switch port configuration in Omada Network v6.2.10**.  
   `https://support.omadanetworks.com/au/document/109105/`

## Closure

**4.05 = COMPLETE** for official access-port/PVID semantics with mode separation, read-back, management-path protection, rollback and persistence gates retained.

**Next:** 4.06 — Trunk/tagged VLAN configuration.
