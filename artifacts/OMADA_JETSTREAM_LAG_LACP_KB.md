# Omada / JetStream LAG and LACP

**Task:** 4.10 — LAG/LACP  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the current official LAG/LACP evidence scope

## Parallel-lane execution

Phase 4.10 uses **12 independent read-only evidence lanes**: concepts/static-vs-LACP, CLI group construction, CLI LACP controls, hash/load balancing, standalone GUI, Controller V6, member compatibility, VLAN/STP dependency, operational read-back, topology/management safety, rollback/persistence, and applicability/validation. One serialized integration lane owns the artifacts.

The repository's 500-lane capacity is an assignment namespace, **not a claim of twelve external workers**.

## Canonical model

A **LAG** is one logical interface built from several physical links. The current vendor material documents two main construction modes:

- **Static LAG** — administratively fixed membership.
- **LACP** — dynamic aggregation using LACP protocol exchange, with **Active** and **Passive** port modes.

The automation must keep the physical-member plane and the logical-LAG plane separate. Correct physical membership alone is not PASS if the logical LAG has the wrong VLAN/STP state or the LACP partner state is not operational.

## 2026 CLI normalization

The May 2026 **Managed Switches CLI Reference Guide REV2.0.0**, Chapter 17, documents member aggregation with:

```text
channel-group <GROUP_ID> mode { on | active | passive }
no channel-group
```

`on` is static LAG; `active` and `passive` are LACP modes.

The guide publishes source-scoped group-number ranges of:

- `1..8` for L2/L2+ switches;
- `1..64` for L3 access switches;
- `1..120` for L3 aggregation switches.

These ranges do **not** prove the exact capacity of every model. Exact model/firmware/member-count limits remain execution gates.

### Hash / load balancing

```text
port-channel load-balance { src-mac | dst-mac | src-dst-mac | src-ip | dst-ip | src-dst-ip }
no port-channel load-balance
```

The cited CLI default is `src-dst-mac`.

A hash algorithm determines how traffic is distributed among eligible members. It does **not** prove that one individual flow can consume the sum of all physical-link bandwidth.

### LACP controls

```text
lacp system-priority <0..65535>
lacp port-priority <0..65535>
lacp timeout { long | short }
```

The cited defaults for system and port priority are `32768`; LACP timeout defaults to `long`.

Important CLI boundaries:

- `lacp port-priority` is published in the cited reference for `gigabitEthernet` / `interface range gigabitEthernet`; do not broaden it without exact evidence.
- `lacp timeout` is valid only on LACP-enabled ports.
- `lacp timeout` cannot be configured in Port-channel view in the cited reference.
- When applied through an interface range, timeout changes only the ports in that range that currently have LACP enabled.
- Converting/removing the LACP member resets the cited timeout state back to its default.

## Read-back is the PASS gate

Canonical CLI evidence surfaces are:

```text
show etherchannel [<GROUP_ID>] { detail | summary }
show etherchannel load-balance
show lacp [<GROUP_ID>] { internal | neighbor }
show lacp sys-id
```

PASS requires:

1. the intended LAG exists;
2. every intended physical member is present with the expected operational state;
3. the intended static/LACP mode is effective;
4. for LACP, local/internal and neighbor/partner state are coherent;
5. the hash algorithm matches intent if it was changed;
6. logical-LAG VLAN/STP state remains correct;
7. management/controller reachability remains healthy.

A successful `channel-group` command or Controller Apply without this operational evidence is `EXECUTED_UNVERIFIED`, not PASS.

## Standalone Smart/Managed behavior

The current 2026 standalone LACP guide says not to connect all parallel inter-switch cables before LAG is configured, because doing so can create a broadcast storm. Configure the aggregation first, then close the redundant physical path.

The same guide describes Active and Passive LACP behavior and recommends one side Active and the other Passive. It also states that LAG should be configured before dependent features such as VLAN, STP and QoS, and that in the cited scope the LAG group's configuration has higher priority than member-port configuration.

Therefore the compiler must discover and verify the **logical LAG interface** rather than blindly applying VLAN/STP changes to individual members.

## Controller V6+ behavior

Current Controller guidance applies the cited workflow to **Omada Smart, L2+ and L3 switches with Controller V6+**.

The documented workflow:

1. begin with a single inter-switch cable;
2. configure aggregation on both switches;
3. select the peer member port(s), LAG ID and LACP mode;
4. ensure both ends use the same LAG mode;
5. for LACP, current guidance suggests one side Active and the other Passive;
6. connect the additional cable(s);
7. verify `Ports > LAG` status and LAG statistics/rate.

The same current guide calls out member **speed and duplex** matching when troubleshooting a failed LAG.

## Member compatibility

Member compatibility is a hard precondition, not a post-failure guess.

At minimum, resolve:

- exact port/media capability on each side;
- group ID/mode on both peers;
- member speed/duplex compatibility;
- feature conflicts;
- logical-LAG VLAN/STP state.

The current Agile/Easy Managed guide adds stronger family-scoped constraints such as matching member count, speed/duplex, flow control and QoS, and disallowing mirrored/mirroring ports in a LAG. Those constraints remain **Agile/Easy scoped** and are not generalized to every JetStream/Omada switch.

## VLAN and STP dependency

Once ports are members of a LAG, VLAN/STP configuration can be authoritative on the logical group in the cited standalone workflows. Task 4.10 therefore does not treat the members as independent links after aggregation.

Task **4.09** still owns STP semantics. Task **4.04–4.08** still own VLAN/PVID/SVI semantics. 4.10 only normalizes how those state planes depend on the logical LAG.

**M-LAG/MLAG is not ordinary LAG/LACP** and remains a separate feature boundary.

## Safety contract

1. Resolve exact model/hardware/firmware/management mode/Controller version and every intended member.
2. Snapshot current speed/duplex, membership, LACP state, VLAN/PVID and STP state on both ends.
3. Detect whether the current management/controller path traverses the target link or LAG.
4. Verify peer mode/group design and member compatibility.
5. Keep redundant links physically open if unaggregated parallel links would create a loop.
6. Obtain production-write approval.
7. Apply only the intended member/group/protocol delta.
8. Read back every member and LACP partner state.
9. Verify logical-LAG VLAN/STP state and management reachability.
10. Persist standalone CLI state through the **4.02 save contract** only after running-state verification.

## Rollback

Rollback restores the exact observed pre-change member group/mode, speed/duplex, LACP priorities/timeouts, hash algorithm, logical-LAG VLAN/STP state and management dependency.

Removing the entire LAG is **not** a generic rollback when the LAG carries live traffic or management.

## CLI PDF visual-verification note

The official 2026 PDF text was parsed successfully. Screenshot calls were attempted for the relevant Chapter 17 pages, but the screenshot backend returned cache-miss. This artifact therefore does **not** claim visual screenshot verification; exact runtime applicability remains mandatory.

## Official sources

1. TP-Link / Omada — **CLI Reference Guide — Managed Switches**, REV2.0.0, May 2026.  
   `https://static.tp-link.com/upload/manual/2026/202607/20260724/1900003588_Managed%20SwitchMulti-model_CLI.pdf`
2. TP-Link / Omada — **How to Configure LACP on Smart/Managed Switches**, 2026-08-10.  
   `https://support.omadanetworks.com/us/document/12920/`
3. TP-Link / Omada — **How to configure LAG (LACP) on Omada Switches via Omada Controller**, 2026-08-20.  
   `https://support.omadanetworks.com/en/document/13148/`
4. TP-Link / Omada — **How to Configure 802.1Q VLAN for LAG Ports on Smart and Managed Switches Using the New GUI**, 2026-07-22.  
   `https://support.omadanetworks.com/au/document/12996/`
5. TP-Link / Omada — **Omada Agile (Easy Managed) Switch (New VI)_User Guide**.  
   `https://support.omadanetworks.com/en/document/46791/`

## Closure

**4.10 = COMPLETE** for the current official LAG/LACP evidence scope with static/LACP construction, member compatibility, hash behavior, priorities/timeouts, logical-interface dependencies, operational verification, topology safety, rollback and persistence gates retained.

**Next:** 4.11 — IGMP Snooping / Querier / Fast Leave.
