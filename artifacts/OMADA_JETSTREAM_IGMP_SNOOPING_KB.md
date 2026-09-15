# Omada / JetStream IGMP Snooping, Querier, and Fast Leave

**Task:** 4.11 — IGMP Snooping / Querier / Fast Leave  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the current official IPv4 IGMP Snooping evidence scope

## Parallel-lane execution

Phase 4.11 uses **12 independent read-only evidence lanes** covering concepts, global/VLAN/port CLI, Querier, Fast Leave, router ports/unknown multicast, static groups/Report Suppression, standalone GUI, current Controller, read-back/troubleshooting, safety/rollback, and applicability/validation. One serialized integration lane owns the artifacts.

The repository's 500-lane capacity is an assignment namespace, **not a claim of twelve external workers**.

## Keep the multicast state planes separate

IGMP Snooping is a **Layer-2 IPv4 multicast forwarding-control mechanism**. It is not PIM/multicast routing.

The automation must separately discover and verify:

1. global IGMP Snooping;
2. VLAN IGMP Snooping;
3. port/LAG IGMP Snooping;
4. IGMP version;
5. Querier/election state;
6. router-port state;
7. dynamic/static multicast group membership;
8. Fast Leave;
9. Report Suppression;
10. unknown-multicast forwarding policy.

Correct configuration in only one plane is not enough to declare PASS.

## 2026 CLI normalization

The May 2026 **Managed Switches CLI Reference Guide REV2.0.0**, Chapter 27, documents global enable and IGMP version:

```text
ip igmp snooping
no ip igmp snooping

ip igmp snooping version { v1 | v2 | v3 }
```

The cited global IGMP-version default is **v3**. The same CLI reference documents unknown multicast as Forward by default and exposes `ip igmp snooping drop-unknown` to change the global handling to discard.

VLAN-level enable/timers use:

```text
ip igmp snooping vlan-config <VLAN_LIST> [ rtime <router-time> | mtime <member-time> | ltime <leave-time> ]
```

The cited VLAN ID range is `1..4094`.

### Fast Leave and Report Suppression

```text
ip igmp snooping vlan-config <VLAN_LIST> immediate-leave
ip igmp snooping vlan-config <VLAN_LIST> report-suppression
```

Both are documented as disabled by default in the cited CLI reference.

Port/LAG Fast Leave is separate:

```text
interface <exact-interface>
ip igmp snooping immediate-leave
```

### Router ports and static multicast groups

Static router port:

```text
ip igmp snooping vlan-config <VLAN_LIST> rport interface { gigabitEthernet <PORT_LIST> | port-channel <PORT_CHANNEL_LIST> }
```

The CLI also exposes a separate **forbidden router-port** control. The command token is printed as `router-ports-forbidd`; the artifact preserves the vendor spelling rather than silently inventing a correction.

Static group membership:

```text
ip igmp snooping vlan-config <VLAN_LIST> static <MULTICAST_IPV4> interface { gigabitEthernet <PORT_LIST> | port-channel <PORT_CHANNEL_LIST> }
```

Static membership is not proof that a dynamic IGMP listener joined the group.

### Querier

```text
ip igmp snooping vlan-config <VLAN_LIST> querier   [ max-response-time <1..25>   | query-interval <10..300>   | general-query source-ip <UNICAST_IPV4>   | last-member-query-count <1..5>   | last-member-query-interval <1..5> ]
```

The cited defaults are:

- Max Response Time: **10 s**
- Query Interval: **60 s**
- General Query source: **0.0.0.0**
- Last Member Query Count: **2**
- Last Member Query Interval: **1 s**

The PDF example text contains a spacing inconsistency around `query interval`; the formal syntax uses `query-interval`, so automation retains the syntax record and still revalidates runtime support.

Querier election is a separate command and is documented as **disabled by default**:

```text
ip igmp snooping vlan-config <VLAN_LIST> querier-election
```

### Unknown multicast policy

The CLI exposes capability-scoped per-VLAN behavior:

```text
ip igmp snooping vlan-config <VLAN_LIST> drop-unknown
ip igmp snooping vlan-config <VLAN_LIST> route-unknown
```

The reference explicitly marks these commands as available only on certain devices. `route-unknown` forwards unregistered multicast toward IGMP Snooping router ports; it must never be inferred on unsupported devices.

## Read-back is the PASS gate

Canonical CLI read-back includes:

```text
show ip igmp snooping vlan [ <VLAN_ID> ]
show ip igmp snooping groups [ vlan <VLAN_ID> ]   [ <MULTICAST_ADDR> | count | dynamic | dynamic count | static | static count ]
```

The cited commands have no published privilege requirement and are available from Privileged EXEC / configuration modes.

PASS requires semantic evidence that the intended group table, receiver ports, router/querier path and forwarding behavior are correct. Configuration acceptance alone is `EXECUTED_UNVERIFIED`.

## Current standalone GUI

The current 2026 standalone L2 Managed IPTV guide explicitly configures the cited example in three layers:

1. enable IGMP Snooping globally;
2. enable it for the target VLAN;
3. enable it on the receiver/router-facing ports.

It also requires the underlying VLAN/PVID path to be correct. This workflow applies to the exact model/revision list on that guide; it is not promoted into an unsupported product-family claim.

## Current Controller v6+ hotel IPTV guidance

The current September 2026 hotel IPTV guide applies its Controller workflow to **all Omada switches except Agile switches**, with **Controller v6.0+**.

It defines Unknown Multicast policies as:

- **Forward** — flood unknown multicast within the VLAN;
- **Discard** — drop unknown multicast;
- **Router Port First** — use static/dynamic router ports when available, otherwise flood within the VLAN.

The same guide recommends a Querier on the aggregation switch closest to the multicast source in its topology and states that there should be **exactly one IGMP Querier in the multicast network**. This is kept as topology/workflow guidance, not converted into a global hardware default.

### Fast Leave safety

Fast Leave is only safe on a positively verified **single-TV/STB edge port** in the current hotel IPTV guidance.

Do **not** enable it on:

- switch-cascade ports;
- AP-cascade ports;
- shared downstream ports with multiple receivers.

On a shared port, one downstream Leave can immediately remove the shared port from the group and interrupt another receiver watching the same multicast stream.

### Report Suppression and router ports

Report Suppression is optional and recommended by the hotel guide, especially for larger IPTV deployments.

The same guide says router ports can normally be learned automatically in its topology; manually configuring a static router port is optional, not a universal requirement.

## Troubleshooting / operational verification

Current Omada multicast troubleshooting guidance recommends verifying the multicast-group table remains stable during playback and comparing receive/forward port counters repeatedly when diagnosing loss.

The automation therefore verifies:

1. intended dynamic/static group entries;
2. exact receiver member ports;
3. a valid router/querier path;
4. stable join/leave behavior;
5. expected stream delivery;
6. absence of unintended flooding or drops;
7. relevant interface counters when diagnosing packet loss.

If Layer-3 multicast routing/PIM is involved, that is a separate routing plane. 4.11 does not synthesize PIM or multicast-route configuration.

## Safety contract

1. Resolve exact model/hardware/firmware/management mode/Controller version and port/LAG identity.
2. Verify VLAN/PVID/LAG forwarding path first.
3. Snapshot global/VLAN/port snooping state, groups, router ports, Querier/election and policies.
4. Resolve an existing Querier before creating another.
5. Positively classify every Fast Leave target as single-receiver edge; block unknown/shared/cascaded ports.
6. Apply only the intended multicast-control delta.
7. Read back group/router/Querier state and verify real join/leave/forwarding behavior.
8. Persist standalone CLI state through the **4.02 save contract** only after operational verification.

## Boundaries

- **MLD** is IPv6 multicast snooping and is outside 4.11.
- **MVR** is a separate multicast VLAN feature and is outside 4.11.
- **PIM/multicast routing** is a Layer-3 feature and is not inferred from IGMP Snooping.
- **ACL** remains 4.12.

## CLI PDF visual-verification note

The official 2026 PDF text was parsed successfully. Required screenshot calls were made against the relevant Chapter 27 pages, but the screenshot backend returned cache-miss on every requested page. This artifact therefore **does not claim visual screenshot verification**; exact runtime applicability remains mandatory.

## Official sources

1. TP-Link / Omada — **CLI Reference Guide — Managed Switches**, REV2.0.0, May 2026.  
   `https://static.tp-link.com/upload/manual/2026/202607/20260724/1900003588_Managed%20SwitchMulti-model_CLI.pdf`
2. TP-Link / Omada — **How to Configure IGMP Snooping for IPTV Network on L2 Managed Switches Using the New GUI**, 2026-08-13.  
   `https://support.omadanetworks.com/jp/document/12988/`
3. TP-Link / Omada — **How to Configure IGMP Snooping on Omada Switches for Hotel IPTV Scenario**, 2026-09-02.  
   `https://support.omadanetworks.com/en/document/13168/?app=decoiSpyConnect`
4. TP-Link / Omada — **Troubleshooting Guide for Multicast Video Issues on Omada Switches**, 2026-08-21.  
   `https://support.omadanetworks.com/us/document/13300/?app=decoWelcome`
5. TP-Link / Omada — **Typical CLI Configuration Examples for TP-Link JetStream Switch**.  
   `https://support.omadanetworks.com/us/document/13117/?app=tapo_website`

## Closure

**4.11 = COMPLETE** for the current official IPv4 IGMP Snooping evidence scope with global/VLAN/port state, Querier/election, Fast Leave safety, Report Suppression, router/static group controls, unknown-multicast policies, standalone/Controller mappings, operational verification, troubleshooting, rollback and persistence gates retained.

**Next:** 4.12 — ACL.
