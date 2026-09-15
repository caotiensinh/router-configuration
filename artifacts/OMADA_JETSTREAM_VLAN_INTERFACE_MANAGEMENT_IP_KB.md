# Omada / JetStream VLAN Interface and Switch Management IP

**Task:** 4.08 — VLAN interface / switch management IP  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the current official VLAN-interface/management-IP evidence scope

## Parallel-lane execution

Phase 4.08 uses **12 independent read-only evidence lanes**: CLI VLAN1/default IP, CLI static/DHCP address mode, new SVI creation, Controller VLAN Interface, Controller Management VLAN, Controller static-IP workflow, adoption preservation, routing dependencies, read-back, management-path cutover, rollback/persistence, and applicability/validation. One serialized integration lane owns the artifacts.

The repository's 500-lane capacity is an assignment namespace, **not a claim of twelve external workers**.

## Three state planes must stay separate

1. **Port VLAN state** — membership, tagging and PVID from tasks 4.04–4.07.
2. **VLAN interface / SVI state** — Layer-3 interface associated with a VLAN, including its IP-address mode/address.
3. **Management interface/VLAN state** — the interface/path actually used to manage the switch.

An SVI does not automatically become the management interface, and changing a PVID does not by itself prove that the management IP changed.

## Standalone CLI evidence

The official generic JetStream CLI guide states that its default scope has a VLAN 1 IP interface that obtains an address by DHCP with a fallback of `192.168.0.1`. This is **guide-scoped behavior**, not an exact-device invariant.

Canonical read-back:

```text
show ip interface
```

Static addressing pattern:

```text
interface vlan <VLAN_ID>
ip address <IPv4_ADDRESS> <SUBNET_MASK>
```

DHCP addressing pattern:

```text
interface vlan <VLAN_ID>
ip address-alloc dhcp
```

The same guide demonstrates additional VLAN interfaces, including a static address on VLAN 20 and DHCP on VLAN 30. It also describes inter-VLAN routing in that guide scope. **Do not infer routed-SVI capability for every JetStream/Omada switch**; exact model/firmware/L3 capability is mandatory.

## Controller VLAN Interface

Official Controller guidance for Omada Smart/L2+/L3 switches exposes `Config > VLAN Interface`, where supported VLAN interfaces can be enabled and assigned an IP Address Mode such as Static. The same example configures DHCP services and then static routes for L3 forwarding. Task 4.08 normalizes only the VLAN-interface/IP portion; detailed static-route syntax remains **4.17**.

## Management VLAN and management IP

Current Controller v6.2+ guidance states that the management VLAN is the LAN network by default in the cited centrally managed workflow. For a custom Management VLAN, the documented flow enables the VLAN Interface on the switch, enables Management VLAN for it, and coordinates the uplink PVID/tagging so that the controller and switch remain reachable. The device can then obtain/use a **new managem IP** in that VLAN.

Controller-managed switches can also set the Management VLAN interface to **Static** IP mode. This Controller object model is not translated into standalone CLI commands.

## Adoption boundary

Current Omada Network V6 guidance states that, with compatible switch firmware, adoption can preserve preconfigured Management VLAN/interface and static interface IP (plus some other settings). The cited guidance excludes Omada Agile switches. Therefore preservation is an **applicability-gated behavior**, not something the automation may assume.

## Management-path safety

A management-IP or management-VLAN mutation is high risk because the command/UI action can succeed while the session disappears. The safe transaction is:

1. Resolve exact model + hardware revision + region + firmware + management mode + L3 capability.
2. Read the current management VLAN/interface, IP mode/address/mask and the currently reachable management IP.
3. Read the VLAN/PVID/tagging path carrying management traffic.
4. If switching to DHCP, prove DHCP is available on the destination management VLAN.
5. Resolve any gateway/static-route dependency needed for off-subnet management, without inventing 4.17 route syntax.
6. Establish a verified alternate/recovery path.
7. Apply only the intended VLAN-interface or management-IP delta.
8. Read back the new interface state and verify the **new management IP is reachable** and Controller heartbeat/adoption remains healthy when applicable.
9. Only then persist standalone CLI state through the **4.02 save contract**.

An accepted configuration action with no semantic read-back/reachability proof is `EXECUTED_UNVERIFIED`, not PASS.

## Rollback

Rollback restores the exact observed pre-change management VLAN/interface, IP mode/address/mask, reachable management IP and relevant uplink VLAN/PVID state. The automation must **not** assume that VLAN 1 or fallback `192.168.0.1` is a valid recovery path unless that exact state was observed and applicable.

## Official sources

1. TP-Link / Omada — **Typical CLI Configuration Examples for TP-Link JetStream Switch**.  
   `https://support.omadanetworks.com/us/document/13117/?app=tapo_website`
2. TP-Link / Omada — **How to configure VLAN Interfaces and Static Routes on Omada Switches**.  
   `https://support.omadanetworks.com/jp/document/13183/`
3. TP-Link / Omada — **How to configure Management VLAN for Omada Devices**.  
   `https://support.omadanetworks.com/uk/document/110372/`
4. TP-Link / Omada — **How to assign Static IP addresses for Omada Devices with Omada SDN Controller**.  
   `https://support.omadanetworks.com/en/document/13074/?app=tether`
5. TP-Link / Omada — **How to Maintain Management VLAN and Port Settings When Adopting Switches on Omada Network V6**.  
   `https://support.omadanetworks.com/en/document/110873/?app=tether`

## Closure

**4.08 = COMPLETE** for VLAN-interface/SVI and switch-management-IP semantics, with management-plane separation, cutover/reachability protection, routing-dependency boundaries, rollback and persistence gates retained.

**Next:** 4.09 — STP/RSTP/MSTP.
