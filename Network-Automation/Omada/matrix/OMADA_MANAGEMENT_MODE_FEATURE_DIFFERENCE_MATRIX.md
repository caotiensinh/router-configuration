# Omada Management-Mode Feature Difference Matrix

**Task:** 3.9 — Standalone / Controller / Cloud feature differences  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the currently registered official-source scope

## Safety model

This artifact does **not** create feature parity between management modes. Every operational lookup must still bind the exact model, hardware revision, region, firmware, management mode, controller type/version, and cloud tier when material.

`UNKNOWN`, `NOT_PUBLISHED`, and scoped limitations are valid outcomes. Absence from a comparison article is not proof that a feature is unsupported.

## 1. Global mode semantics

Official 2026 Omada standalone guidance confirms that gateways, EAPs and switches can be managed through their local Web UI when operating in standalone mode and not adopted by an Omada Controller. Controller mode provides centralized multi-device configuration and monitoring. Adoption can remove local Web-management access on referenced gateway/EAP workflows.

## 2. Gateway — Standalone vs Controller

The current official business-router comparison publishes material mode differences:

- **Both modes / device-persistent after controller loss:** Port Forwarding, Bandwidth Control, Session Limit, Load Balancing, Policy Routing, Static Route, PPTP/L2TP/IPsec/OpenVPN, Attack Defense, Time Range, Dynamic DNS, UPnP, SNMP, SSH, IPTV.
- **Both modes but behavior differs:** Online Detection, Access Control / Gateway ACL, VLAN/PVID behavior.
- **Controller runtime dependent:** Portal authentication flows and Reboot Schedule; new portal authentication can fail when the controller is offline.
- **Standalone-only in the referenced comparison:** Diagnostics (Ping/Traceroute), One-to-One NAT, Port Triggering.
- **Controller exposes extra configuration while device-side function can persist:** selected IPsec parameters, firewall state-timeout control, LED control.

The router comparison itself is not a license to copy a feature to an exact model/revision not covered by exact evidence.

## 3. Switch — Standalone vs Controller

Official JetStream guidance states that standalone mode exposes the switch's full function set while controller mode can limit selected advanced functions. The published comparison shows examples such as controller SSH being limited to show commands, PoE budget being view-only, static/manual MAC operations differing, Voice VLAN vs Auto-VOIP semantics differing, and ACL/L3/DHCP-filter capability differing.

Because this family comparison has historical/general scope, exact current model + firmware evidence always wins.

## 4. AP / Wireless

Current 2026 standalone-AP guidance identifies **Voucher** and **Fast Roaming** as unavailable for standalone configuration, and identifies centralized cloud management, Auto Backup and Upgrade Schedule as controller advantages. Standalone is positioned for small/basic deployments; controller mode is the full centralized path.

For AP firmware adapted to Controller **V6.1+**, official CLI guidance supports CLI in both modes, but the access path differs* standalone SSH versus Controller Terminal/CLI.

Wireless Bridge records retain separate exact-device gating; AP feature examples are not inherited by bridges without evidence.

## 5. Controller platform / cloud tier

Current official Omada comparison data keeps four controller platforms distinct:

| Capability | Cloud Essentials | Cloud Standard | Hardware Controller | Software Controller |
|---|---|---|---|---|
| ZTP | Yes | Yes | No | No |
| MSP mode | No | Yes | No | Yes |
| PPSK | No | Yes | Yes | Yes |
| VPN | WireGuard | Broad VPN set | Broad VPN set | Broad VPN set |
| ACL | No | Yes | Yes | Yes |
| IPS/IDS | No | Yes | Yes | Yes |
| DPI | No | Yes | Yes | Yes |
| Open API | No | Yes | Yes except OC200 in referenced table | Yes |
| WLAN Optimization | No | Yes | Yes | Yes |
| Logs / Alerts | Basic | Advanced | Advanced | Advanced |

Cloud Essentials and Cloud Standard are therefore separate feature tiers, not licensing labels over an identical feature set. Hardware/Software Controller cloud access is also not the same architecture as a Cloud-Based Controller.

## 6. OLT / Surveillance / Accessories

- **OLT:** Omada SDN Controller, DPMS and local OLT GUI behavior remain separate management planes; exact controller/version binding is still required.
- **Surveillance:** NVR GUI/Web, Omada Guard and Omada Central Guard remain the surveillance plane. They are not converted into Omada Network Controller endpoints.
- **Accessories:** remain `NOT_DIRECT_CONTROLLER_TARGET`; host-mediated DDM/telemetry, PoE behavior, optical compatibility, or mechanical/BOM membership does not make an accessory independently adopted.

## Reconciliation

PASS:
- standalone/controller parity is not assumed;
- controller-offline behavior is retained where TP-Link explicitly documents it;
- Cloud Essentials vs Standard remain separate;
- on-prem vs cloud-controller architecture remains separate;
- integrated-controller/platform roles remain separate;
- OLT / Network / Guard / accessory management planes remain separate;
- exact model/firmware/controller compatibility remains the final operational gate.

**Task result:** PHASE 3.9 COMPLETE for the registered current-source scope.  
**Next:** 3.10 — Known hardware/firmware limitations.
