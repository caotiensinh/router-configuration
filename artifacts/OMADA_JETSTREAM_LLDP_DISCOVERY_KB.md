# Omada / JetStream LLDP & LLDP-MED Discovery

**Task:** 4.15  
**Status:** COMPLETE for current official LLDP evidence scope  
**Observed:** 2026-09-15

## Scope and state separation

LLDP global enable, timers, per-port transmit/receive, standard TLV selection, management-address advertisement, LLDP-MED enable/TLV/location, local information, neighbor information, traffic counters, and Voice-VLAN/Auto-VoIP dependencies are distinct state planes. A successful configuration write is not proof that the intended neighbor was discovered.

## Official CLI evidence

The April 2026 Managed Switch CLI Reference Chapter 39 documents `lldp` / `no lldp`, `lldp forward_message`, hold multiplier, global transmission timers, per-port `lldp receive` and `lldp transmit`, TLV selection, management-address TLV, LLDP-MED fast count/status/TLV/location, and read-back through `show lldp`, `show lldp interface`, `show lldp local-information interface`, `show lldp neighbor-information interface`, and `show lldp traffic interface`.

The cited default transmit interval is 30 seconds. LLDP-MED fast count defaults to 4. In the cited CLI scope, enabling `lldp med-status` changes the port Admin Status to Tx&Rx. This side effect is not generalized to Controller or other firmware without exact evidence.

Required PDF screenshot attempts on representative Chapter 39 pages returned cache-miss. Parsed official PDF text was used and `visual_screenshot_verified=false` remains explicit.

## Current Controller / standalone guide

The 2026 Omada guide applies to Controller V5.0+ and Omada L2+/L3 switches in its cited workflow. LLDP-MED can distribute VoIP network-policy information to IP phones. Controller workflow creates a Voice VLAN and port profile, enables LLDP-MED, then assigns the Voice Network/profile to intended ports. Standalone workflow enables LLDP-MED on intended ports, creates the voice VLAN, and enables Auto VoIP. The current standalone guide states LLDP-MED is disabled by default in that cited scope.

Voice VLAN, PVID and QoS are dependencies, not implicit LLDP changes. Existing VLAN/QoS tasks remain authoritative.

## Verification and rollback

PASS requires exact global/port read-back plus expected local/neighbor discovery and LLDP traffic evidence where observable. For the cited VoIP scenario, the IP phone should use the intended voice VLAN. Management/uplink reachability must remain healthy. Configuration acceptance alone is `EXECUTED_UNVERIFIED`.

Rollback restores exact pre-change global LLDP/timers, per-port TX/RX, standard/MED TLV selection, management address, MED status/location and explicitly approved dependent voice settings.

## Sources

1. TP-Link / Omada, **CLI Reference Guide — Managed Switches**, REV1.1.0, April 2026, Chapter 39.
2. **How to Configure LLDP and LLDP-MED on Omada Switches via Omada Controller**, 2026-08-24: `https://support.omadanetworks.com/cl/document/13247/`
3. **How to configure LLDP & LLDP-MED on Omada Switches**, 2026-05-14: `https://support.omadanetworks.com/us/document/13247/?app=decoI`

## Closure

**4.15 = COMPLETE** for current official evidence scope. **Next: 4.16 — DHCP Snooping / ARP Inspection / anti-spoofing where supported.**
