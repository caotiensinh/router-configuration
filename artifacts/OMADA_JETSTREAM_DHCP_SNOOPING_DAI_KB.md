# Omada / JetStream DHCP Snooping, DAI & Anti-Spoofing

**Task:** 4.16  
**Status:** COMPLETE candidate for current official evidence scope  
**Observed:** 2026-09-16

## State separation

DHCP Snooping, Dynamic ARP Inspection (DAI), manual IP-MAC-VLAN-port bindings, dynamically learned DHCP bindings, IP Verify Source, VLAN scope, trusted-port state, validation controls and management/uplink topology are separate state planes. Enabling one plane does not silently authorize another.

## Current Controller evidence

The official 2026-01-27 Omada guide places DHCP Snooping and DAI under IP-MAC-Port Binding (IMPB) and requires current firmware plus Omada Controller V6.1+ for the cited workflow. DHCP Snooping learns valid IP/MAC/port/VLAN/lease associations from DHCP transactions. DAI validates ARP traffic against IMPB evidence.

In the cited Controller workflow, a port selected for DHCP Snooping both learns bindings and rejects illegal DHCP-server response traffic arriving from the client side; the guide says those effects cannot be separated. The cascade port cannot be selected in that workflow so the switch can continue obtaining its own management address by DHCP. This is a topology and management-reachability gate, not a convenience default.

For DHCP networks, dynamically learned Snooping entries can feed DAI validation. For static-IP-only networks, use explicit manual bindings; do not fabricate DHCP-learned entries.

## Official CLI evidence

The April 2026 Managed Switch CLI Reference REV1.1.0 Chapter 77 documents manual IMPB bindings, global/VLAN DHCP Snooping, per-interface maximum learned entries and trusted state, plus read-back with `show ip source binding`, `show ip dhcp snooping`, and `show ip dhcp snooping interface`.

Chapter 93 documents ARP Inspection global state, source/destination/IP validation, VLAN scope, VLAN logging, trusted ports, rate limit, burst interval, exceed action and read-back with `show ip arp inspection`, interface/VLAN views and statistics. In that cited CLI scope, ARP Inspection rate limit defaults to 100 pps and burst interval to 1 second. The CLI explicitly identifies uplink, routing and LAG ports as examples that should be trusted before ARP Inspection is enabled; exact-device applicability remains mandatory.

Representative PDF screenshot requests for the Chapter 77 and Chapter 93 pages returned cache-miss. Parsed official PDF text is retained and `visual_screenshot_verified=false` remains explicit.

## Safety gates

Before enforcement, snapshot bindings, trust state, VLAN scope, validation state, rate/burst/exceed controls and identify DHCP-server/uplink/cascade/routing/LAG paths. Never infer trust state. Keep IP Verify Source as a separate dependent plane. VLAN scope must be explicit.

Configuration acceptance is only `EXECUTED_UNVERIFIED`. PASS requires exact read-back, the expected binding table, legitimate DHCP/ARP/IP behavior, healthy management/uplink reachability, and representative rejection evidence for rogue DHCP or spoofed traffic where safely testable.

## Rollback

Restore exact pre-change manual bindings, learned-binding policy, global/VLAN enforcement, trusted ports, validation, rate limits, burst interval and exceed actions. Verify legitimate DHCP/ARP/IP and management reachability before persistence.

## Sources

1. TP-Link / Omada, **What is DHCP Snooping and DAI and How to Configure Them on Omada Switches When Adopted on Omada Controller**, 2026-01-27: `https://support.omadanetworks.com/en/document/115293/`
2. TP-Link / Omada, **CLI Reference Guide — Managed Switches**, REV1.1.0, April 2026, Chapters 77 and 93.

## Candidate closure

**4.16 = COMPLETE candidate** for current official evidence scope. Promotion still requires Library read-back, canonical promotion, exact GitHub byte/hash verification and CI/Governance PASS. **Next: 4.17 — Static routing / L3 switch features where supported.**
