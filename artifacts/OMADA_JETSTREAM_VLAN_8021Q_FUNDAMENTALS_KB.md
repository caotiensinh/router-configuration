# Omada / JetStream 802.1Q VLAN Fundamentals

**Task:** 4.04 — VLAN 802.1Q fundamentals  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the current official 802.1Q guide scope

## Canonical concept model

Current TP-Link/Omada documentation consistently models IEEE 802.1Q VLANs as logical segmentation of a switched network. The normalized VLAN identifier namespace is **1–4094** in the current official guides used here.

| Concept | Normalized meaning |
|---|---|
| VLAN ID | Identifier carried by / associated with the IEEE 802.1Q VLAN context |
| Tagged ingress | VID is read from the existing VLAN tag where the applicable guide documents this behavior |
| Untagged ingress | The ingress port PVID supplies the VLAN identity where the applicable guide documents this behavior |
| Tagged member | VLAN traffic leaves the port with VLAN tag information present |
| Untagged member | VLAN traffic leaves the port without the VLAN tag |
| Non-member | Port is excluded from that VLAN |

**PVID is not the same field as egress membership.** It is retained separately from tagged/untagged membership so the future compiler cannot silently treat “PVID X” as proof that a port is untagged in VLAN X, or vice versa.

## Source-scoped defaults — do not globalize

The current **Omada Agile (Easy Managed) Switch (New VI) User Guide** states, for that scope, that all ports are in VLAN 1 by default, VLAN 1 cannot be deleted, a port removed from every current VLAN is automatically returned to VLAN 1, and the product scope supports up to **32 VLANs simultaneously**.

Those facts are **not** promoted into generic JetStream/Omada switch defaults or capacities. A different switch family/model may publish different behavior or limits.

## Management-mode boundary

Standalone Smart/Managed, standalone Agile/Easy Managed, and Controller mode expose related VLAN concepts through different object models. This task normalizes only the shared concepts and preserves those management-plane boundaries. It does **not** translate one mode's GUI objects or defaults into another mode's CLI/API/controller behavior.

## Safety / dependency rules

1. Resolve exact model + hardware revision + region + firmware + management mode before execution.
2. Confirm positive 802.1Q support for the exact device.
3. Discover existing VLANs, membership, and PVID through an applicable official read surface.
4. Keep PVID separate from egress tagged/untagged membership.
5. Keep product-specific VLAN 1/default rules and VLAN-count limits attached to their source scope.
6. Do not authorize write syntax from this fundamentals task.

## Deferred write work

- **4.05** — Access-port / PVID configuration.
- **4.06** — Trunk / tagged VLAN configuration.
- **4.07** — VLAN membership, removal, and default-VLAN behavior.
- **4.08** — VLAN interface / switch management IP.

## Official sources

1. TP-Link / Omada — **How to Configure 802.1Q VLAN on Smart and Managed Switches Using the New GUI**, 2026-08-13.  
   `https://support.omadanetworks.com/en/document/12981/`
2. TP-Link / Omada — **Omada Agile (Easy Managed) Switch (New VI)_User Guide**.  
   `https://support.omadanetworks.com/en/document/46791/`
3. TP-Link / Omada — **How to Configure 802.1Q VLAN on Omada Switches in Controller Mode**.  
   `https://support.omadanetworks.com/en/document/13215/`
4. TP-Link / Omada — **Omada Controller User Guide_V6.0**.  
   `https://support.omadanetworks.com/en/document/111217/`

## Closure

**4.04 = COMPLETE** for VLAN 802.1Q fundamentals with source-scoped defaults/limits and management-mode separation preserved.

**Next:** 4.05 — Access-port/PVID configuration.
