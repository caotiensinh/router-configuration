# Router Configuration

Router Configuration is a clean-room network configuration control system for multi-vendor routers.

The project turns high-level network intent into validated, reviewable, and reversible device changes. Its first reference platform is MikroTik RouterOS, followed by Yamaha RTX and TP-Link Omada gateways.

## Goals

- Dual-WAN with weighted load balancing and automatic failover.
- Static routing and policy-based routing.
- VLAN and zone-based segmentation.
- Firewall and management-plane hardening.
- VPN policy, starting with WireGuard/IPsec where supported.
- QoS and traffic classification.
- Desired-state diff and drift detection.
- Dry-run, impact analysis, verification, and rollback.
- Vendor-neutral core with vendor-specific adapters.
- Git-friendly configuration and auditable change evidence.

## Reference topology

- WAN1: 10 Gbps
- WAN2: 1 Gbps
- LAN/Core uplink: 10 Gbps
- Initial reference device: MikroTik CCR2116-12G-4S+

## Architecture

The system is divided into ten capability modules:

1. Intent & Device Engine
2. State / Diff / Drift Engine
3. Configuration Compiler & Secrets
4. Multi-WAN & Load Balancing
5. Resilience & WAN Health
6. Security Operations
7. Segmentation / PBR / VPN / QoS
8. Yamaha Adapter
9. Safe Automation Gate
10. Omada Adapter & API Compatibility

See `ARCHITECTURE.md` for module boundaries and `THIRD_PARTY_RESEARCH.md` for the clean-room research policy.

## Safety model

The default operating mode is read/plan only. A configuration change must pass:

`discover -> inspect -> plan -> validate -> backup -> apply -> verify -> save`

If post-change verification fails, the execution contract requires rollback or a controlled stop while preserving the management path.

## Project status

Early foundation. No production router should be modified with this repository until a module is explicitly marked production-ready and its integration tests pass on the target firmware.
