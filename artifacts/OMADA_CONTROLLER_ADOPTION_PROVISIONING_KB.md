# Omada Controller Adoption / Discovery / Provisioning

**Task:** 7.03  
**Status:** COMPLETE candidate for current official evidence scope  
**Observed:** 2026-09-16

## Deterministic state model

Current TP-Link guidance separates controller-device communication, discovery, adoption and provisioning. For the normal path, a discovered device progresses **Pending → Adopting → Provisioning → Configuring → Connected**. Only `Connected` with the intended controller/site and expected configuration is a PASS terminal state.

The controller also surfaces exceptional states including `Managed by Others`, `Heartbeat Missed`, `Disconnected` and `Isolated`; these are evidence states, not prompts to force ownership changes.

## Discovery

When controller and device are in the same LAN/subnet/VLAN, direct discovery requires no additional discovery configuration. Across different LANs/subnets/VLANs, official guidance names Controller Inform URL, Discovery Utility and DHCP Option 138 as discovery techniques, but controller-device communication remains a prerequisite.

## Provisioning and site safety

Site membership is desired state. Moving a managed switch between sites can replace its prior-site configuration with new-site configuration and clear traffic history, so site moves are network changes.

`Force Provision` synchronizes controller configuration to the device and can temporarily disconnect/readopt it. `Remember Device` can cause automatic adoption after reset/power-on when rediscovered; that behavior requires explicit authorization.

## Verification and rollback

Adoption acceptance or an in-progress state is not PASS. PASS requires the intended site, expected ownership, final `Connected` state, expected provisioning/configuration and healthy management reachability.

Before ownership/site/provisioning changes, record prior controller/site/management state. On failure, stop additional writes and use only an explicitly authorized recovery/rebind path.

## Official sources

1. TP-Link, **Omada SDN Controller User Guide — Manage Omada Managed Devices and Sites**, current web guide.
2. TP-Link, **Omada SDN Controller User Guide — Configure and Monitor Omada Managed Devices**, current web guide.

## Closure

**7.03 = COMPLETE candidate** for current official evidence scope. Durable promotion still requires Library read-back, exact repository bytes, main concurrency checks, CI and Governance PASS.
