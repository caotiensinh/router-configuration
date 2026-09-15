# Omada Remaining Work — 4-Lane Execution Plan

Baseline: **197 / 340 complete; 143 / 340 remaining (42.06%)**.

Each execution lane owns **34 canonical tasks = exactly 10.00% of the 340-task denominator**. The final **7 shared convergence tasks = 2.06%** remain outside lane ownership because they are cross-cutting governance/HIL/release gates.

Durable credit rule: no lane earns progress for planning, branch-only work, or unverified candidates. Credit is added only after canonical persistence/read-back, repository promotion, exact artifact verification where applicable, and required CI/Governance gates PASS.

## LANE-01 — Vendor feature knowledge
- Branch: `lane/remaining-01-vendor-features`
- Allocation: **34 / 340 = 10.00%**
- [ ] 4.17 Static routing / L3 switch features where supported.
- [ ] 4.18 SNMP / monitoring / logging.
- [ ] 4.19 Backup/restore/upgrade.
- [ ] 4.20 Diagnostics/troubleshooting.
- [ ] 5.01 Interfaces / WAN / LAN.
- [ ] 5.02 VLAN / network segmentation.
- [ ] 5.03 DHCP / DNS.
- [ ] 5.04 Static routing.
- [ ] 5.05 Policy routing.
- [ ] 5.06 Multi-WAN / load balancing / failover.
- [ ] 5.07 NAT / port forwarding.
- [ ] 5.08 Firewall / ACL / stateful policy features.
- [ ] 5.09 VPN — site-to-site.
- [ ] 5.10 VPN — remote access.
- [ ] 5.11 Authentication / captive portal where applicable.
- [ ] 5.12 IDS/IPS/security features where officially supported.
- [ ] 5.13 Controller-managed vs standalone differences.
- [ ] 5.14 Logging/monitoring.
- [ ] 5.15 Backup/restore/upgrade.
- [ ] 5.16 Diagnostics/troubleshooting.
- [ ] 6.01 Radio/band/capability schema.
- [ ] 6.02 SSID / WLAN objects.
- [ ] 6.03 VLAN mapping.
- [ ] 6.04 WPA/WPA2/WPA3 capabilities by model/firmware.
- [ ] 6.05 Enterprise authentication / RADIUS.
- [ ] 6.06 Guest/captive portal.
- [ ] 6.07 Roaming / mesh / band steering / load balancing where supported.
- [ ] 6.08 RF optimization / channel / power.
- [ ] 6.09 ACL/client isolation.
- [ ] 6.10 Controller vs standalone differences.
- [ ] 6.11 Firmware upgrade / adoption / recovery.
- [ ] 6.12 WLAN diagnostics/troubleshooting.
- [ ] 7.01 Controller architecture.
- [ ] 7.02 Site / organization / device hierarchy.

## LANE-02 — Controller, compiler & diagnostics
- Branch: `lane/remaining-02-controller-compiler`
- Allocation: **34 / 340 = 10.00%**
- [ ] 7.03 Adoption / discovery / provisioning.
- [ ] 7.04 Controller version compatibility.
- [ ] 7.05 Device firmware compatibility.
- [ ] 7.06 Configuration templates/profiles.
- [ ] 7.07 Gateway management.
- [ ] 7.08 Switch management.
- [ ] 7.09 AP/WLAN management.
- [ ] 7.10 User/RBAC/administrator roles.
- [ ] 7.11 Logs/events/alerts.
- [ ] 7.12 Backup/restore/migration.
- [ ] 7.13 API/integration capabilities from official sources.
- [ ] 7.14 Omada Central/cloud differences.
- [ ] 7.15 Controller troubleshooting.
- [ ] 8.1 Build normalized TP-Link command/object schema.
- [ ] 8.2 Build CLI command database.
- [ ] 8.3 Build API/controller operation database where officially supported.
- [ ] 8.4 Build dependency DAG.
- [ ] 8.5 Build ordering rules.
- [ ] 8.6 Build conflict rules.
- [ ] 8.7 Build model/hardware/firmware compatibility checks.
- [ ] 8.8 Build idempotent diff rules.
- [ ] 8.9 Build deterministic vendor compiler.
- [ ] 8.10 Build per-operation provenance mapping.
- [ ] 9.1 Link/interface diagnostics.
- [ ] 9.2 VLAN/PVID/trunk diagnostics.
- [ ] 9.3 STP/LAG diagnostics.
- [ ] 9.4 DHCP/DNS diagnostics.
- [ ] 9.5 Routing diagnostics.
- [ ] 9.6 ACL/firewall diagnostics.
- [ ] 9.7 VPN diagnostics.
- [ ] 9.8 PoE diagnostics.
- [ ] 9.9 AP/RF/client diagnostics.
- [ ] 9.10 Controller adoption/provisioning diagnostics.
- [ ] 9.11 Firmware/controller compatibility diagnostics.

## LANE-03 — Security, knowledge pipeline & AI intent
- Branch: `lane/remaining-03-security-ai`
- Allocation: **34 / 340 = 10.00%**
- [ ] 9.12 Evidence-based RCA graph.
- [ ] 9.13 Minimum-check strategy.
- [ ] 10.1 TP-Link/Omada official security guidance baseline.
- [ ] 10.2 Management-plane hardening.
- [ ] 10.3 Secure administrator/RBAC baseline.
- [ ] 10.4 Network segmentation baseline.
- [ ] 10.5 L2 attack-protection baseline where supported.
- [ ] 10.6 WLAN security baseline.
- [ ] 10.7 VPN baseline.
- [ ] 10.8 Logging/monitoring baseline.
- [ ] 10.9 Firmware/vulnerability maintenance baseline.
- [ ] 10.10 CIS/NIST/ISO/PCI/company-policy technical mappings where applicable.
- [ ] 11.1 Archive official raw documents locally.
- [ ] 11.2 Hash/version raw sources.
- [ ] 11.3 Normalize relational data.
- [ ] 11.4 Full-text index.
- [ ] 11.5 Semantic retrieval index.
- [ ] 11.6 Dependency graph.
- [ ] 11.7 Knowledge-package versioning.
- [ ] 11.8 Online sync to staging.
- [ ] 11.9 URL-change resilience.
- [ ] 11.10 Diff/test/promote STAGING -> VERIFIED ACTIVE KB.
- [ ] 11.11 Offline functional tests.
- [ ] 12.1 User intent -> vendor-neutral Network Engineering IR.
- [ ] 12.2 Missing-input resolver.
- [ ] 12.3 Device/current-state auto-discovery before asking user.
- [ ] 12.4 Contradiction detection.
- [ ] 12.5 AI provider gateway: OpenAI / Claude / local model.
- [ ] 12.6 Reject all unverified AI-generated commands.
- [ ] 12.7 Human-readable deployment plan.
- [ ] 12.8 Engineer-readable deployment plan.
- [ ] 12.9 Approval gate + changeset hash.
- [ ] 13.1 Current-state snapshot.
- [ ] 13.2 Pre-change backup.

## LANE-04 — Transaction safety, reporting & virtual lab
- Branch: `lane/remaining-04-runtime-reporting`
- Allocation: **34 / 340 = 10.00%**
- [ ] 13.3 Desired-state diff.
- [ ] 13.4 Risk classification.
- [ ] 13.5 Ordered execution.
- [ ] 13.6 Read-back verification.
- [ ] 13.7 Stop-on-failure.
- [ ] 13.8 Rollback.
- [ ] 13.9 Post-rollback verification.
- [ ] 13.10 Final desired-vs-actual validation.
- [ ] 14.1 Project summary.
- [ ] 14.2 Implementation plan.
- [ ] 14.3 Configuration report.
- [ ] 14.4 As-built documentation.
- [ ] 14.5 Change record.
- [ ] 14.6 Test evidence.
- [ ] 14.7 Technical security/compliance report.
- [ ] 14.8 Operation manual.
- [ ] 14.9 Maintenance manual.
- [ ] 14.10 Troubleshooting runbook.
- [ ] 14.11 Future upgrade guide.
- [ ] 14.12 Rollback procedure.
- [ ] 14.13 Handover acceptance.
- [ ] 14.14 Before/after backup package.
- [ ] 14.15 Sanitized config export.
- [ ] 14.16 Manifest with provenance/hashes.
- [ ] VLAB.8 Bind officially verified Controller/API/CLI schemas after Phase 7/8 evidence exists.
- [ ] VLAB.9 Add protocol/transcript fixtures generated only from verified vendor behavior.
- [ ] VLAB.11 Formalize `DeviceBackend` adapter contract: `VirtualBackend`, future `SSHBackend`, `HTTPAPIBackend`, `ControllerBackend`, `PhysicalDeviceBackend`.
- [ ] VLAB.12 Add Linux network-namespace/veth/bridge/VLAN backend when `CAP_NET_ADMIN` is available, with deterministic user-space fallback.
- [ ] VLAB.13 Build verified-capability `VirtualSwitch` behavioral contracts.
- [ ] VLAB.14 Build verified-capability `VirtualGateway` behavioral contracts.
- [ ] VLAB.15 Build verified-capability `VirtualAP` and `VirtualBridge` behavioral contracts.
- [ ] VLAB.16 Build verified-capability `VirtualOLT`, `VirtualCamera`, and `VirtualNVR` behavioral contracts.
- [ ] VLAB.17 Add multi-device topology scenarios, dependency validation, and failure propagation.
- [ ] VLAB.18 Auto-generate boundary tests from verified KB values (power, PoE budget, temperature, interface/capability limits).

## Shared convergence reserve — cross-lane
- Allocation: **7 / 340 = 2.06%**
- [ ] 0.9 Persist/verify MASTER_RULES.md for the TP-Link/Omada project workspace.
- [ ] 0.10 Persist AGENTS.md bootstrap rule.
- [ ] 0.11 Persist CONTRIBUTING.md governance rule.
- [ ] 0.12 Add CI governance enforcement when implementation repository is activated.
- [ ] VLAB.10 Run hardware-in-the-loop acceptance when physical devices become available.
- [ ] VLAB.19 Enforce evidence/confidence classes: `VENDOR_DOCUMENT_VERIFIED`, `VIRTUAL_VERIFIED`, `PROTOCOL_VERIFIED`, `HARDWARE_VERIFIED`; virtual results can never grant `HARDWARE_VERIFIED`.
- [ ] VLAB.20 Define CI/release acceptance gates across schema, virtual, protocol and future HIL evidence.
