# Omada Known Hardware / Firmware Limitation Registry

**Task:** 3.10 — Known hardware/firmware limitations  
**Observed:** 2026-09-15  
**Status:** COMPLETE for verified Phase 3.4–3.9 source scope

## Semantic boundary

This registry deliberately separates **vendor-published limitations/requirements** from **automation safety constraints caused by evidence conflicts, gaps, revision/region boundaries, or non-direct-target roles**. `UNKNOWN` and `NOT_PUBLISHED` are never rewritten as product limitations.

## Coverage

- Registered exact-identifier context: **230**
- Explicit vendor limitation/requirement records: **15**
- Normalized reconciled automation constraints: **168**
- Total registry records: **183**
- Source domains: physical interfaces (3.4), performance/capacity (3.5), power/environment (3.6), firmware (3.7), controller compatibility (3.8), management-mode differences (3.9).

## Critical explicit vendor limitations / requirements

- **VPL-001 — IRREVERSIBLE_FIRMWARE_UPGRADE — Fusion 2.5G:** TP-Link states the firmware upgrade is irreversible. Automation: Require explicit high-risk approval; mark rollback unavailable; snapshot configuration/evidence before upgrade.
- **VPL-002 — IRREVERSIBLE_FIRMWARE_UPGRADE — Fusion 2.5G PoE:** TP-Link states the firmware upgrade is irreversible. Automation: Require explicit high-risk approval; mark rollback unavailable.
- **VPL-003 — APPLICATION_DOWNGRADE_NOT_SUPPORTED — Fusion Pro 2.5G, Fusion Pro 2.5G PoE:** Fusion Pro blocks the operation. Automation: Do not synthesize application downgrade workflow.
- **VPL-004 — OS_DOWNGRADE_FACTORY_RESET — Fusion Pro 2.5G, Fusion Pro 2.5G PoE:** Factory defaults are restored, current configuration is erased, and unsupported applications may be removed. Automation: Treat OS downgrade as destructive reset; require compatible backup and post-downgrade reprovision plan.
- **VPL-005 — DOWNGRADE_NOT_SUPPORTED — ER707-M2:** TP-Link states this firmware version does not support downgrade; technical support is required if downgrade is needed. Automation: Block automated downgrade and enforce minimum source firmware before update.
- **VPL-006 — IRREVERSIBLE_UPGRADE_WITH_MINIMUM_SOURCE_VERSION — ER7412-M2:** TP-Link states the upgrade is irreversible. Automation: Enforce minimum source firmware and mark rollback unavailable.
- **VPL-007 — CONTROLLER_FIRST_UPGRADE_ORDER — ER7206:** Omada Controller v6.2+ is required; upgrading device firmware first can cause management failure. Automation: Require controller >=6.2 and upgrade controller before gateway firmware.
- **VPL-008 — DOWNGRADE_CLOUD_FEATURE_RISK — S6500-24GP4XF:** Cloud authentication, cloud management, or cloud-based firmware upgrade may become unavailable. Automation: Treat downgrade as cloud-control-plane risk; require explicit approval and recovery plan.
- **VPL-009 — PROHIBITED_UPGRADE_PATH — ER7212PC:** TP-Link says do not upgrade due to differences in built-in controller versions. Automation: Deny this transition; require vendor-supported recovery/migration path.
- **VPL-010 — MIGRATION_SCOPE_LIMIT — Fusion Pro 2.5G, Fusion Pro 2.5G PoE:** Migration is supported only between Fusion Pro gateways of the same model and same software version, and currently only for local management scenarios. Automation: Block cross-model/cross-version/cloud-managed migration synthesis.
- **VPL-011 — MINIMUM_CONTROLLER_VERSION — EAP225-Outdoor:** Requires Omada Controller v4.1.5 or above. Automation: Enforce minimum only on exact V1 track; do not inherit to V3.20.
- **VPL-012 — MINIMUM_CONTROLLER_VERSION — DS-P7001-04, DS-P7001-08:** Requires Omada SDN Controller 5.14.20 or above for the documented exact identities. Automation: Bind minimum to exact model/hardware/device version only.
- **VPL-013 — POE_INPUT_DEPENDENCY — ER703WP-4G-Outdoor:** PoE output requires 802.3bt PoE input; passive PoE voltage is not published in the reviewed spec block. Automation: Require 802.3bt input for PoE-out and never infer passive voltage.
- **VPL-014 — LOCAL_GUI_CONFIGURATION_UNAVAILABLE_AFTER_SDN_ADOPTION — DS-P7001-01, DS-P7001-04, DS-P7001-08, DS-P7001-16:** Official guidance states OLT GUI cannot be used for configuration; DPMS behavior differs and keeps GUI configuration with sync. Automation: Do not mix SDN and DPMS/local-GUI write paths.
- **VPL-015 — FIXED_VOLTAGE_NO_NEGOTIATION — POE5460X, POE5430G-M2, POE4824G, POE4818G, POE2412G:** Compatibility cannot be selected from wattage alone; exact voltage, polarity and device compatibility are required. Automation: Deny auto-selection until exact electrical compatibility is verified.

## Fail-closed principles

- Source conflict means evidence ambiguity, not a proven device limitation.
- Missing exact package/controller evidence blocks only the dependent workflow; it does not prove unsupported hardware.
- Irreversible/no-downgrade release notes disable automatic rollback assumptions.
- Region, hardware selector, raw revision notation and firmware train remain package-selection keys.
- Passive PoE requires exact electrical compatibility; optics/distance require exact module/revision/region.
- Recommended controller versions remain recommendations unless TP-Link explicitly publishes minimum/required semantics.
- Integrated controllers, hardware-controller platforms, surveillance/OLT management planes, unmanaged devices, bundles and accessories retain their role boundaries.

## High-value automation blocks retained from reconciliation


### physical_interface
- `ASC-058` **EVIDENCE_CONFLICT_FAIL_CLOSED** — Fusion Pro 2.5G PoE: field=PoE budget; exact_product_page=180W; support_or_series_summary=110W
- `ASC-059` **EVIDENCE_CONFLICT_FAIL_CLOSED** — ER605: field=port roles/USB
- `ASC-060` **EVIDENCE_CONFLICT_FAIL_CLOSED** — ER7206: field=port roles/USB
- `ASC-061` **EVIDENCE_CONFLICT_FAIL_CLOSED** — ER706W-4G: field=SIM slot count
- `ASC-062` **EVIDENCE_CONFLICT_FAIL_CLOSED** — OC200: field=Ethernet speed
- `ASC-063` **EVIDENCE_CONFLICT_FAIL_CLOSED** — OC220: field=PoE input standard
- `ASC-064` **EVIDENCE_CONFLICT_FAIL_CLOSED** — TL-SG3452X / SG3452X: field=model naming
- `ASC-065` **EVIDENCE_CONFLICT_FAIL_CLOSED** — SG2206MP: field=SFP slot count

### performance_capacity
- `ASC-070` **EVIDENCE_GAP_FAIL_CLOSED** — Fusion Pro 2.5G: Product capacity and regional performance are evidenced, but exact hardware selector is not verified.; Impact: Production-scoped sizing/write requires exact hardware discovery.
- `ASC-071` **EVIDENCE_CONFLICT_FAIL_CLOSED** — DS1018GMP: current US + 2026 UN1.20: 26.78 Mbps | older 2024 UN1.0: 26.79 Mpps; Impact: No canonical forwarding-rate metric for dependent sizing.
- `ASC-072` **EVIDENCE_CONFLICT_FAIL_CLOSED** — EAP783: US category/marketing: 1148 Mbps | US exact specification: 1376 Mbps; Impact: No canonical 2.4-GHz PHY rate for dependent PHY-based sizing.
- `ASC-073` **EVIDENCE_CONFLICT_FAIL_CLOSED** — EAP787: US category: 5765 Mbps | US exact product page: 8648 Mbps; Impact: No silent canonical 5-GHz PHY rate.
- `ASC-074` **EVIDENCE_CONFLICT_FAIL_CLOSED** — DS-P7001-16: current JP product page: 60 km; Class C+ | DS-PMA-C+ official module: max 20 km | DS-PMA-C++ official regional/version observations: 20 km and 60 km; Impact: Designs above 20 km cannot be authorized without exact optical module/revision/region.
- `ASC-075` **EVIDENCE_CONFLICT_FAIL_CLOSED** — Omada T8S4-4T: same current exact page marketing: 512 GB | same page specification: 521GB | standalone Omada 8MP Turret: 512 GB; Impact: Bundle-specific onboard storage capacity has no silent canonical value.

### power_environment
- `ASC-047` **EVIDENCE_CONFLICT_FAIL_CLOSED** — Fusion Pro 2.5G PoE: US category listing 110 W conflicts with HK/BR/FR exact pages 180 W. No global default; require region + exact product source.
- `ASC-048` **EVIDENCE_GAP_FAIL_CLOSED** — Fusion Pro 2.5G: AU 9V/3A USB-C and 14.35 W observation is not globally bound to an exact hardware selector.
- `ASC-049` **EVIDENCE_GAP_FAIL_CLOSED** — EAP773: V1 and current V2 differ materially; exact hardware revision is mandatory.
- `ASC-050` **EVIDENCE_CONFLICT_FAIL_CLOSED** — EAP725-Wall: Official versioned/unversioned pages conflict; exact revision/source scope required.
- `ASC-051` **EVIDENCE_CONFLICT_FAIL_CLOSED** — DS110GMP: Same-page official table/headline and marketing prose conflict; total 123 W budget retained but per-port PoE++ planning blocked.
- `ASC-052` **EVIDENCE_CONFLICT_FAIL_CLOSED** — SG5428XMPP: Official JP 500 W vs 550 W publication variance; no global 550 W default.
- `ASC-053` **EVIDENCE_GAP_FAIL_CLOSED** — Passive PoE adapters: Exact voltage, polarity and official device compatibility required; wattage alone is insufficient.
- `ASC-054` **EVIDENCE_CONFLICT_FAIL_CLOSED** — SM311LM: Official current surfaces publish 3.3 V vs 4.0 V; exact revision/region required.

### firmware
- `ASC-001` **IDENTITY_SCOPE_CONSTRAINT** — SX3832MPP, SX3832: V1/V1.60 use 1.0.x train while V1.20/V1.26 use 1.20.x train on reviewed official surfaces; exact selector and region are mandatory.
- `ASC-002` **IDENTITY_SCOPE_CONSTRAINT** — SX3206HPP V1.26: US V1.26 publishes 1.20.25 Build 20260720 while reviewed JP V1.26 page surfaces 1.20.18 Build 20260310. Do not synthesize a global latest; choose by exact target region.
- `ASC-003` **EVIDENCE_GAP_FAIL_CLOSED** — SG3428X-M2: V1.30/V1.36 official surfaces expose 1.30.8 Build 20260720 (published Aug 1) and 1.30.7 Build 20260804 (published Aug 20). Fail closed for automated latest selection.
- `ASC-004` **EVIDENCE_GAP_FAIL_CLOSED** — SG3210X-M2 V1.20: Official surfaces expose 1.20.8 Build 20260720 (published Aug 1) and 1.20.7 Build 20260804 (published Aug 20). Fail closed for automated latest selection.
- `ASC-005` **EVIDENCE_CONFLICT_FAIL_CLOSED** — SG3428XPP-M2, SG3218XP-M2, SG3210XHP-M2, SG2210XMP-M2: Distinct hardware selectors expose distinct firmware trains; no cross-generation package inheritance is allowed.
- `ASC-006` **IDENTITY_SCOPE_CONSTRAINT** — TL-SG3452X -> post-upgrade identity: Do not treat firmware-driven Device Name/hardware-version rename as proof that all TL-SG3452X and SG3452X records are globally interchangeable.
- `ASC-007` **EVIDENCE_GAP_FAIL_CLOSED** — SG5428XMPP V1: V1 hardware observation has no exact versioned release verified in C5; no sibling/revision package inheritance.
- `ASC-008` **EVIDENCE_CONFLICT_FAIL_CLOSED** — SG5452X, SG3452XMPP, SG3452XP, SG3428XMP, SG3428X: Distinct raw selectors use distinct firmware trains; exact target selector is mandatory even when builds or features look similar.

### controller_compatibility
- `ASC-076` **EVIDENCE_GAP_FAIL_CLOSED** — Fusion Pro 2.5G, Fusion Pro 2.5G PoE: Built-in controller/VMS role is official, but exact controller component version is not verified; do not synthesize one.
- `ASC-077` **NON_DIRECT_TARGET_BOUNDARY** — Fusion Pro 2.5G, Fusion Pro 2.5G PoE, Fusion 2.5G, Fusion 2.5G PoE, Fusion G+: Integrated-controller role does not prove external-controller adoption support. Require explicit vendor evidence before such workflow.
- `ASC-078` **EVIDENCE_GAP_FAIL_CLOSED** — ER8411, ER7406: Current compatibility-list/controller-mode evidence proves current platform listing, not a minimum/recommended controller version. Do not inherit sibling recommendation.
- `ASC-079` **IDENTITY_SCOPE_CONSTRAINT** — ER7412-M2, ER707-M2, ER605: Vendor Recommended Omada Controller 6.2.14 is stored as recommendation, not as minimum supported controller version.
- `ASC-080` **EXPLICIT_VENDOR_REQUIREMENT** — ER7206: Official JP guide requires controller v6.2+ for controller-managed ER7206 firmware 2.3+ IPoE scope and requires controller-first upgrade ordering.
- `ASC-081` **EVIDENCE_CONFLICT_FAIL_CLOSED** — ER706W: US compatibility-list V1.20 entry does not prove compatibility for current EN/JP V1.30 identity; exact revision evidence required.
- `ASC-082` **IDENTITY_SCOPE_CONSTRAINT** — ER706W-4G: EU V2.20 and US V1.6 device firmware/hardware tracks remain separate despite model-level compatibility listing.
- `ASC-083` **NON_DIRECT_TARGET_BOUNDARY** — ER7212PC: ER7212PC is explicitly Controller + Gateway + PoE Switch. Exact built-in controller version remains unresolved; known trial->normal upgrade prohibition caused by controller-version difference is preserved.

## Closure

**Task result:** PHASE 3.10 — KNOWN HARDWARE / FIRMWARE LIMITATIONS = COMPLETE for the currently verified source scope.  
**Next:** 3.11 — EOL/EOM/EOS status.
