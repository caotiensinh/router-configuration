# Cisco Vendor Rules

**Scope:** Cisco IOS XE router and switch automation only.  
**Authority:** Subordinate to `MASTER_RULES.md`; mandatory for Cisco IOS XE work.

## 1. Technical truth

Current official Cisco documentation is the primary technical authority. Product- and release-matched Cisco configuration guides, programmability guides, command references, release notes, security advisories, YANG model documentation, and validated offline copies outrank AI prior knowledge or community examples.

Cisco IOS XE, Cisco NX-OS, and Cisco IOS XR are separate operating-system domains. Knowledge or syntax from one domain MUST NOT be silently reused in another domain.

## 2. Initial platform scope

The first Cisco domain targets IOS XE platform families documented by Cisco's IOS XE programmability guides:

- router/edge: Catalyst 8000V, Catalyst 8200, Catalyst 8300, Catalyst 8500;
- campus switching: Catalyst 9200, Catalyst 9300, Catalyst 9400, Catalyst 9500, Catalyst 9600.

A family being listed in an official guide proves documentation scope only. It does not prove that every feature, YANG model, command, license, hardware SKU, or release is available on every member of that family.

## 3. Version and capability discovery

Before any generated operation is treated as executable, the system MUST discover and record:

- exact platform/model;
- IOS XE version;
- software package/image identity where available;
- management transport actually enabled;
- NETCONF/RESTCONF/YANG capabilities actually advertised by the device;
- relevant license/capability facts when the requested feature depends on them.

Unknown or unsupported versions fail closed.

## 4. Model-driven management first

For functionality covered by supported YANG models, NETCONF/RESTCONF and device-advertised YANG capabilities are preferred over parsing human-oriented CLI text.

NETCONF or RESTCONF support in a Cisco guide does NOT authorize a write. Read-only discovery and capability collection are separate from configuration mutation.

If a required feature is not represented by the validated model-driven knowledge, an IOS XE CLI operation may be added only after exact command syntax, mode, platform scope, version scope, dependencies, verification, and rollback behavior are bound to authoritative Cisco sources and deterministic tests.

## 5. AI boundary

AI may normalize operator intent, select among already-validated Cisco operations, explain evidence, and propose ordering. AI MUST NOT invent IOS XE commands, YANG paths, payload fields, feature availability, default values, device facts, license facts, or write authorization.

## 6. Read-only admission first

The Cisco domain MUST establish read-only discovery before any write path. Initial admission should prove at least:

- identity/version readback;
- interface inventory and operational state;
- routing-state visibility appropriate to the platform role;
- VLAN/switching-state visibility for switch platforms where applicable;
- advertised YANG capability inventory;
- secret-field exclusion;
- least-privilege behavior;
- deterministic normalization.

## 7. Configuration safety

Before any production write, the system MUST have current state, desired state, deterministic diff, dependency/conflict analysis, management-path analysis, backup, rollback, verification criteria, and changeset-specific human approval.

High-risk changes include management AAA, management interface/VRF, routing, default route, ACLs affecting management, VLAN/trunk changes, spanning-tree changes, first-hop redundancy, VPN/security changes, and software/image changes.

## 8. Verification

A successful NETCONF/RESTCONF response or CLI return code is not deployment success. The system MUST read back state and verify behavior against desired state and Cisco-documented expectations.

## 9. Lab evidence

Virtual or simulated Cisco evidence MUST identify the exact image/platform used and MUST NOT be represented as physical-hardware evidence. Synthetic fixtures are useful for parser/contract tests but cannot satisfy live-device admission gates.

## 10. Current write boundary

Until Cisco IOS XE read-only admission, deterministic rendering/model validation, transaction safety, rollback/recovery, and required physical-device acceptance gates are explicitly satisfied, unrestricted production Cisco write remains disabled.
