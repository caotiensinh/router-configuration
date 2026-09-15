# MikroTik Vendor Rules

**Scope:** MikroTik RouterOS automation only.  
**Authority:** Subordinate to `MASTER_RULES.md`; mandatory for MikroTik work.

## 1. Technical truth

Current official MikroTik RouterOS documentation is the primary technical authority. Version-matched documentation, CLI Reference, release notes, known issues/security notices, and validated offline copies outrank AI prior knowledge or community examples.

Legacy `help.mikrotik.com` material is reference-only when current `manual.mikrotik.com` documentation exists or conflicts.

## 2. Offline-first knowledge

MikroTik runtime must remain usable without Internet when required validated knowledge exists locally. Online access is for controlled synchronization/update. Offline packages must retain source URL, retrieval metadata, RouterOS/version scope where available, and SHA-256 provenance.

## 3. AI boundary

AI may normalize operator intent and propose ordering of already-validated immutable command primitives. AI must not own RouterOS CLI syntax, invent command strings or parameters, supply device facts, mark verification PASS, or authorize execution.

Claude, OpenAI/Codex, Ollama/local models, or future providers are interchangeable. Deterministic knowledge, renderers, validators, device evidence, and safety gates remain authoritative.

## 4. RouterOS version and device state

Before production writes, detect and record RouterOS version, device model/architecture/capabilities, current management path, relevant configuration state, and required dependencies. Version uncertainty blocks writes.

## 5. Script generation and validation

Generated `.rsc` scripts must be assembled from validated renderer primitives. Dependency/conflict validation must pass before script compilation. The final script must be bound to a SHA-256 digest.

Where supported, validate the exact script with RouterOS `import ... verbose=yes dry-run` on an appropriate validation target. Dry-run evidence must prove the validated script digest, RouterOS version compatibility, negative-control behavior, no unintended state mutation, and cleanup of temporary validation artifacts.

## 6. Safety

Management-critical changes such as firewall input, default routes, bridge/VLAN activation, management addressing, authentication, and VPN changes require additional safeguards. Use RouterOS-safe transaction patterns and Safe Mode where technically applicable; Safe Mode is not a substitute for backup, rollback planning, or verification.

## 7. Backup and rollback

Before production change, capture a pre-change state/configuration backup. After successful deployment, retain a post-change human-readable/sanitized export and a protected vendor-native binary backup where applicable. Sensitive binary backups must be handled as secrets/sensitive artifacts.

Rollback must stop further changes, assess current state, restore the intended known-good state, verify restoration, and preserve incident evidence.

## 8. Verification

Command success is not sufficient. Read back actual state and verify relevant behavior: interface/route/firewall/NAT/DNS/DHCP/VPN/management reachability/blocked paths/logging/failover as applicable. Compare desired state vs actual state vs MikroTik expected behavior.

## 9. Completion

MikroTik deployment is not COMPLETE until reference comparison passes with no unapproved regression, post-change backups exist, evidence is stored, and handover/as-built/operations/maintenance documentation is generated.

## 10. Current write boundary

Until the repository's CHR apply/verify/rollback acceptance and required physical-device acceptance gates are explicitly satisfied, unrestricted production RouterOS write remains disabled.