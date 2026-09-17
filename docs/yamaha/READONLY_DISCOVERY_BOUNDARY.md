# Yamaha RTX3510 Y02 Read-Only Discovery Boundary

Status: engineering test scope only; no production write authorization.

## Scope

Y02 binds the Yamaha domain to the exact baseline already admitted by Y01:

- model: `RTX3510`
- firmware: `Rev.23.01.03`
- role: router
- source authority: official Yamaha Network / Yamaha RTpro documentation only

The baseline read-only command catalog is intentionally small and exact:

- `show environment`
- `show arp`
- `show ip route`
- `show ip route detail`
- `show status lan1`
- `show status lan2`
- `show status lan3`
- `show status lan4`

RTX3510 product specifications define LAN1 through LAN4, and the model-specific user guide documents the show commands used for operational inspection. The current RT-series command reference includes RTX3510 and Rev.23.01.03.

## Fail-closed rules

- Any command not present in the catalog is blocked.
- Command pipelines are not admitted by this baseline.
- `show config`, `show log`, and `show techinfo` are deliberately excluded from the secret-safe baseline because their output may disclose configuration, operational, identity, or other sensitive material that requires a separate sanitization contract.
- Whitespace may be normalized, but command spelling/case/semantics are not guessed.
- Evidence must observe exact `RTX3510` and `Rev.23.01.03` identity.
- Raw command output is not embedded in the digest record.
- The evidence record cannot self-promote transport authenticity, least-privilege verification, live-device verification, physical-hardware verification, or write authorization.

## Evidence meaning

`build_readonly_evidence()` validates caller-supplied command outputs and creates digest-bound metadata. This proves parser/catalog/evidence logic only. It does **not** prove that the output came from a real RTX3510 or from a least-privilege management session.

Therefore the following remain false in Y02 engineering evidence:

- `transport_verified`
- `least_privilege_verified`
- `live_device_verified`
- `physical_device_verified`
- `production_write_authorized`

## External dependency

Physical RTX3510 acceptance cannot be performed when no physical RTX3510 is available. That dependency is explicitly deferred and must not keep the engineering task open after all testable code, synthetic tests, CI, and evidence contracts pass.

A later hardware acceptance task may consume the same exact command catalog, but it must independently prove transport, privilege boundary, device identity, and captured evidence provenance.
