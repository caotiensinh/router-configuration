# RouterOS Guided Preflight

## Purpose

`routeros-preflight` is the bridge between beginner-friendly deployment intent and expert-level safety checks. It compares a validated deployment profile with sanitized RouterOS discovery evidence before any renderer or writer is allowed to participate.

This stage is **read-only**. It does not connect to a router, render RouterOS commands, or authorize a change.

## Command

```bash
routerctl routeros-preflight \
  --profile examples/rd-10g-1g/deployment-profile.json \
  --evidence evidence/routeros-readonly.json
```

Exit code `0` means no blocking finding exists in the current preflight scope. A non-zero result means the operator must correct the blocking conditions before continuing.

## Checks

Current checks include:

- deployment-profile validity and secret-reference policy;
- RouterOS discovery evidence schema;
- RouterOS version and capability blockers;
- expected vendor and physical model;
- existence of all enabled WAN and core-uplink interfaces;
- disabled interface detection;
- link-down warnings without assuming a configuration fault;
- routing coverage when Multi-WAN is requested;
- firewall/NAT coverage when security intent is requested;
- WireGuard discovery coverage when WireGuard is requested;
- queue discovery coverage when QoS is requested;
- management-address consistency warning when the discovered IP state does not confirm the target.

## Beginner-safe finding contract

Every finding contains four fields:

```json
{
  "code": "interface.missing",
  "severity": "blocking",
  "message": "WAN wan1g interface 'ether1' is not present in discovery state",
  "remediation": "Verify the selected physical port name and rerun read-only discovery."
}
```

Severity meanings:

- `blocking`: do not progress toward rendering/apply;
- `warning`: operator must review, but the read-only preflight may still be compatible;
- `info`: status guidance only.

## Safety principles

1. A preflight PASS is **not** write authorization.
2. Preflight never repairs a router automatically.
3. It does not enable ports, change routes, alter firewall rules, or create VPN state.
4. A hardware/model mismatch is blocking because it may indicate the wrong management target.
5. A missing requested-feature surface is blocking for that feature instead of being silently ignored.
6. Link-down is reported separately from interface absence so cabling/SFP/ONU issues are not misdiagnosed as configuration errors.

## Current acceptance level

The evaluator is covered by synthetic reference-topology tests. Live CHR discovery evidence remains the next integration gate. The result must not be described as physical CCR2116 acceptance until `ROUTEROS_TARGET_MATRIX.json` contains live evidence for the corresponding target.
