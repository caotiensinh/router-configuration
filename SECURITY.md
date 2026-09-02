# Security Policy

## Scope

Router Configuration can alter routing, firewall, VPN, QoS, and management-plane configuration. A defect can cause outage or weaken network security, so write operations are treated as high-impact actions.

## Secure-by-default rules

- Default mode is read-only or plan-only.
- Never log credentials, private keys, tokens, pre-shared keys, or complete secret-bearing configuration.
- Secrets are referenced by identifier and resolved only at execution time.
- Do not expose router management services directly to the public Internet as part of an automated baseline.
- A management path must be checked before a route/firewall/interface change.
- Backup must complete before a mutable production operation unless the adapter proves the operation is non-persistent and safely reversible.
- Post-change verification is mandatory before saving persistent configuration.
- A failed verification requires rollback or a controlled stop with an explicit recovery state.
- Experimental/undocumented vendor interfaces are disabled in production mode.
- Production writes require explicit authorization from the caller; an AI/automation agent must not infer approval from context.

## Sensitive output handling

Evidence may include:
- device identifier;
- firmware version;
- interface names;
- normalized route/firewall object identifiers;
- redacted diff;
- test result;
- commit/change-plan identifier.

Evidence must not include plaintext secrets.

## Vulnerability reporting

Do not publish credentials, reachable management addresses, or exploit details for a live deployment in a public issue. Use a private reporting channel when one is configured for the repository owner.