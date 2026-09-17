# Omada Gateway Site-to-Site VPN — Evidence Note

Task: `5.09 VPN — site-to-site`
Micro-task: `5.09.A official-source evidence normalization`
Status: `EVIDENCE_ONLY_CANDIDATE`

## Official sources

1. Omada Controller User Guide V6.0: https://support.omadanetworks.com/en/document/111217/
2. Auto IPsec in Controller Mode, updated 2026-08-28: https://support.omadanetworks.com/jp/document/13051/
3. Manual IPsec via Omada Controller v5, updated 2026-07-17: https://support.omadanetworks.com/en/document/13297/

## Source-supported facts

- Omada managed gateways expose separate Site-to-Site and Client-to-Site VPN purposes.
- Site-to-Site IPsec supports Auto IPsec and Manual IPsec workflows.
- Auto IPsec is controller-orchestrated between two sites under the same controller and requires an Omada managed gateway at the remote site.
- Manual IPsec is configured against an explicit remote peer and explicit remote networks/subnets.
- Local and remote routed network scope must remain explicit; overlapping local/remote LAN scope must not be guessed or silently accepted.
- Tunnel creation alone is not sufficient acceptance evidence; operational status and expected reachability must be verified separately.

## Security and evidence boundary

- PSKs, private keys, passwords, tokens, and other secret values must never be copied into knowledge/evidence artifacts.
- Exact protocol, algorithm, model, firmware, region, and controller-version support must remain applicability-scoped to authoritative source evidence.
- Unsupported or unknown capability is `NOT_SUPPORTED_UNVERIFIED`, never inferred from a different model or release.
- Existing management reachability and unaffected VPNs must be treated as protected dependencies during any future mutation workflow.
- This note does not authorize configuration writes and does not claim hardware validation.

## Next micro-tasks

- `5.09.B` normalized machine-readable schema.
- `5.09.C` dependency/conflict and secret-boundary rules.
- `5.09.D` positive/negative verification contract.
- `5.09.E` unit tests and CI discovery.
