# Omada Gateway Remote-Access VPN — Evidence Note

Task: `5.10 VPN — remote access`
Micro-task: `5.10.A official-source evidence normalization`
Status: `EVIDENCE_ONLY_CANDIDATE`

## Official sources

1. Omada Controller User Guide V6.0: https://support.omadanetworks.com/en/document/111217/
2. Controller v6.2 VPN Overview: https://support.omadanetworks.com/us/document/118322/
3. WireGuard VPN on Omada Gateway, updated 2026-06-30: https://support.omadanetworks.com/en/document/13314/
4. PPTP/L2TP VPN Server in Controller Mode, updated 2026-07-20: https://support.omadanetworks.com/us/document/13052/
5. VPN tunnel access troubleshooting, updated 2026-08-28: https://support.omadanetworks.com/us/document/13048/

## Source-supported scope

- Omada documents Client-to-Site VPN for a remote host accessing a central LAN.
- Controller 6.2 reorganizes VPN configuration into VPN Server, VPN Client, and Site-to-Site tabs; controller-version UI behavior must therefore remain version-scoped.
- Documented remote-access families include server/client workflows and protocol-specific configuration. WireGuard has documented Client-to-Site workflows in standalone and Controller modes; the Controller guide also documents OpenVPN and other protocol families.
- Protocol availability, authentication mode, tunnel mode, account handling, route scope, model/firmware/region support, and controller version must be applicability-scoped rather than inferred across devices/releases.
- A tunnel reporting connected is not sufficient proof of remote-LAN access; routing, firewall/policy, intended resource reachability, and negative/non-authorized flow behavior need independent verification.

## Security and evidence boundary

- Vendor capability is not project security policy. A documented legacy protocol is not automatically an approved deployment choice.
- Passwords, PSKs, private keys, exported client secrets/config secrets, tokens, and certificate private material must never enter evidence artifacts.
- Unknown exact-device or exact-version support is `NOT_SUPPORTED_UNVERIFIED`.
- Remote-access policy must preserve management reachability and existing VPN/routing behavior.
- This note grants no production write authority and no hardware-equivalence claim.

## Next micro-tasks

- `5.10.B` normalized remote-access VPN schema.
- `5.10.C` authentication/routing/conflict and secret-boundary rules.
- `5.10.D` positive/negative verification contract.
- `5.10.E` target tests and CI discovery.
