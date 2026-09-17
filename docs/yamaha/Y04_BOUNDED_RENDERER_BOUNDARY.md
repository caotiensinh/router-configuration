# Yamaha RTX3510 Y04 — Bounded Renderer Boundary

## Scope

Y04 provides deterministic candidate rendering for a deliberately narrow Yamaha RTX3510 / Rev.23.01.03 subset. It is an engineering dry-run surface only.

Supported candidate operations:

- IPv4 interface address on `lan1` through `lan4` using `ip <interface> address <ipv4>/<prefix>`;
- one IPv4 gateway per static route destination using `ip route <destination> gateway <ipv4>`;
- `default` as a route destination.

Everything outside this subset fails closed.

## Explicit non-capabilities

Y04 does **not** provide or authorize:

- transport to a router;
- command execution;
- `save`;
- production write;
- physical-device verification;
- human approval substitution;
- automatic rollback execution;
- IPv6 configuration;
- PP/DHCP/tunnel gateway forms;
- multiple gateways per destination;
- VLAN, firewall/filter, NAT, VPN, QoS, DHCP, DNS, AAA, logging, or other Yamaha configuration surfaces.

Unsupported input must return an error instead of being approximated.

## Safety contract

Every generated plan must keep all of the following false:

- `transport_authorized`
- `apply_authorized`
- `save_authorized`
- `production_write_authorized`
- `physical_device_verified`

Every generated plan must keep all of the following true:

- `requires_current_state`
- `requires_prechange_backup`
- `requires_human_approval`
- `requires_postchange_verification`

The plan also records `rollback_strategy=restore_verified_prechange_state` as a precondition for any later governed write lane. Y04 itself does not execute rollback.

## Provenance and tamper resistance

The renderer is source-bound to the validated Yamaha offline knowledge package and records:

- exact vendor/model/firmware;
- Yamaha documentation source IDs;
- knowledge-package SHA-256;
- plan SHA-256.

Validation reparses every rendered command semantically. A rehashed but malformed IPv4 address or an unapproved command such as `save` must still fail validation.

## Acceptance boundary

Passing unit/synthetic/CI tests proves only the renderer and validator logic for this bounded subset.

It does **not** prove live Yamaha CLI behavior, device transport, least privilege, physical hardware behavior, production readiness, or deployment success.

If RTX3510 hardware is unavailable, those hardware-only checks remain external/deferred and do not keep Y04 engineering scope open.
