# Yamaha RTX3510 Y03 Normalized-State Boundary

Status: engineering normalization scope; no live or production acceptance claim.

## Source-bound surface

Y03 parses only the part of the RTX3510 operational state whose table semantics are explicit in current Yamaha documentation: plain `show ip route`.

Yamaha documents the command output as:

- destination network;
- gateway;
- interface;
- route type;
- optional protocol-specific information.

Plain `show ip route` is treated as the current IPv4 route table. The separate `detail` form can include hidden static routes and is not fed into the Y03 parser.

## LAN inventory boundary

RTX3510 documentation identifies LAN1 through LAN4, and `show status lanN` is the documented operational inspection command. However, Y03 does not yet have a version-bound machine parser for every LAN output field.

Therefore Y03 records:

- `lan1` through `lan4` as the known interface inventory;
- a SHA-256 digest proving that a caller supplied each LAN observation;
- `operational_state: unknown`;
- `parsed_link_state: false`.

It is forbidden to infer `up`, `down`, speed, duplex, MTU, errors, or counters from synthetic text or undocumented formatting.

## Missing surfaces

The following remain explicitly incomplete instead of being guessed:

- LAN link-state field parser;
- interface addresses;
- routing-table instances beyond the current IPv4 table;
- security state;
- VPN state;
- QoS state.

These omissions are part of the normalized record under `missing_surfaces`.

## Evidence boundary

The Y03 state is deterministic and digest-bound, but caller-supplied data cannot prove transport authenticity or physical hardware. These values remain false:

- `transport_verified`;
- `least_privilege_verified`;
- `live_device_verified`;
- `physical_device_verified`;
- `production_write_authorized`.

Physical RTX3510 verification is an external dependency when hardware is unavailable and does not keep this engineering lane open after code/tests/CI pass.

## Authoritative references

- `YAMAHA-RTX-CMDREF` — current Yamaha Router Series command reference.
- `YAMAHA-RTX3510-USERGUIDE` — RTX3510 user guide and troubleshooting guidance.
- `YAMAHA-RTX3510-SPEC` — RTX3510 physical/interface specification.
