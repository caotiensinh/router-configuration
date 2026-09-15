# Cisco IOS XE C05 — Router Normalized State

## Scope

C05 normalizes read-only router operational state from validated IOS XE YANG models. It does not execute a network request, authorize a write, or satisfy the C05 live acceptance gate by itself.

Initial bounded state:

- interface identity and operational state from `Cisco-IOS-XE-interfaces-oper`;
- VRF, IPv4 address/subnet mask and IPv6 address list exposed by that operational model;
- default IPv4 RIB routes from `ietf-routing`.

## Source-bound paths

Cisco's Model-Driven Telemetry material publishes:

- `Cisco-IOS-XE-interfaces-oper` → `/interfaces-ios-xe-oper:interfaces/interface`;
- `ietf-routing` default IPv4 RIB example → `/rt:routing-state/routing-instance[name="default"]/ribs/rib[name="ipv4-default"]/routes/route`.

The schema contract is pinned to the Cisco IOS XE 17.18.1 and 26.1.1 model bundles in `YangModels/yang` at commit `a4ea86b06aa63512e280f1665db6eaf8116bf059`. Runtime device YANG advertisement remains authoritative: the normalizer refuses input unless both required module names are present in an observed inventory and that inventory has a SHA-256 evidence digest.

## Interface normalization

Required leaves:

- `name`;
- `admin-status`;
- `oper-status`.

Bounded optional leaves:

- `vrf`;
- `ipv4` + `ipv4-subnet-mask` as an inseparable observed pair;
- `ipv6-addrs`.

IPv4 address and mask are converted to CIDR only after contiguous-mask validation. IPv6 entries are parsed and canonicalized. Duplicate interface names are rejected because the source YANG list is keyed by `name`.

## Route normalization

The bounded observation is the default IPv4 RIB only. Each route is keyed by `destination-prefix` in `ietf-routing`, so duplicate destination prefixes are rejected. IPv6 prefixes are rejected from this bounded observation rather than silently mixed into the IPv4 RIB.

Normalized route fields include:

- destination prefix;
- source protocol;
- route preference;
- metric;
- simple next-hop interface/address or special next-hop;
- active presence;
- last-updated;
- update-source.

YANG choice semantics are enforced: a special next-hop cannot also carry a simple next-hop interface/address.

## Admission and safety

Before normalization:

1. the model/version pair must pass the existing C02 platform classifier;
2. role must be `router`;
3. IOS XE train must be source-bound (`17.18` or `26`);
4. a valid observed YANG inventory digest is required;
5. `Cisco-IOS-XE-interfaces-oper` and `ietf-routing` must both be advertised;
6. sensitive fields are rejected recursively.

Output is deterministic and includes source catalog and normalized-state digests. `c05_complete` remains hard-coded false in this contract layer. Synthetic fixtures and parser CI cannot award C05 points; a later live-state acceptance layer must bind model payloads, device identity/version, schema inventory, and exact source commit evidence.

Production write and physical-device claims remain disabled.
