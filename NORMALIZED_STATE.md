# Vendor-Neutral Network State Contract

## Purpose

`network-state/1` is the stable state contract between vendor adapters and the vendor-neutral planning core.

Vendor discovery formats must not become the core policy language. RouterOS currently emits `routeros-state/1`; the RouterOS adapter maps that state into `network-state/1`. Future Yamaha and Omada adapters must produce the same core schema rather than teaching the core vendor CLI/API syntax.

## Boundary

```text
Vendor device
   |
Vendor read-only discovery
   |
Vendor state contract
   |  RouterOS: routeros-state/1
   v
Vendor adapter / mapper
   |
network-state/1
   |
State / diff / drift / planning core
```

The core must make policy decisions from normalized fields. Vendor record identifiers may be retained only as `source_ref` for traceability and must not be treated as policy semantics.

## network-state/1 sections

- `device`: vendor, identity, model, firmware version, architecture;
- `interfaces`: name, kind, enabled, operational, source reference;
- `addresses`: address, interface, dynamic status;
- `routes`: destination, gateway, table, distance, active/dynamic status;
- `routing_tables`: name and FIB status;
- `security`: normalized firewall filter and NAT records;
- `vpn`: normalized WireGuard interface/peer state for the current reference adapter;
- `qos`: normalized simple queue and queue-tree state;
- `source`: source vendor schema, missing discovery surfaces and capability map.

## Security invariant

The vendor-neutral state does not carry RouterOS WireGuard private keys or pre-shared keys. Public keys may be retained where required for identity/diff purposes.

A vendor adapter must validate its vendor state before producing `network-state/1`. Unknown top-level core fields are rejected so vendor command syntax cannot be silently inserted into the planning contract.

## Determinism and idempotency

The RouterOS mapper sorts normalized collections deterministically. Equivalent vendor state with different response ordering must produce the same `network-state/1` document.

Passing identical normalized desired/actual state into `StateEngine` must produce a no-op plan. This is covered by regression tests.

## Current acceptance level

The RouterOS-to-core mapper is covered against the synthetic RouterOS 7.24.1 reference fixture. Live CHR evidence remains required before RouterOS discovery/normalization integration is considered accepted on a real target.

This contract does not authorize rendering or writing configuration to a router.
