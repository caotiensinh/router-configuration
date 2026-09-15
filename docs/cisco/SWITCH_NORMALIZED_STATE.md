# Cisco IOS XE C06 — Switch Normalized State

## Scope

C06 normalizes bounded read-only switch operational state from source-bound IOS XE YANG models. This contract does not perform network requests, authorize configuration writes, prove physical hardware, or complete the C06 acceptance gate by itself.

The admitted contract currently covers:

- interface identity and admin/oper state from `Cisco-IOS-XE-interfaces-oper`;
- VLAN operational state from `Cisco-IOS-XE-vlan-oper`;
- VLAN-scoped MAC address-table state from `Cisco-IOS-XE-matm-oper`;
- spanning-tree instance and port state from `Cisco-IOS-XE-spanning-tree-oper`.

Trunk operational state is intentionally **UNVERIFIED** in this contract. VLAN membership, interface names, or STP port data must not be reinterpreted as trunk evidence.

## Provenance

Cisco's Catalyst 9300 Model-Driven Telemetry material publishes operational paths including:

- `/interfaces-ios-xe-oper:interfaces/interface`;
- `/matm-ios-xe-oper:matm-oper-data`.

The source-bound schema contract is pinned to `YangModels/yang` commit `a4ea86b06aa63512e280f1665db6eaf8116bf059` and exact IOS XE model-bundle paths for 17.18.1 and 26.1.1. Runtime device schema advertisement remains authoritative: all four required module names must be observed and the inventory must carry a SHA-256 evidence digest before normalization.

Pinned schema semantics include:

- `Cisco-IOS-XE-vlan-oper`: `/vlan-ios-xe-oper:vlans/vlan`, list key `id`, status enum `active|suspend`;
- `Cisco-IOS-XE-matm-oper`: `/matm-ios-xe-oper:matm-oper-data`, outer table key `table-type vlan-id-number`, nested MAC key `table-type vlan-id-number mac`;
- `Cisco-IOS-XE-spanning-tree-oper`: `/stp-ios-xe-oper:stp-details/stp-detail`, instance key `instance`, nested interface key `name`, source-defined role/state enums.

IOS XE 17.18 and 26 use separate pinned STP schema blobs. A common shape is admitted only for fields verified in both source files; later 26-only additions are not silently backported to 17.18.

## Normalization boundaries

### Interfaces

The bounded interface observation requires `name`, `admin-status`, and `oper-status`. Duplicate interface keys and unsupported source enum values fail closed.

### VLANs

VLAN records preserve the source `uint16` ID contract rather than introducing an unsourced operational range. VLAN name is optional. Assigned `ports` and `vlan-interfaces` are canonicalized deterministically; duplicate decoded entries are rejected.

### MAC address table

The initial bounded L2 observation admits only `mat-vlan` MATM records. It normalizes VLAN ID, canonical MAC address, source-defined address type (`static|dynamic|any`), port, and `vlan-all` presence. VLAN-independent and L3 MATM table types are not silently mixed into this bounded contract.

### Spanning tree

The contract normalizes per-instance bridge/root attributes and keyed STP interfaces. Port role and state must match the source YANG enumerations. Duplicate instances or duplicate interface keys within one instance fail closed.

## Admission and safety

Before normalization:

1. model/version must pass the existing C02 admission classifier;
2. device role must be `switch`;
3. IOS XE train must be source-bound (`17.18` or `26`);
4. a valid observed YANG inventory SHA-256 digest is required;
5. all four admitted modules must be advertised;
6. sensitive fields are rejected recursively.

Output is deterministic and includes catalog and normalized-state digests. The parser fixes `trunk_state_verified=false` and `c06_complete=false`. Synthetic fixtures and contract CI cannot award C06 points.

C06 can close only after an identified live IOS XE switch target supplies accepted source-bound evidence for the required switch state, including a separately admitted trunk operational-state model/path. Production write and physical-device claims remain disabled.
