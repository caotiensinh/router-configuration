# Cisco IOS XE C06 — Switch Normalized State

## Scope

C06 normalizes bounded read-only switch operational state from source-bound IOS XE YANG models. This contract does not perform network requests, authorize configuration writes, prove physical hardware, or complete the C06 acceptance gate by itself.

The admitted contract covers:

- interface identity and admin/oper state from `Cisco-IOS-XE-interfaces-oper`;
- VLAN operational state from `Cisco-IOS-XE-vlan-oper`;
- VLAN-scoped MAC address-table state from `Cisco-IOS-XE-matm-oper`;
- spanning-tree instance and port state from `Cisco-IOS-XE-spanning-tree-oper`;
- physical-Ethernet switched-VLAN operational state from the IOS XE-advertised OpenConfig modules.

The trunk blocker is now source-bound. Synthetic fixtures still cannot satisfy the C06 live-state gate.

## Provenance

Cisco's Catalyst 9300 Model-Driven Telemetry material publishes operational paths including:

- `/interfaces-ios-xe-oper:interfaces/interface`;
- `/matm-ios-xe-oper:matm-oper-data`.

The existing Cisco-native schema contract remains pinned to `YangModels/yang` commit `a4ea86b06aa63512e280f1665db6eaf8116bf059`.

The switched-VLAN contract is additionally pinned to CiscoDevNet repository `CiscoDevNet/cisco-ios-xe-openapi-swagger` commit `a4a7b5bc090ab178b5fe75c6a6473ca57cbf5891`:

- IOS XE 17.18.1 tree: `releases/17.18.1/yang-trees/openconfig-vlan.html`, blob `324775059607a2eccd1fcd38d7893ddc79643a29`;
- IOS XE 26.1.1 tree: `releases/26.1.1/yang-trees/openconfig-vlan.html`, blob `defa48042f0e5643d269167023990875a280c34e`;
- 17.18.1 `openconfig-vlan.yang`: `references/17181-YANG-modules/openconfig-vlan.yang`, blob `03090e7d6caf14c6614479b36cdd0311f33fe9fe`;
- 17.18.1 `openconfig-vlan-types.yang`: `references/17181-YANG-modules/openconfig-vlan-types.yang`, blob `5c9f0f13eb99a8b156bd79e8b7fd48d020bea367`.

Runtime device YANG advertisement remains authoritative for admission.

## Source-bound switched-VLAN path

The OpenConfig VLAN module augments the physical Ethernet interface tree at:

```text
/oc-if:interfaces/oc-if:interface/oc-eth:ethernet/
  oc-vlan:switched-vlan/oc-vlan:state
```

The enclosing interface list key is `oc-if:name`.

The `state` container is `config false` and reuses the switched-VLAN fields:

- `interface-mode`;
- `native-vlan`;
- `access-vlan`;
- `trunk-vlans`.

The source-defined interface-mode enum is exactly:

- `ACCESS`;
- `TRUNK`.

`native-vlan` and `trunk-vlans` are valid only for `TRUNK`. `access-vlan` is valid only for `ACCESS`.

The source-defined VLAN ID type is `uint16` with range `1..4094`. A trunk VLAN entry is either one VLAN ID or an inclusive range encoded as `x..y`, where `x < y`. The model states that when `trunk-vlans` is not specified for a trunk interface, all VLANs are allowed.

The runtime inventory must advertise all of the following before switched-VLAN observations are admitted:

- `openconfig-interfaces`;
- `openconfig-if-ethernet`;
- `openconfig-vlan`;
- `openconfig-vlan-types`.

The current C06 implementation normalizes the physical Ethernet augment only. The OpenConfig LAG switched-VLAN augment is not silently admitted into this implementation.

## Other pinned schema semantics

- `Cisco-IOS-XE-vlan-oper`: `/vlan-ios-xe-oper:vlans/vlan`, list key `id`, status enum `active|suspend`;
- `Cisco-IOS-XE-matm-oper`: `/matm-ios-xe-oper:matm-oper-data`, outer table key `table-type vlan-id-number`, nested MAC key `table-type vlan-id-number mac`;
- `Cisco-IOS-XE-spanning-tree-oper`: `/stp-ios-xe-oper:stp-details/stp-detail`, instance key `instance`, nested interface key `name`, source-defined role/state enums.

IOS XE 17.18 and 26 use separate pinned STP schema blobs. A common shape is admitted only for fields verified in both source files; later train-specific additions are not silently backported.

## Normalization boundaries

### Interfaces

The bounded interface observation requires `name`, `admin-status`, and `oper-status`. Duplicate interface keys and unsupported source enum values fail closed.

### VLANs

VLAN records preserve the Cisco source `uint16` ID contract rather than introducing an unsourced operational range. VLAN name is optional. Assigned `ports` and `vlan-interfaces` are canonicalized deterministically; duplicate decoded entries are rejected.

### MAC address table

The bounded L2 observation admits only `mat-vlan` MATM records. It normalizes VLAN ID, canonical MAC address, source-defined address type (`static|dynamic|any`), port, and `vlan-all` presence. VLAN-independent and L3 MATM table types are not silently mixed into this contract.

### Spanning tree

The contract normalizes per-instance bridge/root attributes and keyed STP interfaces. Port role and state must match the source YANG enumerations. Duplicate instances or duplicate interface keys within one instance fail closed.

### Switched VLAN / trunk

Each decoded switched-VLAN record is keyed by its enclosing interface name. Normalization:

- validates `ACCESS|TRUNK` exactly;
- validates OpenConfig VLAN IDs as `1..4094`;
- expands `x..y` trunk ranges deterministically;
- sorts and de-duplicates expanded VLAN IDs;
- records `all_vlans_allowed=true` only for a `TRUNK` observation with no explicit `trunk-vlans`;
- rejects trunk-only fields on `ACCESS`;
- rejects `access-vlan` on `TRUNK`;
- rejects duplicate switched-VLAN interface keys;
- rejects references to an interface absent from the admitted interface observation.

No VLAN membership, STP state, interface name pattern, or Cisco CLI output is reinterpreted as trunk evidence.

## Admission and safety

Before base normalization:

1. model/version must pass the existing C02 admission classifier;
2. device role must be `switch`;
3. IOS XE train must be source-bound (`17.18` or `26`);
4. a valid observed YANG inventory SHA-256 digest is required;
5. all four Cisco-native base observation modules must be advertised;
6. sensitive fields are rejected recursively.

Before switched-VLAN normalization, the four OpenConfig modules listed above must also be advertised.

A successful source-bound switched-VLAN parse sets:

```text
trunk_state_verified=true
c06_contract_complete=true
```

This means the normalized-state contract now has a source-bound trunk observation. It does **not** mean the project acceptance gate is complete.

The normalizer deliberately retains:

```text
c06_complete=false
production_write_authorized=false
physical_device_verified=false
```

because `synthetic_fixture_can_complete_c06=false` and identified live-state evidence is still required. Contract CI therefore proves parser/schema behavior only; it cannot award C06 ledger points by itself.

C06 can close only after an identified live IOS XE switch supplies accepted source-bound observations for the required switch state and the evidence is validated under the repository governance rules.
