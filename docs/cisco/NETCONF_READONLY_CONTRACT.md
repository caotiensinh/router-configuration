# Cisco IOS XE NETCONF Read-Only Evidence Contract

## Scope

This contract belongs only to the Cisco IOS XE vendor domain. It does not apply to Cisco NX-OS or Cisco IOS XR, and it does not authorize configuration writes.

The implementation is defined by:

- `src/router_configuration/vendors/cisco/netconf_readonly.py`;
- `src/router_configuration/vendors/cisco/data/netconf_readonly_catalog.json`;
- `tests/test_cisco_netconf_readonly.py`;
- `.github/workflows/cisco-netconf-readonly.yml`.

## Authoritative source binding

The NETCONF contract is bound to the official Cisco records in `official_sources.json`, including the release-matched IOS XE 17.18.x and IOS XE 26.x.x NETCONF documentation.

Repository metadata proves documentation scope only. Live admission must still use the capabilities and YANG schema inventory advertised by the connected device.

## Read-only boundary

The only catalogued RPC operations are:

- `get` with a bounded subtree filter;
- `get-config` from `running` with a bounded subtree filter;
- `get-schema` with an explicit model identifier.

The read-only validator fails closed on mutation/control operations including `edit-config`, `copy-config`, `delete-config`, `commit`, `discard-changes`, `lock`, `unlock`, `kill-session`, and `action`. An `nc:operation` mutation attribute is also rejected even when nested inside an otherwise read-only request.

`production_write_authorized` remains `false`.

## Evidence minimization and secret handling

Evidence queries must request only the subtree needed for the stated fact. The C03 contract deliberately does not retrieve an unrestricted running configuration.

Parsed evidence is rejected when sensitive field names are present, including password, secret, private-key, pre-shared-key/PSK, token, community, and key-string fields. DTD/entity declarations are rejected and NETCONF XML evidence is size bounded.

## C03 live acceptance gate

Synthetic fixtures and contract tests prove parser and policy behavior, but they do not complete C03.

C03 acceptance requires an identified live IOS XE target and preserved evidence for at least:

1. NETCONF server `<hello>` and base capability;
2. device-advertised YANG capability/schema inventory;
3. exact IOS XE version read through a bounded, source-bound query;
4. exact device identity/model evidence;
5. bounded interface inventory and operational-state evidence;
6. deterministic normalized digests;
7. confirmation that no configuration write was authorized or performed.

Virtual IOS XE evidence must identify the image/platform used and cannot be represented as physical-hardware evidence. Physical-device acceptance remains a later, separately attested gate.

## Progress accounting

C03 carries 10 points in `CISCO_PROGRESS.json`. Implementation, documentation, synthetic fixtures, and CI contract success alone earn zero C03 acceptance points. The points may move only after the live acceptance evidence above exists and passes the repository gates.
