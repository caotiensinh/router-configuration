# Cisco IOS XE NETCONF Read-Only Evidence Contract

## Scope

This contract belongs only to the Cisco IOS XE vendor domain. It does not apply to Cisco NX-OS or Cisco IOS XR, and it does not authorize configuration writes.

The implementation is defined by:

- `src/router_configuration/vendors/cisco/netconf_readonly.py`;
- `src/router_configuration/vendors/cisco/live_netconf_probe.py`;
- `src/router_configuration/vendors/cisco/data/netconf_readonly_catalog.json`;
- `tests/test_cisco_netconf_readonly.py`;
- `tests/test_cisco_live_netconf_probe.py`;
- `.github/workflows/cisco-netconf-readonly.yml`;
- `.github/workflows/cisco-netconf-live-readonly.yml`.

## Authoritative source binding

The NETCONF contract is bound to the official Cisco records in `official_sources.json`, including the release-matched IOS XE 17.18.x and IOS XE 26.x.x NETCONF documentation.

Repository metadata proves documentation scope only. Live admission must still use the capabilities and YANG schema inventory advertised by the connected device. The live probe retrieves the exact `Cisco-IOS-XE-platform-oper` and `Cisco-IOS-XE-interfaces-oper` schemas before using their operational-state containers.

## Read-only boundary

The only catalogued RPC operations are:

- `get` with a bounded subtree filter;
- `get-config` from `running` with a bounded subtree filter;
- `get-schema` with an explicit model identifier.

The read-only validator fails closed on mutation/control operations including `edit-config`, `copy-config`, `delete-config`, `commit`, `discard-changes`, `lock`, `unlock`, `kill-session`, and `action`. An `nc:operation` mutation attribute is also rejected even when nested inside an otherwise read-only request.

The live probe uses `ncclient==0.7.1`, disables SSH agent/key-file discovery, requires SSH host-key verification, and requires an exact base64 host-key pin. It never invokes a NETCONF write operation.

`production_write_authorized` remains `false`.

## Runtime secrets and host-key pinning

No Cisco credential or host key is stored in repository content. The manually dispatched live workflow consumes these GitHub Actions secrets:

- `CISCO_NETCONF_HOST`;
- `CISCO_NETCONF_PORT` (optional; defaults to 830 when empty);
- `CISCO_NETCONF_USERNAME`;
- `CISCO_NETCONF_PASSWORD`;
- `CISCO_NETCONF_HOSTKEY_B64`.

`CISCO_NETCONF_HOSTKEY_B64` must be the trusted SSH public host-key material encoded as base64. The repository does not auto-discover and trust a new host key. Obtain the pin through an operator-trusted source and validate it out of band before storing it as a secret.

The workflow redirects raw live-probe stdout/stderr to non-uploaded temporary files. Only sanitized JSON evidence is uploaded. Unexpected process failure is represented as `probe_process_failed` without copying the raw exception text into the evidence artifact.

## Evidence minimization and secret handling

Evidence queries request only the subtree needed for the stated fact. The C03 contract deliberately does not retrieve an unrestricted running configuration.

Parsed evidence is rejected when sensitive field names are present, including password, secret, private-key, pre-shared-key/PSK, token, community, and key-string fields. DTD/entity declarations are rejected and NETCONF XML evidence is size bounded.

Hardware serial values are not retained in plaintext live evidence; only a deterministic digest is preserved. Interface evidence stores aggregate state plus a deterministic normalized digest instead of persisting a full device configuration.

Before artifact upload, the workflow removes plaintext target host, device hostname, and transient NETCONF session ID. It preserves deterministic SHA-256 bindings for the target host, device hostname, trusted SSH host-key pin, hardware serial inventory, capabilities, schemas, platform components, and interfaces. This allows later evidence correlation without publishing the target address or hostname.

## C03 live acceptance gate

Synthetic fixtures and contract tests prove parser and policy behavior, but they do not complete C03.

C03 acceptance requires an identified live IOS XE target and preserved evidence for at least:

1. a live NETCONF session with pinned SSH host-key verification;
2. NETCONF server capability inventory;
3. device-advertised YANG/schema inventory and exact live schema retrieval for required models;
4. exact IOS XE hostname and version through a bounded query, with the hostname minimized to an artifact digest after verification;
5. exact platform/model evidence that passes the repository IOS XE platform/version admission gate;
6. bounded interface inventory and operational-state evidence;
7. deterministic normalized digests and minimized target/host-key bindings;
8. confirmation that no configuration write was authorized or performed.

The live workflow fails its acceptance step when `c03_complete` is not exactly `true`. Missing credentials, target outage, authentication failure, unsupported model/version, missing YANG models, host-key mismatch, schema mismatch, or parsing uncertainty are all valid fail-closed outcomes.

Virtual IOS XE evidence must identify the observed target/platform and cannot be represented as physical-hardware evidence. `physical_device_verified` remains `false`; physical-device acceptance is a later, separately attested gate.

## Progress accounting

C03 carries 10 points in `CISCO_PROGRESS.json`. Implementation, documentation, synthetic fixtures, contract CI, and a skipped/unverified live probe earn zero C03 acceptance points. The points may move only after the live acceptance evidence above exists, is exact-head bound, and passes the repository gates.
