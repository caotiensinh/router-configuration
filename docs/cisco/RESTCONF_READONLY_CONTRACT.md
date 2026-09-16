# Cisco IOS XE RESTCONF Read-Only Evidence Contract

## Scope

This contract belongs only to the Cisco IOS XE vendor domain. It establishes deterministic RESTCONF read-only request and evidence rules; it does not authorize configuration writes and it does not claim live or physical-device acceptance.

Implementation surfaces:

- `src/router_configuration/vendors/cisco/restconf_readonly.py`;
- `src/router_configuration/vendors/cisco/data/restconf_readonly_catalog.json`;
- `src/router_configuration/vendors/cisco/knowledge.py`;
- `tests/test_cisco_restconf_readonly.py`;
- `.github/workflows/cisco-restconf-readonly.yml`.

## Authoritative source binding

The catalog is bound to release-matched official Cisco IOS XE 17.18.x and 26.x.x RESTCONF documentation. Cisco documents RESTCONF over HTTPS, maps `GET` to read behavior, describes RESTCONF root discovery using `/.well-known/host-meta`, and documents the `fields` query parameter including semicolon-separated field selection.

Documentation scope does not prove that a live device has RESTCONF enabled. C04 remains incomplete until live HTTPS evidence is collected from an identified IOS XE target.

## Deterministic query catalog

AI and callers are not allowed to invent arbitrary RESTCONF paths. A request must reference a known `query_id` whose exact relative URI, media type, response kind, and source IDs are stored in the validated offline catalog.

Initial queries are deliberately narrow:

- `restconf-root-discovery`: `/.well-known/host-meta` with `Accept: application/xrd+xml`;
- `native-identity`: `/restconf/data/Cisco-IOS-XE-native:native?fields=hostname;version` with `Accept: application/yang-data+json`.

The identity query is bounded to the two facts required for version/identity admission and must not be replaced by an unrestricted native-config retrieval.

## Transport and method boundary

A request is allowed only when all of these are true:

- method is exactly `GET`;
- URL is absolute HTTPS;
- TLS certificate verification is enabled;
- redirect following is disabled;
- credentials are not embedded in the URL;
- URL path and query exactly match the selected catalog entry;
- `Accept` matches the catalogued media type.

`POST`, `PUT`, `PATCH`, and `DELETE` are explicitly blocked. No C04 primitive grants write authority.

## Response safety

RESTCONF evidence is size bounded and must have the expected HTTP status and media type.

XRD root-discovery evidence rejects DTD/entity declarations and must prove exactly one RESTCONF root href: `/restconf`.

YANG JSON evidence is recursively checked for sensitive key names including passwords, secrets, private keys, PSKs, tokens, communities, and key strings. The native identity parser additionally requires the returned native container to contain only `hostname` and `version`; a server response that ignores the bounded field selection and returns a broader tree is rejected.

## C04 live acceptance boundary

Synthetic fixtures and CI contract success cannot complete C04. Live acceptance requires, at minimum:

1. an identified IOS XE target with RESTCONF enabled;
2. HTTPS with certificate verification enabled;
3. root discovery proving `/restconf` without redirect following;
4. a source-bound, bounded identity read;
5. exact IOS XE platform/version admission consistent with the repository Cisco domain;
6. sanitized, deterministic evidence digests;
7. confirmation that no RESTCONF write method was authorized or performed.

`production_write_authorized=false` and `physical_device_verified=false` remain mandatory. Physical Cisco acceptance is a later independent gate.

## Progress accounting

C04 carries 8 points in `CISCO_PROGRESS.json`. Catalog work, parser tests, documentation, CI, and synthetic fixtures earn zero C04 acceptance points. The score may increase only after a live C04 acceptance artifact exists and passes the repository governance gates.
