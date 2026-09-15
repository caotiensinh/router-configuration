# Cisco IOS XE RESTCONF Live Read-Only Probe

## Purpose

This lane prepares C04 for live IOS XE RESTCONF read-only acceptance without
authorizing configuration mutation.

The probe is intentionally narrower than a general RESTCONF client. It executes
only source-bound `GET` requests that exist in
`restconf_readonly_catalog.json`.

## Authoritative Cisco basis

The active source manifest binds this contract to the official Cisco IOS XE
17.18.x and 26.x.x RESTCONF protocol guides.

Those guides document:

1. `GET /.well-known/host-meta` for RESTCONF root discovery;
2. `/restconf` as the discovered RESTCONF API root;
3. RESTCONF `GET` as a read operation;
4. both `application/yang-data+xml` and `application/yang-data+json` media representations;
5. `GET /restconf/data/ietf-restconf-monitoring:restconf-state/capabilities` for RESTCONF capability discovery;
6. the advertised capability `urn:ietf:params:restconf:capability:fields:1.0`;
7. `fields=` URI examples for bounded RESTCONF reads.

The project does not copy Cisco examples that disable TLS verification. Project
security governance is stricter: certificate and hostname verification are mandatory.

## Live sequence

```text
HTTPS + verified certificate
        |
        v
GET /.well-known/host-meta
        |
        v
prove /restconf root
        |
        v
GET /restconf/data/ietf-restconf-monitoring:restconf-state/capabilities
        |
        v
prove fields:1.0 was actually advertised
        |
        v
GET /restconf/data/Cisco-IOS-XE-native:native?fields=hostname;version
        |
        v
admit only documented IOS XE train (17.18 or 26)
```

The identity query is fail-closed unless the same live probe has already
observed the `fields:1.0` capability. Documentation scope by itself is not
treated as runtime feature availability.

## TLS boundary

The implementation uses Python's verified TLS context:

- hostname checking remains enabled;
- `CERT_REQUIRED` remains mandatory;
- system trust is used by default;
- an optional custom CA bundle may be supplied as base64-encoded PEM;
- there is no `verify=False`, `-k`, insecure fallback, or redirect following;
- the peer certificate is persisted only as a SHA-256 digest.

The same certificate digest must be observed throughout the three-request probe.
A certificate change during one probe fails closed.

## Credential boundary

Runtime inputs are supplied through environment variables / GitHub Secrets:

- `CISCO_RESTCONF_HOST`
- `CISCO_RESTCONF_PORT` (optional; defaults to 443)
- `CISCO_RESTCONF_USERNAME`
- `CISCO_RESTCONF_PASSWORD`
- `CISCO_RESTCONF_CA_PEM_B64` (optional custom trust anchor)

Credentials are used only to build an in-memory HTTP Authorization header.
They are not stored in evidence, repository files, command-line arguments, or
uploaded artifacts.

Missing credential evidence records only a count. It does not list secret field
names.

## Evidence minimization

Successful sanitized evidence may contain:

- exact source commit SHA;
- offline knowledge digest;
- hashed target endpoint;
- peer-certificate SHA-256;
- RESTCONF root proof digest;
- capability count and capability inventory digest;
- whether `fields:1.0` was observed;
- hashed device hostname;
- IOS XE version and admitted documentation train;
- identity digest;
- explicit `GET`-only / TLS / redirect / write-authority boundaries.

It does not persist:

- username;
- password;
- Authorization header;
- plaintext target host;
- plaintext device hostname;
- raw exception text;
- raw RESTCONF response bodies.

## Workflow behavior

`.github/workflows/cisco-restconf-live-readonly.yml` has two different roles.

### Pull request / push

Only contract and synthetic unit tests run. No live RESTCONF network request is made.

### Manual `workflow_dispatch`

The `live-readonly` job may run when the operator has provided the runtime
secrets. Missing secrets, external target outages, authentication failures, TLS
failures, unsupported IOS XE versions, or missing runtime capabilities produce
sanitized non-completion evidence.

A successful workflow job is not automatically C04 acceptance. The uploaded
artifact must show `c04_complete=true` and must be reviewed against the C04 hard gate.

## C04 acceptance boundary

Synthetic fixtures prove parser and safety behavior only. They cannot complete C04.

C04 remains incomplete until sanitized exact-head evidence from an identified
live IOS XE RESTCONF target proves the required read-only sequence.

This lane does not claim:

- physical-device verification;
- production write authorization;
- platform-model admission;
- Cisco NX-OS or IOS XR support;
- configuration deployment success.

`production_write_authorized` and `physical_device_verified` remain `false`.
