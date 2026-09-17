# Cisco IOS XE RESTCONF Live Read-Only Probe

## Purpose

This lane prepares C04 for live IOS XE RESTCONF read-only acceptance without authorizing configuration mutation. The probe is deliberately narrower than a general RESTCONF client and executes only source-bound `GET` requests from the validated offline catalog.

## Authoritative Cisco basis

The active source manifest binds this contract to official Cisco IOS XE 17.18.x and 26.x.x RESTCONF protocol guides. Those guides document:

1. `GET /.well-known/host-meta` for RESTCONF root discovery;
2. `/restconf` as the discovered API root;
3. `GET` as a read operation;
4. `application/yang-data+xml` and `application/yang-data+json` representations;
5. `GET /restconf/data/ietf-restconf-monitoring:restconf-state/capabilities` for capability discovery;
6. the advertised capability `urn:ietf:params:restconf:capability:fields:1.0`;
7. `fields=` URI examples for bounded reads.

The project does not copy Cisco examples that disable TLS verification. Repository security policy is stricter: certificate and hostname verification are mandatory.

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
admit documented IOS XE train (17.18 or 26)
        |
        v
bind independent same-target platform evidence
        |
        v
C02 exact platform/version admission
```

The identity query is denied unless the same live probe has already observed the `fields:1.0` capability. Documentation scope is not treated as runtime capability evidence.

## TLS boundary

The implementation uses Python's verified TLS context:

- hostname checking stays enabled;
- `CERT_REQUIRED` stays mandatory;
- system trust is used by default;
- an optional custom CA bundle may be supplied as base64-encoded PEM;
- an optional peer-certificate SHA-256 pin may be supplied;
- there is no `verify=False`, `-k`, insecure fallback, or redirect following;
- all three requests must observe the same peer-certificate digest.

A certificate change or pin mismatch fails closed.

## Credential boundary

Runtime values are supplied through environment variables / GitHub Secrets:

- `CISCO_RESTCONF_HOST`
- `CISCO_RESTCONF_PORT` (optional; default 443)
- `CISCO_RESTCONF_USERNAME`
- `CISCO_RESTCONF_PASSWORD`
- `CISCO_RESTCONF_CA_PEM_B64` (optional)
- `CISCO_RESTCONF_CERT_SHA256` (optional stronger certificate pin)

Credentials are used only to build an in-memory Authorization header. They are not stored in evidence, repository content, command-line arguments, or uploaded artifacts. Missing credential evidence records only a count.

## Exact platform cross-binding

RESTCONF root/capability/hostname/version evidence does not, by itself, prove an exact Cisco platform model. The project therefore does **not** invent a model-discovery path.

To satisfy the existing C04 hard gate, live RESTCONF evidence must be bound to independent platform evidence for the same target, preferably accepted C03 NETCONF evidence. Manual dispatch supplies:

- `CISCO_RESTCONF_PLATFORM_MODEL`
- `CISCO_RESTCONF_PLATFORM_TARGET_SHA256`
- `CISCO_RESTCONF_PLATFORM_EVIDENCE_SHA256`

The platform target digest must equal the RESTCONF target-host digest. The model plus the live RESTCONF IOS XE version must then pass the C02 `assess_read_only_candidate` classifier.

If HTTPS/root/capability/identity/version all succeed but independent platform evidence is missing, malformed, bound to another target, or not admitted by C02, the artifact records the successful RESTCONF observations but keeps `c04_complete=false`.

## Evidence minimization

Sanitized evidence may contain:

- exact source commit SHA;
- offline knowledge digest;
- target-host SHA-256;
- peer-certificate SHA-256;
- RESTCONF root proof digest;
- capability count and inventory digest;
- whether `fields:1.0` was observed;
- device-hostname SHA-256;
- IOS XE version and admitted documentation train;
- identity digest;
- admitted platform family/model only after independent platform binding;
- independent platform evidence digest;
- explicit GET-only / TLS / redirect / write-authority boundaries.

It does not persist username, password, Authorization header, plaintext target host, plaintext device hostname, raw exception text, or raw RESTCONF response bodies.

## Workflow behavior

`.github/workflows/cisco-restconf-live-readonly.yml` has two roles.

### Pull request / push

Only contract and synthetic unit tests run. No live RESTCONF network request is made.

### Manual `workflow_dispatch`

The `live-readonly` job may run when the operator has supplied runtime secrets and independent platform evidence. Probe stdout/stderr are redirected away from Actions logs. A sanitized artifact is uploaded even when the live gate fails.

The final workflow step passes only when `c04_complete=true`, TLS/redirect/write boundaries remain safe, `fields:1.0` was observed, and same-target independent platform evidence passed C02 admission.

## C04 acceptance boundary

Synthetic fixtures, contract tests, and implementation readiness do not earn C04 points. C04 remains incomplete until exact-head sanitized evidence from an identified live IOS XE RESTCONF target satisfies the full live gate.

`production_write_authorized=false` and `physical_device_verified=false` remain mandatory. Physical Cisco acceptance is a separate later gate.
