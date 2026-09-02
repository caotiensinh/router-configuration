# RouterOS Read-Only Discovery Contract

## Purpose

Phase 1 must learn the current RouterOS state before any renderer or writer is enabled. Discovery is intentionally independent from configuration mutation.

## Hard safety boundary

`RouterOSRestClient` exposes **GET only** and accepts only named surfaces from `READ_SURFACES`.

No generic POST/PUT/PATCH/DELETE method exists in the discovery client. This is deliberate: RouterOS REST maps GET to read/print operations, while PATCH/PUT/DELETE mutate resources and POST is a universal console-command method.

Official RouterOS REST documentation records REST support starting with RouterOS `7.1beta4`. Production discovery therefore requires RouterOS v7 at or above that REST baseline. See:

- https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST%20API
- `ROUTEROS_TARGET_MATRIX.json`

Plain HTTP is rejected by default. MikroTik also advises against HTTP REST because credentials can be passively observed. Production mode therefore requires HTTPS with certificate verification. HTTP or disabled TLS verification is accepted only when the CLI is explicitly run with `--lab`.

The REST base URL must be only `scheme://host[:port]`. Credentials embedded in the URL, extra paths, query strings and fragments are rejected.

## Least-privilege discovery identity

Do not use the full administrator account for routine discovery.

RouterOS user policies separate `read`, `write`, `sensitive`, `sniff`, `rest-api` and other privileges. The default RouterOS `read` group includes additional permissions such as sensitive/sniff/reboot, so it should not be treated as a minimal service account.

For production, create a dedicated account/group that grants only the policies required for approved REST read access, excludes write/policy/sensitive/sniff privileges, and restricts the account/source network to the management plane. The exact group must be verified against the target RouterOS release before acceptance.

Official user-policy reference:

- https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User

## Initial surfaces

- system identity;
- system resource/version/board information;
- interfaces;
- IPv4 addresses;
- IPv4 routes;
- routing tables;
- firewall filter;
- firewall NAT;
- WireGuard interfaces;
- WireGuard peers;
- simple queues;
- queue tree.

The surface list is intentionally bounded. New surfaces require a code change, test coverage, and progress-checklist update.

## Live-safe CLI

The CLI deliberately has **no `--password` argument** so credentials are not encouraged into shell history or process listings.

Interactive use can omit the environment variable and enter the password through the hidden prompt:

```bash
routerctl routeros-discover \
  --url https://192.0.2.1 \
  --username routercfg-reader \
  --output evidence/routeros-readonly.json
```

Non-interactive automation should inject the password using the environment variable named by `--password-env` (default: `ROUTEROS_PASSWORD`) from the local secret-management mechanism.

Controlled lab example with a self-signed certificate:

```bash
routerctl routeros-discover \
  --url https://192.0.2.1 \
  --username routercfg-reader \
  --output evidence/lab-routeros.json \
  --lab \
  --no-verify-tls
```

Plain HTTP is even more restricted and requires both `--lab` and `--allow-insecure-http`.

## Partial collection behavior

One unavailable optional surface must not destroy all collected evidence. `collect_report()` records successful surfaces and converts errors to sanitized error codes such as `http_404`, `transport_error`, `timeout`, or an exception class name. Exception messages, URLs and credentials are not persisted into evidence.

Missing identity/resource data is a capability blocker. Missing feature surfaces such as WireGuard or QoS are represented as capability warnings/gaps and prevent the project from falsely claiming coverage.

## Secret handling

Any key whose name indicates password, private key, pre-shared key, PSK, secret or token is replaced with `<redacted>` before normalized state is emitted.

The evidence builder performs a second secret-boundary check and refuses to persist a normalized state containing an unredacted secret-bearing field.

## Normalization and evidence contracts

Raw REST data is converted to deterministic `routeros-state/1` JSON:

- platform identity/version/model;
- interfaces;
- addresses;
- routes/routing tables;
- firewall filter/NAT;
- WireGuard state;
- QoS queues;
- missing-surface list.

List records are deterministically sorted so the same router state produces stable diff input.

`routeros-discovery-evidence/1` then stores only sanitized information:

- UTC observation time;
- normalized-state SHA-256 digest;
- platform metadata;
- sanitized per-surface failures;
- record counts;
- capability assessment;
- redacted normalized state.

Raw RouterOS responses and credentials are deliberately excluded from this artifact. The CLI writes the file atomically and attempts owner-only (`0600`) permissions on platforms that support POSIX modes.

## Evidence levels

`ROUTEROS_TARGET_MATRIX.json` distinguishes three evidence classes:

1. synthetic fixture verified by CI;
2. live RouterOS CHR read-only evidence;
3. physical CCR2116 evidence after CHR acceptance.

Synthetic fixture success must never be presented as live-device acceptance.

## Current limitation

The live-safe discovery command and sanitized evidence format now exist and are CI-tested against synthetic data. **No live CHR or physical CCR2116 discovery evidence has been recorded yet.** A physical router writer remains disabled.
