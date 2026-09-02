# RouterOS Read-Only Discovery Contract

## Purpose

Phase 1 must learn the current RouterOS state before any renderer or writer is enabled. Discovery is intentionally independent from configuration mutation.

## Hard safety boundary

`RouterOSRestClient` exposes **GET only** and accepts only named surfaces from `READ_SURFACES`.

No generic POST/PUT/PATCH/DELETE method exists in the discovery client. This is deliberate: RouterOS REST maps GET to read/print operations, while other methods can mutate state or access console commands.

Plain HTTP is rejected by default. It can be explicitly enabled only for a controlled lab. TLS verification is enabled by default.

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

## Secret handling

Any key whose name indicates password, private key, pre-shared key, PSK, secret or token is replaced with `<redacted>` before normalized state is emitted.

This matters especially for WireGuard: RouterOS can expose private-key material in detailed interface output. The normalized state must never persist it.

## Normalization contract

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

## Current limitation

This phase provides the read-only REST client and fixture-backed normalizer. Live hardware evidence has not yet been recorded. A physical router writer remains disabled.
