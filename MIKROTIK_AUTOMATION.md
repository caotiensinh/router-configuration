# MikroTik Intent-Driven Automation

## Purpose

MikroTik is the first production-reference vendor for this repository.

The target operator experience is **intent in -> verified network state out**.
An operator should describe the network outcome, not memorize RouterOS CLI
syntax. RouterOS commands remain an implementation detail generated only after
discovery, validation, policy compilation and safety gates.

This document adds the MikroTik-specific contract without weakening the
vendor-neutral architecture or the existing rule that production writes are
disabled until acceptance gates are complete.

## Official knowledge sources

Source precedence is mandatory:

1. `https://manual.mikrotik.com/docs/` — current authoritative RouterOS manual.
2. `https://manual.mikrotik.com/llms.txt` — current page index for retrieval.
3. `https://manual.mikrotik.com/llms-full.txt` — current full corpus for bulk
   indexing and documentation-diff jobs.
4. Per-page Markdown (`.md`) and `sitemap.xml` — deterministic ingestion and
   completeness checks.
5. `https://help.mikrotik.com/docs/` — legacy/history only. It must never
   override conflicting behavior in the current manual.

A future documentation sync job should ingest the current manual, normalize
command paths/arguments/version notes, diff the previous snapshot, regenerate
affected tool metadata, run tests against CHR and open a review PR. Documentation
changes must never auto-deploy to production.

## Architecture

```text
Operator request
    |
    v
MikroTik operator-intent compiler
    |
    +--> explicit facts
    +--> derived policy
    +--> missing facts / blockers
    +--> verification contract
    |
    v
Relevant micro-tool selection
    |
    v
RouterOS discovery / normalized state
    |
    v
Vendor-neutral desired state / safe-subset IR
    |
    v
Existing RouterOS renderers
    |
    v
Existing transaction + admission + rollback gates
    |
    v
CHR acceptance
    |
    v
Production apply (future gate only)
```

The tool registry is deliberately small and composable. The runtime should load
only tools relevant to the current intent. Packet capture tools require a
separate opt-in because RouterOS separates normal read/test permissions from
`sniff`. Write tools are metadata-only until the normal write gate authorizes a
transaction.

## Intent: secure Internet gateway

Minimal operator facts:

```json
{
  "kind": "secure_internet_gateway",
  "lan_cidr": "192.168.10.0/24",
  "lan_interface": "bridge-lan",
  "wan_interface": "ether1",
  "wan_addressing": "dhcp",
  "credential_ref": "env://ROUTEROS_PASSWORD"
}
```

Derived policy includes:

- LAN may initiate Internet traffic.
- unsolicited WAN-to-LAN traffic is denied.
- WAN access to router management is denied.
- WAN ICMP echo-request is denied when requested by the intent, while required
  IPv4 ICMP control/error messages are preserved.
- established/related traffic is accepted and invalid state is dropped.
- IPv4 source NAT is derived only after discovery confirms that it is required.
- management services are restricted to the declared LAN management source.
- default deny is the primary port-scan control; optional detection/logging is
  not allowed to replace correct firewall policy.
- every management-critical mutation requires verification and rollback
  coverage.
- the second plan against the achieved state must be idempotent.

The compiler does **not** emit RouterOS command strings and does not authorize
writes.

## Intent: Site-to-Site WireGuard

Minimal topology facts:

```json
{
  "kind": "site_to_site_wireguard",
  "local_site_id": "tokyo",
  "remote_site_id": "nagoya",
  "local_lan_cidr": "192.168.10.0/24",
  "remote_lan_cidr": "192.168.20.0/24",
  "local_credential_ref": "vault://routers/tokyo",
  "remote_credential_ref": "vault://routers/nagoya"
}
```

Derived policy includes:

- overlapping site LANs fail closed before routing is generated.
- unique WireGuard key pairs are generated per site and stored through secret
  references; plaintext private keys do not belong in profiles or generated
  scripts.
- tunnel addressing is allocated automatically only after both sites are
  discovered and overlap checks pass.
- only the remote tunnel host and declared remote LAN are placed in the peer
  allowed-address set.
- the Internet default route stays local at each site.
- the firewall opens only the required WireGuard UDP listener and declared
  LAN-to-LAN forwarding.
- persistent keepalive is enabled only when discovered NAT/firewall behavior
  requires it.
- NAT behavior is derived after discovery so LAN-to-LAN traffic is not
  accidentally masqueraded.
- verification requires a recent handshake, tunnel reachability, bidirectional
  LAN reachability, local Internet breakout and denial of undeclared VPN
  forwarding.

Endpoint reachability, public/private/CGNAT state and current firewall/NAT state
must be discovered rather than guessed.

## Micro-tool permission model

Default selection returns read/test tools only.

- `read_only`: inventory and configuration observation.
- `test`: bounded active diagnostics such as ping/traceroute.
- `capture`: torch/sniffer; separate explicit opt-in and RouterOS `sniff`
  permission.
- `write`: configuration mutation metadata; always requires normal write
  admission.
- `destructive`: reserved for operations such as reset/cleanup and should
  require a higher human-confirmation policy.

REST is preferred for one-shot reads and CRUD-shaped operations. RouterOS API or
SSH/CLI remains available where continuous monitoring, interactive behavior or
Safe Mode semantics make REST the wrong transport. Selecting a write-capable
tool never means that execution is authorized.

## Safety invariants

1. Current state is discovered before planning.
2. Existing configuration is not overwritten blindly.
3. Required facts are never invented to make a renderer succeed.
4. Secrets remain unresolved references until the approved execution boundary.
5. Management-plane changes require backup, recovery evidence and post-step
   verification.
6. Subnet overlap, unsupported RouterOS behavior or unknown reachability blocks
   automatic deployment.
7. Generated operations must be deterministic and idempotent.
8. Failed verification stops the transaction and enters rollback handling.
9. Documentation-derived code is tested in CHR before physical-device
   acceptance.
10. AI or natural-language input may propose intent but cannot bypass the same
    deterministic compiler, admission and transaction gates.

## Current implementation slice

This change adds:

- `mikrotik_docs.py` — official source precedence and machine-readable
  documentation endpoints.
- `mikrotik_tool_registry.py` — small RouterOS micro-tool metadata catalog with
  permission/risk boundaries and intent-based selection.
- `mikrotik_intent.py` — deterministic high-level compilers for secure Internet
  gateway and Site-to-Site WireGuard.
- `MikroTikReferenceAdapter` integration for intent compilation and relevant
  tool selection.

It intentionally does **not** add a new production write transport. Existing
RouterOS renderers, CHR acceptance and transaction gates remain authoritative.
