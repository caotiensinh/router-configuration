# Router Configuration

> **IMPORTANT — MANDATORY PROJECT GOVERNANCE**
>
> This repository is governed by `MASTER_RULES.md`. All humans, AI agents, sub-agents, automation workers, and future contributors MUST read the current `MASTER_RULES.md` before making technical changes. Task prompts do not need to repeat this requirement.
>
> After the Master Rules, read `AGENTS.md`, applicable files under `governance/`, and the relevant `vendors/<vendor>/VENDOR_RULES.md` before beginning scoped work.

Router Configuration is a clean-room network automation platform with a shared safety/governance shell and **vendor-isolated implementation domains**. It must not evolve into one cross-vendor mega-compiler that guesses a lowest-common-denominator configuration model.

Its goal is to let an operator with basic router/network knowledge deploy a professional configuration through guided intent, authoritative vendor knowledge, deterministic planning, safety gates, verification and rollback instead of memorizing vendor CLI syntax.

Each vendor domain owns its own technical knowledge, command semantics, dependency/conflict rules, validation, execution constraints, backup behavior and operational documentation. Shared code is limited to truly vendor-neutral infrastructure primitives such as governance, evidence, secrets, audit and transaction contracts.

## Current focus

Configuration and automation first.

Reference platform:
- MikroTik CCR2116-12G-4S+;
- WAN1 10 Gbps;
- WAN2 1 Gbps;
- Core uplink 10 Gbps.

Target capabilities:
- weighted Dual-WAN load distribution;
- automatic failover/failback;
- static and policy routing;
- VLAN/zone segmentation;
- firewall and management-plane hardening;
- WireGuard/IPsec intent where supported;
- QoS/traffic classes;
- desired-state diff/drift;
- backup, preflight, verify and rollback.

## Governance

Highest project authority:
- `MASTER_RULES.md` — mandatory project rules and Project Entry Gate;
- `AGENTS.md` — mandatory AI/automation bootstrap;
- `CONTRIBUTING.md` — human contributor bootstrap;
- `governance/` — scoped AI, knowledge, execution, security and documentation policies;
- `vendors/mikrotik/VENDOR_RULES.md` — mandatory MikroTik-specific rules.

Repository analysis may occur to discover applicable rules. Repository mutation and production execution are fail-closed when the current governance set has not been loaded/acknowledged or when a higher-priority rule conflicts with the requested task.

## Deployment harness

All writes must eventually follow:

`DISCOVER -> INSPECT -> PLAN -> VALIDATE -> BACKUP -> PREFLIGHT -> APPROVAL -> APPLY -> VERIFY -> SAVE`

Failed verification after a possible mutation enters `ROLLBACK` handling.

Writes remain disabled by default in deployment profiles.

See:
- `SPEC.md` — product requirements and safety invariants;
- `HARNESS.md` — deployment harness contract;
- `WORKFLOW.md` — detailed operator/execution workflow;
- `ARCHITECTURE.md` — module/layer architecture;
- `ROUTEROS_DISCOVERY.md` — RouterOS read-only discovery/evidence contract;
- `PREFLIGHT.md` — guided profile-to-evidence safety checks;
- `CHECKLIST.md` / `PROJECT_PROGRESS.json` — weighted completion measurement;
- `AI_GATEWAY.md` — advisory-only AI boundary;
- `MIKROTIK_AUTOMATION.md` — MikroTik vendor-isolated automation design;
- `MIKROTIK_SCRIPT_COMPILER.md` — immutable primitive/order-only AI compiler boundary;
- `THIRD_PARTY_RESEARCH.md` — clean-room research policy.

## Guided read-only workflow available now

Install the package in a development environment and use `routerctl`.

### 1. Create a conservative deployment profile

The initializer never enables writes. It defaults to the CCR2116 10G + 1G reference topology, weighted Multi-WAN, WAN management denied, and guided operator mode.

```bash
routerctl profile-init \
  --output rd-profile.json \
  --site-name rd \
  --device-id rd-router-01 \
  --management-target 192.168.11.1 \
  --recovery-method local-console
```

Interactive terminal mode is also available:

```bash
routerctl profile-init --interactive --output rd-profile.json
```

WireGuard and QoS intent are opt-in. WireGuard requires a secret reference rather than a plaintext private key.

### 2. Validate the profile

```bash
routerctl profile-check --profile rd-profile.json
```

For the reference 10 Gbps + 1 Gbps links the capacity-derived weights are `10:1`.

### 3. Collect read-only RouterOS evidence

Production mode defaults to HTTPS with TLS certificate verification. Do not place the password on the command line. Interactive use prompts without echo; non-interactive automation can provide the environment variable named by `--password-env` (default `ROUTEROS_PASSWORD`).

```bash
routerctl routeros-discover \
  --url https://192.168.11.1 \
  --username routercfg-reader \
  --output evidence/routeros-readonly.json
```

The discovery client exposes only an explicit GET allowlist. It has no RouterOS POST/PUT/PATCH/DELETE method.

### 4. Verify evidence integrity

```bash
routerctl routeros-evidence-check \
  --evidence evidence/routeros-readonly.json
```

This validates the versioned `routeros-state/1` contract, redaction boundary, state SHA-256 digest, record counts and capability summary. Tampered evidence is rejected before preflight.

### 5. Run guided preflight

```bash
routerctl routeros-preflight \
  --profile rd-profile.json \
  --evidence evidence/routeros-readonly.json
```

Blocking findings include a code, explanation and remediation. Preflight checks device/model identity, selected physical ports and required discovery coverage for Multi-WAN, firewall, WireGuard and QoS.

A preflight PASS **does not authorize a write**. It only says the current profile and verified discovery evidence are compatible with the implemented read-only checks.

### Other safe inspection commands

Inspect guided behavior for a harness stage:

```bash
routerctl workflow --stage preflight
```

Derive WAN weights:

```bash
routerctl multiwan --wan wan10g=10000 --wan wan1g=1000
```

Inspect the weighted project ledger:

```bash
routerctl progress
```

The generic JSON diff command remains a development primitive:

```bash
routerctl plan --desired desired.json --actual actual.json
```

It is not yet the production RouterOS renderer input path.

**No production router writer is enabled yet.** Live CHR read-only acceptance remains a hard gate before RouterOS rendering/apply work is allowed to advance.

## Capability areas

Shared platform capabilities and vendor domains are tracked separately. The existence of a Yamaha/Omada/Fortinet or future vendor domain does not authorize reusing MikroTik command logic or vendor-specific technical assumptions across vendors.

Current capability areas include:
1. Intent & Device Engine
2. State / Diff / Drift Engine
3. Configuration Compiler & Secrets
4. Multi-WAN & Load Balancing
5. Resilience & WAN Health
6. Security Operations
7. Segmentation / PBR / VPN / QoS
8. Vendor-isolated MikroTik RouterOS domain
9. Safe Automation / Governance Gate
10. Future vendor-isolated domains

MikroTik is the first vendor domain being completed as the production reference.

## AI boundary

AI may interpret intent, retrieve approved offline vendor knowledge, propose ordering among immutable verified command primitives, explain evidence and generate documentation.

AI has no direct router-write path and is not a RouterOS syntax or technical-truth authority. Any proposal must pass deterministic vendor-specific dependency/conflict validation, exact-version checks, dry-run/acceptance gates, changeset-specific approval, execution controls and post-state verification.

## Project status

Configuration automation remains pre-production. Do not use this repository to mutate a production router until the RouterOS reference domain passes live CHR discovery, lab apply/verify/rollback testing and required physical-device acceptance evidence is recorded.