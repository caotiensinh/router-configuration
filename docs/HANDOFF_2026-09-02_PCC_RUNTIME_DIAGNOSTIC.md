# Router Configuration — Handoff 2026-09-02 — PCC Runtime Diagnostic

## Repository

- Repository: `caotiensinh/router-configuration`
- Branch: `main`
- Checkpoint evidence commit before this handoff: `d2c5307deb5932430eadfe151a1dcd9e9f0273df`
- IMPORTANT: repository may change concurrently. Always read current `main` SHA before continuing and do not trust a stale SHA from this document.

## Development invariant

Every work unit follows:

`CODE -> TEST -> COMMIT -> EXACT-HEAD CI/CHR EVIDENCE -> UPDATE CHECKLIST/% -> CONTINUE`

Do not stop after a commit if another safe independent work unit can be continued in the same session.

## Current official progress

- Completed: **72%**
- Remaining: **28%**
- Source of truth: `PROJECT_PROGRESS.json`
- Do **not** increase P11 or total completion until real fail-closed packet-flow evidence passes.

Key weighted status:

- P01 Spec/architecture/harness: 8/8 DONE
- P02 Clean-room/security/change policy: 4/4 DONE
- P03 Guided deployment profile: 6/6 DONE
- P04 Operator workflow CLI: 2/2 DONE
- P05 Vendor-neutral state/diff/drift: 8/8 DONE
- P06 Compiler/secret boundary: 4/4 DONE
- P07 RouterOS discovery: 10/12 PARTIAL
- P08 RouterOS normalization: 6/6 DONE
- P09 RouterOS renderer: 6/13 PARTIAL
- P10 Transactional runtime: 5/15 PARTIAL
- P11 Weighted Dual-WAN/failover: 4/5 PARTIAL
- P12 Security/VLAN/PBR/VPN/QoS: 1/8 PARTIAL
- P13 CHR integration/failure lab: 5/5 DONE
- P14 CI/regression/golden evidence: 2/2 DONE
- P15 v1 beginner release/docs: 0/1 NOT STARTED
- P16 AI observability gateway placeholder: 1/1 DONE

## What is already proven

### RouterOS read-only and safety foundation

Proven on official MikroTik CHR 7.24.1:

- live REST discovery
- HTTPS + CA verification
- dedicated least-privilege reader
- read-only evidence integrity
- populated firewall/NAT/WireGuard/QoS discovery and normalization
- secret redaction boundary
- reader write-denial with read-back verification
- synthetic + CHR integration tests

Production router write remains disabled.

### Recursive failover renderer

Proven on CHR 7.24.1:

- 17 recursive failover commands pass RouterOS import dry-run
- negative control fails correctly
- config digest remains unchanged during dry-run
- generated commands were also exercised in disposable mutation/failure/rollback lab

Evidence:

- `evidence/chr/2026-09-02-recursive-failover-render-dryrun-7.24.1.json`

### PCC renderer — syntax and rollback evidence

The combined renderer produces:

- 17 recursive failover commands
- 21 PCC commands
- total 38 commands
- exact 10G:1G plan -> 11 PCC buckets -> 10 WAN10 buckets + 1 WAN1 bucket

The 38-command fixture has passed RouterOS import dry-run and disposable mutation/failure/rollback testing.

Evidence:

- `evidence/chr/2026-09-02-pcc-render-dryrun-7.24.1.json`
- `evidence/chr/2026-09-02-mutation-rollback-7.24.1.json`

However, syntax/apply success is **not sufficient** for PCC behavior correctness. The runtime blocker below is now the highest-priority issue.

## Critical latest finding — do not lose this checkpoint

A real 4-NIC CHR dataplane lab was added:

- `ether1`: management
- `ether2`: WAN10
- `ether3`: WAN1
- `ether4`: CORE

Linux namespaces emulate:

- WAN10 responder -> tag `WAN10`
- WAN1 responder -> tag `WAN1`
- CORE client -> many unique UDP flows

Relevant files:

- `lab/chr/run_packet_flow_acceptance.sh`
- `lab/chr/verify_packet_flow_behavior.py`
- `lab/chr/udp_tag_server.py`
- `lab/chr/udp_flow_probe.py`
- `.github/workflows/chr-packet-flow.yml`
- `tests/test_chr_packet_flow_contract.py`

### False-green discovered

Workflow run `33615540152` originally concluded SUCCESS, but its artifact showed acceptance FAILURE:

- 220/220 normal flows succeeded
- all 220 returned `WAN10`
- WAN1 received 0 flows

Root cause in the harness:

- `cleanup()` called `set +e`
- because the cleanup function is invoked once before test execution, shell `errexit` stayed disabled
- evaluator exit `17` was masked and the workflow could appear green

This has already been fixed:

- `cleanup()` no longer changes `errexit`
- contract test forbids `set +e`
- prepare step now fails closed when managed PCC mangle rows have `invalid=true`

### Fail-closed diagnostic run

Workflow run:

- Run ID: `33616274561`
- Head: `bc907090c76b530780f86bf24edef5617ac456c8`
- Conclusion: FAILURE, intentionally fail-closed
- Artifact ID: `9841071030`
- Artifact digest: `sha256:79b21422cf590e0bf3b802797d04a2bddaf617835a5fd4506eaaaf9ad46385d3`

Sanitized committed evidence:

- `evidence/chr/2026-09-02-pcc-runtime-diagnostic-7.24.1.json`

Observed on RouterOS 7.24.1 runtime:

- total managed PCC mangle rules: 13
- managed rules with `invalid=true`: **12**
- only managed rule confirmed valid:
  - `routercfg:managed:pcc-connection:lab-wan10g:0`
  - PCC matcher: `both-addresses-and-ports:11/0`

Invalid managed classes:

- connection classifiers with remainders `11/1` through `11/10`
- both managed `mark-routing` rules

Diagnostic matrix also created 7 minimal variants and all 7 were `invalid=true`:

1. passthrough + PCC 11/0
2. passthrough + PCC 11/1
3. passthrough + PCC 11/2
4. plain mark-connection
5. mark-connection + PCC 11/1
6. mark-connection + PCC 11/2
7. mark-routing -> `to-lab-wan10g`

Important: the 38-command RouterOS import dry-run returned `OK`, and apply returned `OK`, while runtime mangle objects were invalid. Therefore:

> RouterOS syntax/import success MUST NOT be treated as proof of PCC correctness.

Runtime object validity + real dataplane behavior are mandatory gates.

## Current highest-priority blocker

Identify the exact RouterOS 7.24.1 runtime requirement that makes the PCC/mangle rules invalid.

Do not guess. Use live CHR evidence and progressively smaller runtime objects.

The next iteration should inspect the runtime state and dependencies of:

- `/ip/firewall/mangle`
- connection marks
- routing marks
- `/routing/table`
- interface list membership
- connection tracking/runtime prerequisites
- PCC matcher behavior per denominator/remainder

Do not weaken the acceptance thresholds just to obtain green CI.

## Required next sequence

1. Read current `main` SHA and recent commits.
2. Read this handoff.
3. Read `PROJECT_PROGRESS.json`.
4. Read committed diagnostic evidence.
5. Confirm exact-head normal CI before changing code.
6. Reproduce/inspect PCC runtime invalid state on CHR 7.24.1.
7. Build a smaller live runtime matrix that isolates the actual RouterOS dependency/constraint.
8. Fix `routeros_pcc_renderer.py` only from evidence.
9. Add regression tests for the exact root cause.
10. Commit.
11. Trigger fail-closed `ci(chr-flow):` acceptance.
12. Require all of the following before closing P11:
    - no managed PCC mangle rule has `invalid=true`
    - normal phase success ratio >= 97%
    - normal WAN10 share within 0.84..0.97
    - WAN1 receives > 0 flows
    - WAN10 failure: success ratio >= 95%
    - WAN10 failure: WAN1 share >= 98%
    - recovery success ratio >= 97%
    - recovery distribution returns to the 10:1 tolerance
    - route failover state observed
    - route recovery state observed
13. Only then update P11 from 4/5 -> 5/5 and total 72% -> 73%.
14. Commit evidence + ledger update.
15. Continue immediately into RouterOS firewall baseline renderer because it advances both P09 and P12 and is a prerequisite for WireGuard.

## Safety invariants

Do not violate these:

- production write/apply remains disabled
- physical CCR2116 write remains blocked
- no plaintext credentials or private keys in Git/evidence
- AI gateway remains advisory/read-only; AI engine work is deferred
- no direct third-party source/config copying; clean-room implementation only
- FastTrack active -> state-aware PCC generation must fail closed
- incompatible `dstnat` -> outbound PCC v0.1 generation must fail closed
- no invented gateway/IP/VLAN/WireGuard/QoS data
- CHR/QEMU lab mutation is disposable and is not a production writer

## After P11

Priority order for faster completion:

1. RouterOS firewall baseline renderer + CHR validation
2. management-plane protection / default WAN input deny
3. WireGuard renderer with unresolved secret-reference boundary
4. VLAN/PBR segmentation
5. QoS explicit policy renderer and 10G performance guardrails
6. real transactional product runtime: backup -> preflight -> apply -> verify -> rollback
7. operator provenance/target admission closure for P07
8. one-command beginner deployment/release docs

## Handoff rule

The next chat must continue from this checkpoint. Do not restart research, redesign the architecture, or reimplement completed modules. Re-check GitHub because concurrent commits are possible, then continue from the newest valid checkpoint.
