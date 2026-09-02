# RouterOS CHR Read-Only Acceptance Gate

## Purpose

This lab is the next hard gate before any RouterOS renderer or production writer may advance.

The objective is deliberately narrow:

1. boot a controlled RouterOS CHR instance;
2. expose secure REST management only on the lab/management network;
3. collect the same read surfaces used by the production discovery client;
4. verify state/evidence integrity;
5. compare the live state with the guided deployment profile;
6. preserve an auditable manifest for review;
7. explicitly attest provenance before the target matrix may be reviewed.

No configuration renderer, apply command, failover mutation or rollback mutation is part of this gate.

## Official RouterOS references

Use MikroTik sources for CHR and REST behavior:

- RouterOS REST API: https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST%20API
- RouterOS users/policies: https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User
- RouterOS installation/CHR context: https://help.mikrotik.com/docs/spaces/ROS/pages/328142/Upgrading%20and%20installation
- MikroTik download page: https://mikrotik.com/download
- RouterOS WireGuard: https://help.mikrotik.com/docs/spaces/ROS/pages/69664792/WireGuard

RouterOS REST is documented from v7.1beta4. Production-style discovery in this project requires HTTPS with certificate verification. HTTP or disabled TLS verification is accepted only in an explicitly isolated lab.

## Lab topology

Keep CHR isolated from production routing while validating discovery:

```text
Operator / CI host
        |
   management-only network
        |
   RouterOS CHR
        |
   disposable lab networks
```

Do not bridge the initial acceptance CHR into a production WAN or management VLAN.

## Dedicated REST reader

Do not use a full administrator identity for routine discovery.

Create a dedicated RouterOS account/group for the lab and verify its effective permissions on the tested RouterOS release. The project requires REST read capability but does not require write, policy-management, sensitive-data or packet-sniffing privileges for discovery.

RouterOS exposes distinct `read`, `write`, `policy`, `sensitive`, `sniff`, `api` and `rest-api` policies. Do not assume the built-in `read` group is a least-privilege service account; review the current official User documentation before acceptance.

Restrict management services and the reader account to the lab/management source network wherever practical.

## Environment variables

The acceptance runner intentionally does not accept a password argument.

```bash
export ROUTEROS_URL='https://192.0.2.10'
export ROUTEROS_USERNAME='routercfg-reader'
export ROUTEROS_PASSWORD='...provided by local secret mechanism...'
```

For a controlled CHR lab using a self-signed certificate that is not yet trusted by the host, the runner can explicitly use:

```bash
export ROUTEROS_LAB_INSECURE_TLS=1
```

That switch passes `--lab --no-verify-tls`. It must not be used as a production default.

## Run the gate

From the repository root after installing the package:

```bash
sh lab/chr/run_readonly_acceptance.sh \
  examples/rd-10g-1g/deployment-profile.json \
  evidence/chr-readonly
```

The runner executes only these project operations:

1. `routerctl profile-check`;
2. `routerctl routeros-discover`;
3. `routerctl routeros-evidence-check`;
4. `routerctl routeros-preflight`.

If all four commands succeed, it creates a manifest containing hashes for the profile, evidence file and normalized state plus the discovered platform metadata.

## Provenance review

A valid evidence bundle is not automatically proof that the source was a real CHR instance. The next step is an explicit provenance attestation.

Copy the safe template next to the evidence bundle:

```bash
cp lab/chr/provenance-attestation.template.json \
  evidence/chr-readonly/provenance-attestation.json
```

After directly observing the controlled CHR run, fill only the non-secret provenance fields:

- `operator_attested=true`;
- `controlled_environment=true`;
- exact `observed_at` with timezone;
- exact RouterOS version reported by the validated evidence;
- exact normalized-state SHA-256 from the validated evidence.

Do not place credentials, management IP addresses, private keys, tokens or other secrets in the attestation file.

Then review all three gates with one non-mutating command:

```bash
python -m router_configuration.review_candidate \
  --profile examples/rd-10g-1g/deployment-profile.json \
  --evidence evidence/chr-readonly/routeros-discovery.json \
  --manifest evidence/chr-readonly/manifest.json \
  --attestation evidence/chr-readonly/provenance-attestation.json \
  --matrix ROUTEROS_TARGET_MATRIX.json
```

The command evaluates, in order:

1. bundle integrity and hashes;
2. provenance attestation consistency;
3. target-matrix admission rules.

A successful result only returns `candidate_for_manual_acceptance`. It does not mutate the matrix and it does not automatically mark CHR as verified.

## Required evidence before P07/P08 can advance

The following must be reviewed from a real CHR run:

- RouterOS exact version;
- platform/architecture;
- successful discovery of system identity/resource;
- interface list;
- IP address list;
- route list;
- routing table list;
- firewall filter and NAT;
- WireGuard interface/peer surfaces when supported/configured;
- simple queue and queue-tree surfaces;
- capability gaps explicitly recorded rather than silently ignored;
- `routeros-evidence-check` PASS;
- `routeros-preflight` PASS or reviewed non-blocking warnings;
- evidence and manifest hashes retained;
- provenance attestation reviewed;
- candidate admission output reviewed.

Only after this live CHR evidence is reviewed should `ROUTEROS_TARGET_MATRIX.json` mark `chr-live-v7` as verified.

## What this gate does NOT prove

A CHR read-only PASS does not prove:

- RouterOS renderer correctness;
- 10G throughput;
- CCR2116 hardware behavior;
- Dual-WAN failover correctness;
- firewall mutation safety;
- rollback correctness;
- production readiness.

Those remain separate weighted gates in `PROJECT_PROGRESS.json` and `CHECKLIST.md`.

## Firewall baseline runtime gate

The enterprise firewall renderer has a separate disposable CHR gate. It does not use the production discovery identity and it does not expose a production writer.

Trigger the dedicated workflow by committing to `main` with a message beginning with:

```text
ci(chr-firewall):
```

The gate runs against the official MikroTik CHR 7.24.1 image in a QEMU snapshot. It derives the management CIDR from the live IPv4 address observed on `ether1`; the management network is not hard-coded or inferred from a production topology.

The validator executes these gates in order:

1. render the explicit enterprise firewall fixture;
2. dry-run both rollback and apply scripts;
3. prove the configuration digest is unchanged by dry-run;
4. apply only to the disposable CHR snapshot;
5. require all managed filter rules to be enabled and `invalid=false`;
6. verify the managed input and essential-ICMP chain order;
7. verify management-source anti-spoofing precedes ICMP handling;
8. verify management accept is bounded to `routercfg-CORE` plus the explicit management source list;
9. verify WAN input default deny and bounded explicit WAN-service exceptions;
10. perform a fresh REST read after activation to prove the observed management path remains reachable;
11. rollback only `routercfg`-owned firewall surfaces;
12. require the post-rollback configuration digest to equal the exact pre-apply baseline digest.

The workflow preserves evidence even on failure. The artifact name is:

```text
chr-firewall-baseline-${{ github.sha }}
```

The gate uses no production credentials, targets no physical router, exposes no product write transport, and keeps `write_authorized=false`.

## WireGuard deferred-secret runtime gate

WireGuard uses a stricter product boundary than ordinary generation-only commands. The product renderer validates the interface, address, listen port, MTU, peer public keys, peer tunnel addresses, non-overlapping bounded `allowed-address` ranges, endpoints, keepalive/responder flags, and explicit routes, but it does **not** resolve or serialize the private key. Instead it emits a deferred template plan and keeps `vpn.wireguard` blocked on two remaining boundaries: private-key secret binding and an authorized transactional apply path.

Trigger the disposable CHR validator by committing to `main` with a message beginning with:

```text
ci(chr-wireguard):
```

The workflow boots official MikroTik CHR 7.24.1 in a QEMU snapshot and binds a synthetic private key only inside the lab process. The synthetic private key is generated from in-memory random bytes, is never committed, never written to the evidence JSON, never uploaded as an artifact, and is cleared from the validator's local variables after the mutation gate. A valid remote public key is obtained from a temporary WireGuard interface created on the disposable CHR; only the public key is read, and that temporary interface is removed before the baseline digest is captured.

The WireGuard validator requires all of the following:

1. product templates remain generation-only and retain an unresolved secret binding;
2. apply and rollback scripts both pass RouterOS import dry-run while a negative control is rejected;
3. dry-run leaves the configuration digest unchanged;
4. real apply is permitted only inside the disposable CHR lab boundary;
5. exactly one managed WireGuard interface, address, peer and explicit route exist after apply;
6. all managed WireGuard objects are enabled and `invalid=false`;
7. the peer's bounded `allowed-address` set exactly matches the synthetic fixture;
8. a fresh REST read succeeds after activation, proving management access still works;
9. rollback removes only `routercfg:managed:wg:*` objects in dependency order;
10. the final configuration digest equals the exact pre-apply baseline digest;
11. evidence explicitly records `private_key_recorded=false`, `private_key_serialized=false` and `preshared_key_used=false`;
12. the product still reports no writer, no exposed transport and no write authorization.

The sanitized artifact is named:

```text
chr-wireguard-baseline-${{ github.sha }}
```

The artifact intentionally excludes RouterOS import scripts and the CHR serial log because those surfaces are unnecessary for acceptance and could expand the secret-exposure boundary.

This gate proves RouterOS syntax/runtime acceptance and exact rollback for the deferred-secret WireGuard configuration slice. It does **not** prove a peer-to-peer WireGuard handshake, encrypted packet transfer, production firewall UDP exception, Internet reachability, or physical CCR2116 behavior. Those remain separate acceptance gates.
