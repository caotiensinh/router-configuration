# MikroTik RouterOS Automation Domain

## Scope rule: one vendor, one domain

MikroTik is developed as an independent router automation domain.

The project must **not** implement one large cross-vendor configuration engine that
tries to force MikroTik, Yamaha, Omada, or future vendors into identical behavior.
Shared code is limited to infrastructure primitives such as evidence envelopes,
secret references, audit records, transaction interfaces, hashing, and generic
approval concepts.

MikroTik-specific knowledge, intent semantics, RouterOS command behavior,
validation, safety rules, diagnostics, backup policy, AI grounding, and handover
outputs belong under:

`src/router_configuration/vendors/mikrotik/`

Root-level `mikrotik_*` modules are compatibility shims during migration only.

## Target operator experience

The target is:

`operator intent -> discovered RouterOS facts -> MikroTik policy -> verified configuration -> backup -> handover bundle`

The operator should describe the required network outcome instead of memorizing
RouterOS syntax. Missing facts are discovered when possible and explicitly
blocked when they cannot be proven. The system must never invent interface
names, addresses, routes, capabilities, credentials, or reachability.

## Official MikroTik knowledge sources

Current official documentation has highest authority:

1. `https://manual.mikrotik.com/docs/`
2. `https://manual.mikrotik.com/llms.txt`
3. `https://manual.mikrotik.com/llms-full.txt`
4. per-page Markdown (`.md`) and `sitemap.xml`
5. `https://help.mikrotik.com/docs/` for legacy/history only

The current manual explicitly publishes machine-readable endpoints for AI and
retrieval systems. Online documentation is therefore an **update source**, not a
runtime dependency.

## Offline-first knowledge architecture

Runtime MikroTik reasoning must work without Internet access.

The package ships a curated, structured knowledge seed:

`vendors/mikrotik/data/knowledge_seed.json`

It contains normalized RouterOS concepts, relevant CLI paths, safety rules, and
official source provenance. `MikroTikOfflineKnowledge` retrieves this data
locally and performs no network I/O.

For complete offline documentation, run the synchronization tool while Internet
access is available:

```bash
python tools/mikrotik/sync_offline_knowledge.py \
  --output ./offline/mikrotik/current
```

The snapshot contains:

- `llms.txt` page catalog;
- `llms-full.txt` complete text corpus;
- `sitemap.xml` completeness source;
- `snapshot-manifest.json` with byte counts, source URLs, timestamps and SHA-256.

After synchronization, deployment/reasoning runtimes consume local files only.
Documentation updates must be reviewed and tested against CHR before they can
change production configuration behavior.

## AI/reasoning provider boundary

AI is optional and replaceable. It is not the RouterOS source of truth and it
never authorizes a write.

Supported provider boundary:

- `openai` - OpenAI Responses API with an explicit caller-selected model;
- `codex` - same OpenAI Responses transport with an explicit coding model;
- `anthropic` - Claude Messages API;
- `ollama` - local Ollama `/api/chat`, allowing fully local/offline reasoning.

No model name is hard-coded as permanent policy. Provider, model, base URL and
API-key environment variable are configuration.

Before a request reaches any model:

1. relevant MikroTik knowledge is retrieved locally;
2. observed RouterOS evidence is attached;
3. secret-like fields are redacted;
4. constraints forbid invented network facts;
5. model output is treated as advisory;
6. deterministic MikroTik compilers/validators remain authoritative.

A system can run with no cloud AI at all. Deterministic intent, discovery,
validation, rendering, verification, backup and handover logic remain usable.
A local Ollama model can be added when natural-language reasoning is wanted in
an isolated environment.

## MikroTik deployment lifecycle

The MikroTik workflow is vendor-specific and completion requires more than a
successful apply:

```text
DISCOVER
  -> NORMALIZE
  -> RESOLVE_INTENT
  -> RETRIEVE_OFFLINE_KNOWLEDGE
  -> OPTIONAL_AI_REASONING
  -> PLAN
  -> VALIDATE
  -> PRE_CHANGE_BACKUP
  -> APPROVAL
  -> APPLY
  -> VERIFY
  -> POST_CHANGE_BACKUP
  -> GENERATE_HANDOVER
  -> COMPLETE
```

`COMPLETE` is forbidden until verification, backup, and documentation outputs
exist.

### Safety invariants

- current RouterOS state is discovered before planning;
- existing configuration is diffed, not blindly overwritten;
- management-path survival is checked around critical changes;
- management-critical mutations are small and independently verified;
- Safe Mode/rollback protection is used where its RouterOS semantics apply;
- reboot-required operations are not assumed to be protected by Safe Mode;
- secrets stay as references until the approved execution boundary;
- subnet overlap and unsupported/unknown behavior fail closed;
- generated changes are deterministic and idempotent;
- failed verification stops completion and enters rollback/recovery handling.

## Backup policy

Every production deployment requires both pre-change and post-change recovery
artifacts.

### Human-readable export

Template:

```text
/export terse file={artifact_name}
```

Purpose:

- reviewable change/as-built evidence;
- configuration diff support;
- operational troubleshooting.

It is **not** a complete secret/certificate/user-database backup.

### Binary system backup

Template:

```text
/system/backup/save name={artifact_name} password={resolved_backup_password}
```

Binary backups contain sensitive configuration. They must be encrypted,
access-controlled, hashed, and stored with RouterOS version provenance.
Restore compatibility must be checked before use.

## Automatic post-deployment package

A verified deployment automatically produces a handover bundle:

```text
00_deployment_completion.md
01_handover_record.md
02_as_built.md
03_operations_maintenance.md
04_verification_evidence.json
05_backup_manifest.json
backups/
99_bundle_manifest.json
```

The bundle generator accepts only observed deployment evidence. It does not
invent facts. If any verification item is not PASS, the handover bundle cannot
be finalized.

The backup manifest records hashes, RouterOS version, sensitivity classification
and artifact type. The final bundle manifest hashes every generated deliverable.

## Operations and maintenance document

The generated O&M guide includes at minimum:

- approved management path;
- routine resource/interface/route checks;
- firewall/log review guidance;
- WireGuard handshake/RX/TX checks when VPN is deployed;
- drift comparison against the verified as-built state;
- safe change procedure;
- backup/restore constraints;
- first-response troubleshooting guidance;
- recovery/rollback references.

Human-facing documents may later be rendered in Japanese, Vietnamese, or
English. Their factual source remains the same verified deployment record and
MikroTik offline knowledge bundle.

## Intent: secure Internet gateway

The current compiler supports a conservative IPv4 gateway intent. Derived policy
includes LAN-initiated Internet access, default denial of unsolicited WAN-to-LAN
traffic, WAN management denial, stateful firewall handling, controlled ICMP,
NAT only when evidence shows it is required, management-source restriction,
rollback coverage, and idempotency verification.

The compiler does not authorize RouterOS writes.

## Intent: Site-to-Site WireGuard

The current compiler validates non-overlapping site LANs, keeps Internet breakout
local unless explicitly requested otherwise, limits allowed-address and forwarding
to declared networks, derives keepalive/NAT behavior from evidence, and requires
handshake plus bidirectional LAN verification.

The compiler does not invent public reachability or silently hide subnet overlap
behind NAT.

## Current implementation

Canonical MikroTik domain components now include:

- `vendors/mikrotik/docs.py` - official documentation authority and offline roles;
- `vendors/mikrotik/data/knowledge_seed.json` - bundled offline knowledge;
- `vendors/mikrotik/knowledge.py` - local retrieval;
- `vendors/mikrotik/tool_registry.py` - MikroTik micro-tool catalog;
- `vendors/mikrotik/intent.py` - deterministic intent compiler;
- `vendors/mikrotik/inference.py` - OpenAI/Codex/Claude/Ollama reasoning boundary;
- `vendors/mikrotik/backup.py` - pre/post backup contract;
- `vendors/mikrotik/workflow.py` - MikroTik deployment lifecycle;
- `vendors/mikrotik/postdeploy.py` - completion/handover/as-built/O&M bundle;
- `tools/mikrotik/sync_offline_knowledge.py` - official full-doc snapshot sync.

Production write enablement remains separately gated by CHR acceptance,
transaction admission, recovery evidence, and physical-device acceptance.
