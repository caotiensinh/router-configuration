# Guided Deployment Start

This guide is the beginner entry point for Router Configuration v1.

## Goal

Create a local planning workspace with one command. This step does **not** connect to or modify a router.

## 1. Create the workspace

Run the same command from PowerShell, Command Prompt, Bash, or another shell where `routerctl` is installed:

```text
routerctl guided-start --workspace ./routercfg-site --site-name "R&D Center" --device-id router-001 --management-target 192.0.2.10
```

The command creates:

```text
routercfg-site/
├── profile.json
├── safe-subset-ir.json
└── START_HERE.md
```

## 2. Review and validate

```text
routerctl profile-check --profile ./routercfg-site/profile.json
```

The generated profile is always `allow_write=false`. The safe-subset IR contains no RouterOS commands and no write transport.

## 3. Read-only discovery

Do not proceed to configuration generation until RouterOS read-only discovery and evidence verification pass. Production discovery must use HTTPS with TLS verification and a least-privilege reader account.

Never place a password, token, WireGuard private key, or PSK in the workspace or command line.

## 4. Preflight

Run `routerctl routeros-preflight` against the exact generated profile and the exact verified discovery evidence. Blocking findings must be resolved before generation proceeds.

## 5. Generation boundary

RouterOS artifact generation remains offline. `guided-start` exposes no apply, rollback, shell, REST write method, credential resolver, or production writer.

Physical-router mutation remains disabled until the separate transactional runtime and physical CCR2116 acceptance gates are complete.

## Failure handling

If `guided-start` fails, fix the reported local input/workspace problem and rerun it. Do not work around a failed validation by editing `allow_write`, inserting vendor commands into the IR, or adding credentials to generated files.
