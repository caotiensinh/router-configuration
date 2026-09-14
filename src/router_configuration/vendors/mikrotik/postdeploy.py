from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class BackupArtifact:
    kind: str
    path: Path
    contains_sensitive_data: bool
    routeros_version: str


@dataclass(frozen=True)
class HandoverBundleResult:
    output_dir: Path
    files: tuple[Path, ...]
    manifest_sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_text(record: Mapping[str, Any], key: str) -> str:
    value = str(record.get(key) or "").strip()
    if not value:
        raise ValueError(f"deployment record requires {key}")
    return value


def _verification_rows(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = record.get("verification")
    if not isinstance(raw, list) or not raw:
        raise ValueError("deployment record requires non-empty verification evidence")
    rows: list[Mapping[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"verification[{index}] must be an object")
        if str(item.get("status") or "").lower() not in {"pass", "passed", "success"}:
            raise ValueError("handover bundle can be generated only after all verification checks pass")
        rows.append(item)
    return rows


def _write(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _table(rows: Iterable[tuple[str, str]]) -> str:
    return "\n".join(f"| {left} | {right} |" for left, right in rows)


def build_handover_bundle(
    *,
    output_dir: str | Path,
    deployment_record: Mapping[str, Any],
    backup_artifacts: Iterable[BackupArtifact] = (),
) -> HandoverBundleResult:
    """Create deterministic post-deployment evidence and handover documents.

    This builder does not invent configuration facts. It requires completed,
    verified deployment evidence and copies only backup files supplied by the
    RouterOS execution layer. Binary backups are marked sensitive in the manifest.
    """

    if str(deployment_record.get("status") or "").lower() != "completed":
        raise ValueError("handover bundle requires status=completed")

    deployment_id = _require_text(deployment_record, "deployment_id")
    site = _require_text(deployment_record, "site")
    device = deployment_record.get("device")
    if not isinstance(device, Mapping):
        raise ValueError("deployment record requires device object")
    identity = str(device.get("identity") or device.get("id") or "").strip()
    model = str(device.get("model") or "").strip()
    version = str(device.get("routeros_version") or device.get("firmware_version") or "").strip()
    if not identity or not version:
        raise ValueError("device identity and RouterOS version are required")
    verification = _verification_rows(deployment_record)

    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    backup_dir = root / "backups"
    backup_dir.mkdir(exist_ok=True)

    copied_backups: list[dict[str, Any]] = []
    for artifact in backup_artifacts:
        source = Path(artifact.path)
        if not source.is_file():
            raise ValueError(f"backup artifact does not exist: {source}")
        if artifact.routeros_version != version:
            raise ValueError("backup artifact RouterOS version must match deployment record")
        destination = backup_dir / source.name
        shutil.copy2(source, destination)
        copied_backups.append(
            {
                "kind": artifact.kind,
                "file": str(destination.relative_to(root)),
                "sha256": _sha256(destination),
                "contains_sensitive_data": artifact.contains_sensitive_data,
                "routeros_version": artifact.routeros_version,
            }
        )

    changes = deployment_record.get("changes", [])
    if not isinstance(changes, list):
        raise ValueError("deployment_record.changes must be a list")
    intent = deployment_record.get("intent", {})
    if not isinstance(intent, Mapping):
        raise ValueError("deployment_record.intent must be an object")

    completion = root / "00_deployment_completion.md"
    _write(
        completion,
        f"""# MikroTik Deployment Completion Report

| Field | Value |
| --- | --- |
{_table((
    ("Deployment ID", deployment_id),
    ("Site", site),
    ("Device", identity),
    ("Model", model or "not-recorded"),
    ("RouterOS", version),
    ("Status", "COMPLETED / VERIFIED"),
))}

## Implemented intent

```json
{json.dumps(intent, indent=2, ensure_ascii=False, sort_keys=True)}
```

## Changes applied

{chr(10).join(f'- {str(item)}' for item in changes) if changes else '- No change summary was supplied.'}

## Verification

{chr(10).join(f'- PASS: {str(item.get("name") or item.get("check") or "unnamed-check")}' for item in verification)}

The deployment is considered complete only because all supplied verification checks passed.
""",
    )

    handover = root / "01_handover_record.md"
    _write(
        handover,
        f"""# MikroTik Configuration Handover Record

Deployment `{deployment_id}` for site `{site}` has been handed over with the verified as-built state and backup manifest in this bundle.

## Device

- Identity: `{identity}`
- Model: `{model or 'not-recorded'}`
- RouterOS: `{version}`

## Handover acceptance checklist

- [x] Configuration deployment completed
- [x] Post-change verification passed
- [x] As-built documentation generated
- [x] Operations and maintenance guide generated
- [{'x' if copied_backups else ' '}] Backup artifact(s) captured and hashed
- [x] Sensitive backup artifacts are explicitly marked in the manifest

Do not transmit binary `.backup` files through insecure channels. Store them encrypted and access-controlled.
""",
    )

    as_built = root / "02_as_built.md"
    _write(
        as_built,
        f"""# MikroTik As-Built Configuration

## Deployment metadata

```json
{json.dumps({k: deployment_record.get(k) for k in ('deployment_id', 'site', 'started_at', 'completed_at', 'operator')}, indent=2, ensure_ascii=False, sort_keys=True)}
```

## Device

```json
{json.dumps(dict(device), indent=2, ensure_ascii=False, sort_keys=True)}
```

## Intended state

```json
{json.dumps(intent, indent=2, ensure_ascii=False, sort_keys=True)}
```

## Applied change summary

```json
{json.dumps(changes, indent=2, ensure_ascii=False, sort_keys=True)}
```

## State provenance

- Pre-change state SHA-256: `{str(deployment_record.get('pre_state_sha256') or 'not-recorded')}`
- Post-change state SHA-256: `{str(deployment_record.get('post_state_sha256') or 'not-recorded')}`
""",
    )

    operations = root / "03_operations_maintenance.md"
    _write(
        operations,
        f"""# MikroTik Operations and Maintenance Guide

## Routine checks

1. Confirm management reachability through the approved management path only.
2. Check RouterOS resource health, interface operational state, default routes, and WAN reachability.
3. Review firewall counters and logs for unexpected WAN-input or forwarding activity.
4. For WireGuard deployments, check recent handshake time plus RX/TX counters before troubleshooting routes.
5. Compare the live normalized state with the recorded desired/as-built state and investigate drift before making changes.

## Change procedure

1. Discover and snapshot current state.
2. Validate intended change against the local MikroTik knowledge bundle.
3. Create a pre-change export and binary backup when the operation warrants it.
4. Apply management-critical changes in small verified batches with rollback protection.
5. Run explicit post-change verification.
6. Generate a new handover bundle and replace the previous as-built baseline only after verification passes.

## Backup/restore rules

- Keep a human-readable RouterOS export and a binary system backup as distinct artifacts.
- Treat binary backups as sensitive and store them encrypted/access-controlled.
- Record RouterOS version with every backup; restore compatibility must be checked before use.
- A text export does not contain every secret/certificate/auxiliary database and is not a complete substitute for a binary backup.

## Incident first response

- Preserve logs/evidence before mutation when possible.
- Verify power/link/interface state before changing routing or firewall policy.
- If management was lost immediately after a configuration change, use the documented recovery path and rollback evidence before introducing additional changes.

Device baseline: `{identity}` / RouterOS `{version}`.
""",
    )

    verification_path = root / "04_verification_evidence.json"
    verification_path.write_text(
        json.dumps(verification, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    backup_manifest = root / "05_backup_manifest.json"
    backup_manifest.write_text(
        json.dumps(
            {
                "schema_version": "mikrotik-backup-manifest/1",
                "deployment_id": deployment_id,
                "device_identity": identity,
                "routeros_version": version,
                "artifacts": copied_backups,
            },
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    generated = [completion, handover, as_built, operations, verification_path, backup_manifest]
    generated.extend(backup_dir / Path(item["file"]).name for item in copied_backups)

    bundle_manifest = root / "99_bundle_manifest.json"
    manifest_payload = {
        "schema_version": "mikrotik-handover-bundle/1",
        "deployment_id": deployment_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": [
            {
                "file": str(path.relative_to(root)),
                "sha256": _sha256(path),
            }
            for path in generated
        ],
    }
    bundle_manifest.write_text(
        json.dumps(manifest_payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    files_out = tuple([*generated, bundle_manifest])
    return HandoverBundleResult(root, files_out, _sha256(bundle_manifest))
