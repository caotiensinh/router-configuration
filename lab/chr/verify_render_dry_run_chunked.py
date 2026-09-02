from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base


READ_CHUNK_BYTES = 4096
FILE_SIZE_TIMEOUT_SECONDS = 5.0


def _file_size_bytes(admin: base.LoopbackCHRAdmin, name: str) -> int:
    record = base._file_record(admin, name)
    if record is None:
        raise base.CHRRenderDryRunError(f"RouterOS file disappeared unexpectedly: {name}")
    raw = str(record.get("size") or "").strip()
    try:
        size = int(raw)
    except ValueError as exc:
        raise base.CHRRenderDryRunError(
            f"RouterOS file size is not an integer byte count for {name}: {raw!r}"
        ) from exc
    if size < 0:
        raise base.CHRRenderDryRunError(f"RouterOS file size is negative for {name}")
    return size


def _wait_for_file_size(
    admin: base.LoopbackCHRAdmin,
    name: str,
    expected_bytes: int,
    *,
    timeout_seconds: float = FILE_SIZE_TIMEOUT_SECONDS,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    last_size = -1
    while True:
        last_size = _file_size_bytes(admin, name)
        if last_size == expected_bytes:
            return last_size
        if time.monotonic() >= deadline:
            raise base.CHRRenderDryRunError(
                f"RouterOS file size did not reach expected byte count for {name}: "
                f"expected={expected_bytes} observed={last_size}"
            )
        time.sleep(0.1)


def _extract_read_data(payload: Any, *, name: str, offset: int) -> str:
    rows = base._rows(payload)
    if len(rows) != 1:
        raise base.CHRRenderDryRunError(
            f"RouterOS /file/read returned {len(rows)} records for {name} at offset {offset}"
        )
    value = rows[0].get("data")
    if value is None:
        raise base.CHRRenderDryRunError(
            f"RouterOS /file/read omitted data for {name} at offset {offset}"
        )
    return str(value)


def _read_text_file_chunked(admin: base.LoopbackCHRAdmin, name: str) -> str:
    """Read one UTF-8 text file using RouterOS /file/read instead of /file contents.

    RouterOS exposes /file/read specifically for content that should not be
    retrieved through the ordinary file record. Keeping chunks at 4 KiB also
    avoids relying on historical API/variable-size behavior around larger
    `contents` values.
    """

    expected_size = _file_size_bytes(admin, name)
    if expected_size == 0:
        return ""

    offset = 0
    parts: list[str] = []
    while offset < expected_size:
        requested = min(READ_CHUNK_BYTES, expected_size - offset)
        status, payload = admin.request(
            "POST",
            "file/read",
            {
                "file": name,
                "offset": offset,
                "chunk-size": requested,
            },
            allow_http_error=True,
        )
        if status >= 400:
            raise base.CHRRenderDryRunError(
                f"RouterOS /file/read failed for {name} at offset {offset} "
                f"with HTTP {status}: {str(payload)[:300]}"
            )
        data = _extract_read_data(payload, name=name, offset=offset)
        encoded = data.encode("utf-8")
        if not encoded:
            raise base.CHRRenderDryRunError(
                f"RouterOS /file/read returned an empty chunk before EOF for {name} at offset {offset}"
            )
        if len(encoded) > requested:
            raise base.CHRRenderDryRunError(
                f"RouterOS /file/read exceeded requested chunk size for {name}: "
                f"requested={requested} observed={len(encoded)}"
            )
        parts.append(data)
        offset += len(encoded)

    text = "".join(parts)
    observed_size = len(text.encode("utf-8"))
    if observed_size != expected_size:
        raise base.CHRRenderDryRunError(
            f"RouterOS chunked file read byte count mismatch for {name}: "
            f"expected={expected_size} observed={observed_size}"
        )
    return text


def _create_text_file_chunk_verified(
    admin: base.LoopbackCHRAdmin,
    name: str,
    contents: str,
) -> None:
    expected_bytes = contents.encode("utf-8")
    if len(expected_bytes) > 60_000:
        raise base.CHRRenderDryRunError("render dry-run file exceeds RouterOS editable file limit")

    base._delete_file_if_present(admin, name)
    _, created = admin.request(
        "PUT",
        "file",
        {"name": name, "type": "file"},
    )
    file_id = None
    if isinstance(created, Mapping):
        file_id = str(created.get(".id") or "").strip() or None
    file_id = file_id or base._find_file_id(admin, name)
    if not file_id:
        raise base.CHRRenderDryRunError("RouterOS did not expose the created render dry-run file")

    admin.request("PATCH", f"file/{file_id}", {"contents": contents})
    _wait_for_file_size(admin, name, len(expected_bytes))
    observed = _read_text_file_chunked(admin, name)
    observed_bytes = observed.encode("utf-8")

    expected_sha256 = hashlib.sha256(expected_bytes).hexdigest()
    observed_sha256 = hashlib.sha256(observed_bytes).hexdigest()
    if observed != contents or observed_sha256 != expected_sha256:
        raise base.CHRRenderDryRunError(
            "RouterOS render dry-run file chunked round-trip mismatch: "
            f"name={name} expected_bytes={len(expected_bytes)} "
            f"observed_bytes={len(observed_bytes)} expected_sha256={expected_sha256} "
            f"observed_sha256={observed_sha256}"
        )


def _configuration_snapshot_with_pcc(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    """Extend the proven failover snapshot with PCC's mangle mutation surface."""

    snapshot = base._configuration_snapshot(admin)
    _, payload = admin.request("GET", "ip/firewall/mangle")
    fields = (
        "chain",
        "action",
        "connection-state",
        "connection-mark",
        "dst-address-type",
        "in-interface-list",
        "new-connection-mark",
        "per-connection-classifier",
        "new-routing-mark",
        "passthrough",
        "comment",
        "disabled",
    )
    normalized: list[dict[str, Any]] = []
    for row in base._rows(payload):
        if base._is_true(row.get("dynamic")):
            continue
        normalized.append(
            {
                field: row[field]
                for field in fields
                if field in row
            }
        )
    normalized.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    snapshot["firewall_mangle"] = normalized
    return snapshot


def verify_render_dry_run(*, admin_url: str, script_path: Path) -> dict[str, Any]:
    # Keep the already-proven verdict/digest logic in the base verifier. Replace
    # only the file round-trip primitive and extend the mutation snapshot with
    # PCC mangle state. This adapter remains lab-only and exposes no writer.
    original_create = base._create_text_file
    original_snapshot = base._configuration_snapshot
    base._create_text_file = _create_text_file_chunk_verified
    base._configuration_snapshot = _configuration_snapshot_with_pcc
    try:
        result = base.verify_render_dry_run(admin_url=admin_url, script_path=script_path)
    finally:
        base._create_text_file = original_create
        base._configuration_snapshot = original_snapshot
    result["file_roundtrip_verification"] = {
        "method": "routeros_file_read_chunked",
        "chunk_bytes": READ_CHUNK_BYTES,
        "sha256_verified": True,
    }
    result["mutation_surfaces"] = [
        "interface/list",
        "interface/list/member",
        "ip/address",
        "routing/table",
        "ip/route",
        "ip/firewall/mangle",
    ]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate generated RouterOS syntax using chunk-verified temporary files"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9180")
    parser.add_argument("--script", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_render_dry_run(
            admin_url=args.admin_url,
            script_path=Path(args.script),
        )
        rc = 0
    except (OSError, base.CHRRenderDryRunError) as exc:
        result = {"ok": False, "error": str(exc)}
        rc = 14

    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
