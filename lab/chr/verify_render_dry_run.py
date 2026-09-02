from __future__ import annotations

import argparse
import base64
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping


class CHRRenderDryRunError(RuntimeError):
    pass


_SCRIPT_ERROR_MARKERS = (
    "script error",
    "bad command",
    "syntax error",
    "expected end of command",
    "no such command",
)


class LoopbackCHRAdmin:
    """Lab-only RouterOS REST mutator restricted to disposable loopback CHR."""

    def __init__(self, base_url: str) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise CHRRenderDryRunError("render dry-run lab target must be loopback HTTP")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise CHRRenderDryRunError("render dry-run lab URL must not contain path/query/fragment")
        self.base_url = base_url.rstrip("/")
        token = base64.b64encode(b"admin:").decode("ascii")
        self.headers = {"Authorization": f"Basic {token}"}

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        allow_http_error: bool = False,
    ) -> tuple[int, Any]:
        data = None
        headers = dict(self.headers)
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.base_url}/rest/{path.lstrip('/')}",
            data=data,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read()
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = int(exc.code)
            if not allow_http_error:
                detail = raw.decode("utf-8", errors="replace")[:400]
                raise CHRRenderDryRunError(
                    f"RouterOS REST {method} {path} failed with HTTP {status}: {detail}"
                ) from exc
        except urllib.error.URLError as exc:
            raise CHRRenderDryRunError(
                f"RouterOS REST {method} {path} transport failed: {exc.reason.__class__.__name__}"
            ) from exc

        if not raw:
            return status, None
        try:
            return status, json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return status, {"raw": raw.decode("utf-8", errors="replace")[:1000]}

    def assert_disposable_chr(self) -> Mapping[str, Any]:
        _, payload = self.request("GET", "system/resource")
        if not isinstance(payload, Mapping):
            raise CHRRenderDryRunError("system/resource did not return an object")
        if payload.get("platform") != "MikroTik":
            raise CHRRenderDryRunError("target is not RouterOS")
        if str(payload.get("architecture-name") or "") != "x86_64":
            raise CHRRenderDryRunError("render dry-run lab is restricted to x86_64 CHR")
        if not str(payload.get("board-name") or "").startswith("CHR"):
            raise CHRRenderDryRunError("render dry-run lab is restricted to CHR")
        return payload


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _rows(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    if isinstance(payload, Mapping):
        return [payload]
    return []


def _response_has_script_error(payload: Any) -> bool:
    """Detect RouterOS import/script failure even if /rest/execute returns HTTP 2xx."""

    if payload is None:
        return False
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False).lower()
    return any(marker in text for marker in _SCRIPT_ERROR_MARKERS)


def _configuration_snapshot(admin: LoopbackCHRAdmin) -> dict[str, Any]:
    """Capture only surfaces the current renderer syntax fixture could mutate."""

    surfaces: dict[str, Any] = {}
    for key, path in (
        ("interface_lists", "interface/list"),
        ("interface_list_members", "interface/list/member"),
    ):
        _, payload = admin.request("GET", path)
        normalized = []
        for row in _rows(payload):
            normalized.append(
                {
                    str(k): v
                    for k, v in row.items()
                    if k not in {".id", "dynamic", "invalid"}
                }
            )
        normalized.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        surfaces[key] = normalized
    return surfaces


def _find_file_id(admin: LoopbackCHRAdmin, name: str) -> str | None:
    _, payload = admin.request("GET", "file")
    for row in _rows(payload):
        if row.get("name") == name:
            value = str(row.get(".id") or "").strip()
            return value or None
    return None


def _delete_file_if_present(admin: LoopbackCHRAdmin, name: str) -> None:
    file_id = _find_file_id(admin, name)
    if file_id:
        admin.request("DELETE", f"file/{file_id}")


def _create_script_file(admin: LoopbackCHRAdmin, name: str, contents: str) -> None:
    if len(contents.encode("utf-8")) > 60_000:
        raise CHRRenderDryRunError("render dry-run script exceeds RouterOS editable file limit")
    _delete_file_if_present(admin, name)
    _, created = admin.request(
        "PUT",
        "file",
        {"name": name, "type": "file"},
    )
    file_id = None
    if isinstance(created, Mapping):
        file_id = str(created.get(".id") or "").strip() or None
    file_id = file_id or _find_file_id(admin, name)
    if not file_id:
        raise CHRRenderDryRunError("RouterOS did not expose the created render dry-run file")
    admin.request("PATCH", f"file/{file_id}", {"contents": contents})

    _, files = admin.request("GET", "file")
    record = next((row for row in _rows(files) if row.get("name") == name), None)
    if record is None or str(record.get("contents") or "") != contents:
        raise CHRRenderDryRunError("RouterOS render dry-run file contents did not round-trip")


def _execute_import_dry_run(
    admin: LoopbackCHRAdmin,
    *,
    file_name: str,
    expect_success: bool,
) -> dict[str, Any]:
    script = f"import {file_name} verbose=yes dry-run"
    status, payload = admin.request(
        "POST",
        "execute",
        {"script": script},
        allow_http_error=True,
    )
    response_has_script_error = _response_has_script_error(payload)
    transport_success = status < 400

    if expect_success:
        if not transport_success or response_has_script_error:
            raise CHRRenderDryRunError(
                "generated RouterOS script dry-run reported an error "
                f"(HTTP {status}): {str(payload)[:400]}"
            )
    else:
        if not response_has_script_error:
            raise CHRRenderDryRunError(
                "negative-control dry-run did not expose a recognizable RouterOS script error "
                f"(HTTP {status}): {str(payload)[:400]}"
            )

    return {
        "http_status": status,
        "response_has_script_error": response_has_script_error,
        "response": payload,
    }


def verify_render_dry_run(
    *,
    admin_url: str,
    script_path: Path,
) -> dict[str, Any]:
    admin = LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    script_contents = script_path.read_text(encoding="utf-8")
    if not script_contents.strip():
        raise CHRRenderDryRunError("generated RouterOS script is empty")

    valid_name = "routercfg-render-dryrun.rsc"
    invalid_name = "routercfg-render-negative-control.rsc"
    before = _configuration_snapshot(admin)
    before_digest = _canonical_digest(before)

    valid_result: dict[str, Any] | None = None
    negative_result: dict[str, Any] | None = None
    try:
        _create_script_file(admin, valid_name, script_contents)
        valid_result = _execute_import_dry_run(
            admin,
            file_name=valid_name,
            expect_success=True,
        )

        # MikroTik's RouterOS 7.16+ import documentation uses `this` as the
        # canonical bad-command example for syntax-error handling.
        _create_script_file(admin, invalid_name, "this\n")
        negative_result = _execute_import_dry_run(
            admin,
            file_name=invalid_name,
            expect_success=False,
        )
    finally:
        _delete_file_if_present(admin, valid_name)
        _delete_file_if_present(admin, invalid_name)

    after = _configuration_snapshot(admin)
    after_digest = _canonical_digest(after)
    if after_digest != before_digest:
        raise CHRRenderDryRunError("RouterOS configuration changed during import dry-run validation")

    return {
        "ok": True,
        "scope": "disposable_chr_routeros_render_dry_run",
        "platform": {
            "version": platform.get("version"),
            "architecture": platform.get("architecture-name"),
            "board_name": platform.get("board-name"),
        },
        "generated_script": {
            "sha256": hashlib.sha256(script_contents.encode("utf-8")).hexdigest(),
            "byte_length": len(script_contents.encode("utf-8")),
            "dry_run_passed": True,
            "http_status": valid_result.get("http_status") if valid_result else None,
            "response_has_script_error": (
                valid_result.get("response_has_script_error") if valid_result else None
            ),
        },
        "negative_control": {
            "fixture": "this",
            "dry_run_rejected": True,
            "http_status": negative_result.get("http_status") if negative_result else None,
            "response_has_script_error": (
                negative_result.get("response_has_script_error") if negative_result else None
            ),
        },
        "configuration_before_sha256": before_digest,
        "configuration_after_sha256": after_digest,
        "configuration_changed": False,
        "temporary_files_removed": True,
        "lab_setup_write_operations_performed": True,
        "production_writer_available": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate generated RouterOS syntax with CHR import verbose dry-run and negative control"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9180")
    parser.add_argument("--script", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        result = verify_render_dry_run(
            admin_url=args.admin_url,
            script_path=Path(args.script),
        )
    except (OSError, CHRRenderDryRunError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 14

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
