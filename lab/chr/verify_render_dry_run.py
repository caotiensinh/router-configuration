from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping


class CHRRenderDryRunError(RuntimeError):
    pass


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


def _parse_verdict_contents(contents: str) -> tuple[bool, str]:
    """Return (is_error, detail) from the temporary RouterOS verdict file."""

    text = str(contents or "").strip()
    if text == "OK":
        return False, ""
    if text.startswith("ERROR|"):
        detail = text[len("ERROR|"):].strip()
        if not detail:
            raise CHRRenderDryRunError("RouterOS dry-run verdict file contains an empty captured error")
        return True, detail
    raise CHRRenderDryRunError(
        f"RouterOS dry-run verdict file contains an unexpected value: {text[:200] or '<empty>'}"
    )


def _is_true(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _configuration_snapshot(admin: LoopbackCHRAdmin) -> dict[str, Any]:
    """Capture every static configuration surface exercised by the syntax fixture."""

    surface_specs = (
        ("interface_lists", "interface/list", ("name", "comment")),
        (
            "interface_list_members",
            "interface/list/member",
            ("list", "interface", "comment", "disabled"),
        ),
        (
            "ip_addresses",
            "ip/address",
            ("address", "network", "interface", "comment", "disabled"),
        ),
        (
            "routing_tables",
            "routing/table",
            ("name", "fib", "comment", "disabled"),
        ),
        (
            "ip_routes",
            "ip/route",
            (
                "dst-address",
                "gateway",
                "routing-table",
                "distance",
                "scope",
                "target-scope",
                "check-gateway",
                "comment",
                "disabled",
            ),
        ),
    )
    surfaces: dict[str, Any] = {}
    for key, path, fields in surface_specs:
        _, payload = admin.request("GET", path)
        normalized = []
        for row in _rows(payload):
            if _is_true(row.get("dynamic")):
                continue
            normalized.append(
                {
                    field: row[field]
                    for field in fields
                    if field in row
                }
            )
        normalized.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        surfaces[key] = normalized
    return surfaces


def _file_record(admin: LoopbackCHRAdmin, name: str) -> Mapping[str, Any] | None:
    _, payload = admin.request("GET", "file")
    return next((row for row in _rows(payload) if row.get("name") == name), None)


def _find_file_id(admin: LoopbackCHRAdmin, name: str) -> str | None:
    record = _file_record(admin, name)
    if record is None:
        return None
    value = str(record.get(".id") or "").strip()
    return value or None


def _delete_file_if_present(admin: LoopbackCHRAdmin, name: str) -> None:
    file_id = _find_file_id(admin, name)
    if file_id:
        admin.request("DELETE", f"file/{file_id}")


def _create_text_file(admin: LoopbackCHRAdmin, name: str, contents: str) -> None:
    if len(contents.encode("utf-8")) > 60_000:
        raise CHRRenderDryRunError("render dry-run file exceeds RouterOS editable file limit")
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

    record = _file_record(admin, name)
    if record is None or str(record.get("contents") or "") != contents:
        raise CHRRenderDryRunError("RouterOS render dry-run file contents did not round-trip")


def _read_file_contents(admin: LoopbackCHRAdmin, name: str) -> str:
    record = _file_record(admin, name)
    if record is None:
        raise CHRRenderDryRunError(f"RouterOS verdict file disappeared unexpectedly: {name}")
    return str(record.get("contents") or "")


def _wait_for_verdict(
    admin: LoopbackCHRAdmin,
    name: str,
    *,
    timeout_seconds: float = 10.0,
    poll_interval_seconds: float = 0.1,
) -> str:
    """Poll an async /rest/execute verdict file until it leaves PENDING."""

    deadline = time.monotonic() + timeout_seconds
    while True:
        contents = _read_file_contents(admin, name)
        if contents.strip() != "PENDING":
            return contents
        if time.monotonic() >= deadline:
            raise CHRRenderDryRunError(
                f"RouterOS dry-run verdict remained PENDING for {timeout_seconds:.1f}s"
            )
        time.sleep(poll_interval_seconds)


def _assert_files_absent(admin: LoopbackCHRAdmin, names: tuple[str, ...]) -> None:
    remaining = [name for name in names if _file_record(admin, name) is not None]
    if remaining:
        raise CHRRenderDryRunError(f"temporary RouterOS dry-run files were not removed: {remaining}")


def _execute_import_dry_run(
    admin: LoopbackCHRAdmin,
    *,
    file_name: str,
    verdict_name: str,
    expect_success: bool,
) -> dict[str, Any]:
    # /rest/execute returns an async job handle such as *12 for this workflow.
    # The RouterOS script itself writes a temporary verdict file; the host then
    # polls that file with a finite timeout. No opaque ret value can cause PASS.
    verdict_q = verdict_name.replace('"', '\\"')
    script = (
        f':onerror e in={{ import {file_name} verbose=yes dry-run }} do={{'
        f'/file set [find where name="{verdict_q}"] contents=("ERROR|" . [:tostr $e]);'
        ':return};'
        f'/file set [find where name="{verdict_q}"] contents="OK"'
    )
    status, response = admin.request(
        "POST",
        "execute",
        {"script": script},
        allow_http_error=True,
    )
    if status >= 400:
        raise CHRRenderDryRunError(
            f"RouterOS dry-run wrapper failed to start with HTTP {status}: {str(response)[:400]}"
        )

    contents = _wait_for_verdict(admin, verdict_name)
    captured_error, detail = _parse_verdict_contents(contents)
    if expect_success and captured_error:
        raise CHRRenderDryRunError(
            f"generated RouterOS script dry-run reported an error: {detail[:400]}"
        )
    if not expect_success and not captured_error:
        raise CHRRenderDryRunError("negative-control RouterOS script unexpectedly passed dry-run")

    opaque_ret = None
    if isinstance(response, Mapping):
        opaque_ret = str(response.get("ret") or "").strip() or None
    return {
        "http_status": status,
        "captured_error": captured_error,
        "error_detail": detail,
        "verdict": "ERROR" if captured_error else "OK",
        "verdict_channel": "temporary_routeros_file",
        "execute_ret_observed": opaque_ret,
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
    verdict_name = "routercfg-render-verdict.txt"
    temporary_names = (valid_name, invalid_name, verdict_name)
    before = _configuration_snapshot(admin)
    before_digest = _canonical_digest(before)

    valid_result: dict[str, Any] | None = None
    negative_result: dict[str, Any] | None = None
    cleanup_verified = False
    try:
        _create_text_file(admin, valid_name, script_contents)
        _create_text_file(admin, verdict_name, "PENDING")
        valid_result = _execute_import_dry_run(
            admin,
            file_name=valid_name,
            verdict_name=verdict_name,
            expect_success=True,
        )

        # MikroTik's RouterOS 7.16+ import documentation uses `this` as the
        # canonical bad-command example for syntax-error handling.
        _create_text_file(admin, invalid_name, "this\n")
        verdict_id = _find_file_id(admin, verdict_name)
        if not verdict_id:
            raise CHRRenderDryRunError("RouterOS verdict file is missing before negative control")
        admin.request("PATCH", f"file/{verdict_id}", {"contents": "PENDING"})
        negative_result = _execute_import_dry_run(
            admin,
            file_name=invalid_name,
            verdict_name=verdict_name,
            expect_success=False,
        )
    finally:
        for name in temporary_names:
            _delete_file_if_present(admin, name)
        _assert_files_absent(admin, temporary_names)
        cleanup_verified = True

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
        "verdict_channel": "temporary_routeros_file",
        "generated_script": {
            "sha256": hashlib.sha256(script_contents.encode("utf-8")).hexdigest(),
            "byte_length": len(script_contents.encode("utf-8")),
            "dry_run_passed": True,
            "http_status": valid_result.get("http_status") if valid_result else None,
            "verdict": valid_result.get("verdict") if valid_result else None,
            "execute_ret_observed": valid_result.get("execute_ret_observed") if valid_result else None,
        },
        "negative_control": {
            "fixture": "this",
            "dry_run_rejected": True,
            "http_status": negative_result.get("http_status") if negative_result else None,
            "verdict": negative_result.get("verdict") if negative_result else None,
            "error_detail": negative_result.get("error_detail") if negative_result else None,
            "execute_ret_observed": negative_result.get("execute_ret_observed") if negative_result else None,
        },
        "configuration_before_sha256": before_digest,
        "configuration_after_sha256": after_digest,
        "configuration_changed": False,
        "snapshot_surfaces": [
            "interface/list",
            "interface/list/member",
            "ip/address",
            "routing/table",
            "ip/route",
        ],
        "temporary_files_removed": cleanup_verified,
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
