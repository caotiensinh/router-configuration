from __future__ import annotations

import argparse
import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping


class ReaderBoundaryError(RuntimeError):
    pass


BOUNDARY_PROBE_MARKER = "routercfg-readonly-boundary-probe"
_PERMISSION_MARKERS = (
    "not enough permissions",
    "not allowed",
    "permission denied",
    "forbidden",
)


def _loopback_https(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ReaderBoundaryError("reader boundary probe requires loopback HTTPS")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ReaderBoundaryError("reader boundary URL must not include path, query or fragment")
    return url.rstrip("/")


def _auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _decode_routeros_error(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {"detail": raw.decode("utf-8", errors="replace")[:400]}
    if isinstance(payload, Mapping):
        return {str(key): value for key, value in payload.items()}
    return {"detail": str(payload)[:400]}


def _is_explicit_permission_denial(status: int, payload: Mapping[str, Any]) -> bool:
    """Accept only an HTTP failure that clearly represents authorization denial.

    RouterOS REST is a JSON wrapper over console/API operations. RouterOS 7.24.1
    may surface a missing write policy as HTTP 500 with a permission error in the
    response body instead of HTTP 403. We therefore require either a direct 403,
    or a 500 whose RouterOS error text explicitly says permission/not-allowed.
    Arbitrary 5xx errors never satisfy this boundary check.
    """

    if status == 403:
        return True
    if status != 500:
        return False
    text = " ".join(str(payload.get(key) or "") for key in ("message", "detail", "error"))
    lowered = text.lower()
    return any(marker in lowered for marker in _PERMISSION_MARKERS)


def _contains_probe_marker(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_probe_marker(key) or _contains_probe_marker(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_probe_marker(item) for item in value)
    return BOUNDARY_PROBE_MARKER in str(value)


def _read_json(
    *,
    base_url: str,
    path: str,
    headers: Mapping[str, str],
    context: ssl.SSLContext,
) -> Any:
    request = urllib.request.Request(
        f"{base_url}/rest/{path.lstrip('/')}",
        headers=dict(headers),
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, ssl.SSLError) as exc:
        raise ReaderBoundaryError(f"dedicated reader GET failed: {exc.__class__.__name__}") from exc


def verify_reader_boundary(*, url: str, ca_file: Path, credentials_file: Path) -> dict[str, object]:
    base_url = _loopback_https(url)
    credentials = json.loads(credentials_file.read_text(encoding="utf-8"))
    username = str(credentials.get("username") or "")
    password = str(credentials.get("password") or "")
    if username != "routercfg-reader" or not password:
        raise ReaderBoundaryError("unexpected or incomplete dedicated-reader credentials")

    context = ssl.create_default_context(cafile=str(ca_file))
    headers = {
        "Authorization": _auth_header(username, password),
        "Accept": "application/json",
    }

    resource = _read_json(
        base_url=base_url,
        path="system/resource",
        headers=headers,
        context=context,
    )
    if not isinstance(resource, dict) or resource.get("platform") != "MikroTik":
        raise ReaderBoundaryError("dedicated reader GET did not reach RouterOS")

    payload = json.dumps(
        {
            "chain": "input",
            "action": "accept",
            "protocol": "tcp",
            "dst-port": "65534",
            "comment": BOUNDARY_PROBE_MARKER,
        }
    ).encode("utf-8")
    write_headers = dict(headers)
    write_headers["Content-Type"] = "application/json"
    write_request = urllib.request.Request(
        f"{base_url}/rest/ip/firewall/filter",
        data=payload,
        headers=write_headers,
        method="PUT",
    )

    denied_status: int | None = None
    denial_payload: dict[str, Any] = {}
    try:
        with urllib.request.urlopen(write_request, timeout=10, context=context) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        denied_status = int(exc.code)
        denial_payload = _decode_routeros_error(exc.read())
        if not _is_explicit_permission_denial(denied_status, denial_payload):
            detail = str(denial_payload.get("detail") or denial_payload.get("message") or "")[:240]
            raise ReaderBoundaryError(
                f"dedicated reader write failed with unverified HTTP {denied_status}: {detail}"
            ) from exc
    except (urllib.error.URLError, ssl.SSLError) as exc:
        raise ReaderBoundaryError(
            f"dedicated reader write-denial probe transport failed: {exc.__class__.__name__}"
        ) from exc
    else:
        raise ReaderBoundaryError("dedicated reader unexpectedly performed a write operation")

    filters = _read_json(
        base_url=base_url,
        path="ip/firewall/filter",
        headers=headers,
        context=context,
    )
    if _contains_probe_marker(filters):
        raise ReaderBoundaryError("reader boundary probe object exists after denied write")

    safe_error = {
        key: denial_payload[key]
        for key in ("error", "message", "detail")
        if key in denial_payload
    }
    return {
        "ok": True,
        "scope": "disposable_chr_reader_permission_boundary",
        "username": username,
        "read_verified": True,
        "write_denied_http_status": denied_status,
        "write_denial_error": safe_error,
        "write_denial_verified_by_readback": True,
        "probe_marker_absent_after_denial": True,
        "write_authorized": False,
        "production_writer_available": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a disposable CHR least-privilege reader can GET but cannot write"
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        result = verify_reader_boundary(
            url=args.url,
            ca_file=Path(args.ca_file),
            credentials_file=Path(args.credentials_file),
        )
    except (OSError, json.JSONDecodeError, ReaderBoundaryError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 11

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
