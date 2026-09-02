from __future__ import annotations

import argparse
import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class ReaderBoundaryError(RuntimeError):
    pass


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

    read_request = urllib.request.Request(
        f"{base_url}/rest/system/resource", headers=headers, method="GET"
    )
    try:
        with urllib.request.urlopen(read_request, timeout=10, context=context) as response:
            resource = json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, ssl.SSLError) as exc:
        raise ReaderBoundaryError(f"dedicated reader GET failed: {exc.__class__.__name__}") from exc
    if not isinstance(resource, dict) or resource.get("platform") != "MikroTik":
        raise ReaderBoundaryError("dedicated reader GET did not reach RouterOS")

    payload = json.dumps(
        {
            "chain": "input",
            "action": "accept",
            "protocol": "tcp",
            "dst-port": "65534",
            "comment": "routercfg-readonly-boundary-probe",
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
    try:
        with urllib.request.urlopen(write_request, timeout=10, context=context) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise ReaderBoundaryError(
                f"dedicated reader write returned HTTP {exc.code}, expected 403"
            ) from exc
    except (urllib.error.URLError, ssl.SSLError) as exc:
        raise ReaderBoundaryError(
            f"dedicated reader write-denial probe transport failed: {exc.__class__.__name__}"
        ) from exc
    else:
        raise ReaderBoundaryError("dedicated reader unexpectedly performed a write operation")

    return {
        "ok": True,
        "scope": "disposable_chr_reader_permission_boundary",
        "username": username,
        "read_verified": True,
        "write_denied_http_status": 403,
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
