from __future__ import annotations

import argparse
import base64
import json
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping


class LabBootstrapError(RuntimeError):
    pass


class LoopbackRestAdmin:
    """Purpose-limited mutator for disposable CHR acceptance setup only.

    This class is intentionally outside src/router_configuration and is not
    imported by routerctl. It refuses non-loopback targets and verifies the
    target identifies itself as CHR before any mutation.
    """

    def __init__(self, base_url: str) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise LabBootstrapError("bootstrap admin target must be loopback HTTP")
        self.base_url = base_url.rstrip("/")
        self._admin_header = "Basic " + base64.b64encode(b"admin:").decode("ascii")

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        authorization: str | None = None,
        context: ssl.SSLContext | None = None,
    ) -> Any:
        data = None
        headers = {"Authorization": authorization or self._admin_header}
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
            with urllib.request.urlopen(request, timeout=10, context=context) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise LabBootstrapError(
                f"RouterOS REST {method} {path} failed with HTTP {exc.code}: {detail[:400]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise LabBootstrapError(
                f"RouterOS REST {method} {path} failed: {exc.reason.__class__.__name__}"
            ) from exc
        if not raw:
            return None
        return json.loads(raw.decode("utf-8"))

    def assert_disposable_chr(self) -> Mapping[str, Any]:
        payload = self.request("GET", "system/resource")
        if not isinstance(payload, Mapping):
            raise LabBootstrapError("system/resource did not return an object")
        if payload.get("platform") != "MikroTik":
            raise LabBootstrapError("target is not a MikroTik RouterOS platform")
        board = str(payload.get("board-name") or "")
        architecture = str(payload.get("architecture-name") or "")
        if not board.startswith("CHR") or architecture != "x86_64":
            raise LabBootstrapError("bootstrap is restricted to x86_64 CHR lab targets")
        return payload


def _basic_auth(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _first_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                return item
    return None


def bootstrap_secure_acceptance(
    *,
    admin_url: str,
    https_url: str,
    ca_output: Path,
    credentials_output: Path,
) -> dict[str, Any]:
    https_parsed = urllib.parse.urlparse(https_url)
    if https_parsed.scheme != "https" or https_parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise LabBootstrapError("secure acceptance URL must be loopback HTTPS")

    admin = LoopbackRestAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    reader_password = secrets.token_urlsafe(30)

    admin.request(
        "PUT",
        "user/group",
        {
            "name": "routercfg-read",
            "policy": "read,rest-api",
        },
    )
    admin.request(
        "PUT",
        "user",
        {
            "name": "routercfg-reader",
            "group": "routercfg-read",
            "password": reader_password,
        },
    )

    admin.request(
        "PUT",
        "certificate",
        {
            "name": "routercfg-ca",
            "common-name": "Router Configuration CHR Lab CA",
            "key-usage": "key-cert-sign,crl-sign",
            "trusted": "yes",
        },
    )
    admin.request(
        "POST",
        "certificate/sign",
        {"numbers": "routercfg-ca", "name": "routercfg-ca"},
    )
    admin.request(
        "PUT",
        "certificate",
        {
            "name": "routercfg-https",
            "common-name": "127.0.0.1",
            "subject-alt-name": "IP:127.0.0.1",
            "key-usage": "digital-signature,key-encipherment,tls-server",
        },
    )
    admin.request(
        "POST",
        "certificate/sign",
        {
            "numbers": "routercfg-https",
            "ca": "routercfg-ca",
            "name": "routercfg-https",
        },
    )
    admin.request(
        "PATCH",
        "ip/service/www-ssl",
        {
            "certificate": "routercfg-https",
            "disabled": "false",
            "port": "443",
        },
    )

    admin.request(
        "POST",
        "certificate/export-certificate",
        {
            "numbers": "routercfg-ca",
            "file-name": "routercfg-ca",
            "type": "pem",
        },
    )
    files = admin.request("GET", "file?name=routercfg-ca.crt")
    file_record = _first_mapping(files)
    if not file_record or not str(file_record.get("contents") or "").strip():
        # Some RouterOS builds omit file contents from filtered print. Ask for
        # the complete file table and select locally before failing.
        all_files = admin.request("GET", "file")
        records = all_files if isinstance(all_files, list) else []
        file_record = next(
            (
                item
                for item in records
                if isinstance(item, Mapping) and item.get("name") == "routercfg-ca.crt"
            ),
            None,
        )
    if not file_record or not str(file_record.get("contents") or "").strip():
        raise LabBootstrapError("exported CA certificate contents were not available through REST")

    ca_pem = str(file_record["contents"])
    if "BEGIN CERTIFICATE" not in ca_pem:
        raise LabBootstrapError("exported CA file is not PEM certificate data")
    ca_output.parent.mkdir(parents=True, exist_ok=True)
    ca_output.write_text(ca_pem.rstrip() + "\n", encoding="utf-8")

    credentials_output.parent.mkdir(parents=True, exist_ok=True)
    credentials_output.write_text(
        json.dumps(
            {
                "username": "routercfg-reader",
                "password": reader_password,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    try:
        credentials_output.chmod(0o600)
    except OSError:
        pass

    context = ssl.create_default_context(cafile=str(ca_output))
    reader_header = _basic_auth("routercfg-reader", reader_password)
    secure_request = urllib.request.Request(
        f"{https_url.rstrip('/')}/rest/system/resource",
        method="GET",
        headers={"Authorization": reader_header},
    )
    try:
        with urllib.request.urlopen(secure_request, timeout=10, context=context) as response:
            secure_resource = json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, ssl.SSLError) as exc:
        raise LabBootstrapError(
            f"dedicated reader HTTPS verification failed: {exc.__class__.__name__}"
        ) from exc

    if not isinstance(secure_resource, Mapping):
        raise LabBootstrapError("dedicated reader HTTPS response was not an object")
    if secure_resource.get("version") != platform.get("version"):
        raise LabBootstrapError("HTTPS reader reached a different RouterOS target")

    return {
        "ok": True,
        "scope": "disposable_chr_secure_acceptance_bootstrap",
        "platform": {
            "version": platform.get("version"),
            "architecture": platform.get("architecture-name"),
            "board_name": platform.get("board-name"),
        },
        "reader": {
            "username": "routercfg-reader",
            "policy": "read,rest-api",
        },
        "https": {
            "url": https_url,
            "certificate_verification": True,
            "ca_file": str(ca_output),
        },
        "credentials_file": str(credentials_output),
        "production_writer_available": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap secure read-only acceptance on disposable loopback CHR only"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9180")
    parser.add_argument("--https-url", default="https://127.0.0.1:9443")
    parser.add_argument("--ca-output", required=True)
    parser.add_argument("--credentials-output", required=True)
    args = parser.parse_args()

    try:
        payload = bootstrap_secure_acceptance(
            admin_url=args.admin_url,
            https_url=args.https_url,
            ca_output=Path(args.ca_output),
            credentials_output=Path(args.credentials_output),
        )
    except LabBootstrapError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 9

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
