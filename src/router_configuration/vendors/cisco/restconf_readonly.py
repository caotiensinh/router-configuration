"""Fail-closed Cisco IOS XE RESTCONF read-only contract helpers.

The module validates only source-bound GET requests and parses minimized RESTCONF
evidence. It does not perform HTTP requests and does not authorize writes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from .knowledge import CiscoOfflineKnowledge

MAX_RESTCONF_BODY_BYTES = 512 * 1024
XRD_NS = "http://docs.oasis-open.org/ns/xri/xrd-1.0"

_SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "private-key",
    "private_key",
    "pre-shared-key",
    "preshared-key",
    "psk",
    "token",
    "community",
    "key-string",
    "key_string",
)


class CiscoRestconfEvidenceError(ValueError):
    """Raised when RESTCONF request/evidence violates the read-only contract."""


@dataclass(frozen=True)
class RestconfQueryDefinition:
    query_id: str
    relative_uri: str
    accept: str
    response_kind: str
    source_ids: tuple[str, ...]


@dataclass(frozen=True)
class RestconfReadOnlyRequestDecision:
    allowed: bool
    status: str
    query_id: str | None
    method: str
    reason: str


@dataclass(frozen=True)
class RestconfRootEvidence:
    root_href: str
    digest_sha256: str


@dataclass(frozen=True)
class RestconfNativeIdentity:
    hostname: str
    iosxe_version: str
    digest_sha256: str


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _media_type(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def query_definition(
    query_id: str,
    knowledge: CiscoOfflineKnowledge | None = None,
) -> RestconfQueryDefinition:
    catalog = (knowledge or CiscoOfflineKnowledge()).restconf_readonly_catalog
    for item in catalog["evidence_queries"]:
        if item["id"] == query_id:
            return RestconfQueryDefinition(
                query_id=item["id"],
                relative_uri=item["relative_uri"],
                accept=item["accept"],
                response_kind=item["response_kind"],
                source_ids=tuple(item["source_ids"]),
            )
    raise CiscoRestconfEvidenceError(f"unknown source-bound RESTCONF query: {query_id}")


def validate_restconf_request(
    *,
    query_id: str,
    method: str,
    url: str,
    headers: Mapping[str, str],
    verify_tls: bool,
    allow_redirects: bool,
    knowledge: CiscoOfflineKnowledge | None = None,
) -> RestconfReadOnlyRequestDecision:
    try:
        query = query_definition(query_id, knowledge)
    except CiscoRestconfEvidenceError as exc:
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="UNVERIFIED_QUERY",
            query_id=None,
            method=method.upper().strip(),
            reason=str(exc),
        )

    normalized_method = method.upper().strip()
    if normalized_method != "GET":
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="WRITE_OR_UNAPPROVED_METHOD",
            query_id=query_id,
            method=normalized_method,
            reason="Cisco RESTCONF read-only contract permits GET only",
        )
    if verify_tls is not True:
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="TLS_VERIFICATION_REQUIRED",
            query_id=query_id,
            method=normalized_method,
            reason="TLS certificate verification cannot be disabled",
        )
    if allow_redirects is not False:
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="REDIRECTS_NOT_ALLOWED",
            query_id=query_id,
            method=normalized_method,
            reason="RESTCONF evidence requests must not follow redirects",
        )

    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="HTTPS_REQUIRED",
            query_id=query_id,
            method=normalized_method,
            reason="RESTCONF evidence request requires an absolute HTTPS URL",
        )
    if parsed.username is not None or parsed.password is not None:
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="URL_CREDENTIALS_FORBIDDEN",
            query_id=query_id,
            method=normalized_method,
            reason="credentials must not be embedded in RESTCONF URLs",
        )
    if parsed.fragment:
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="URL_FRAGMENT_FORBIDDEN",
            query_id=query_id,
            method=normalized_method,
            reason="RESTCONF evidence request must not contain a URL fragment",
        )

    actual_relative = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    if actual_relative != query.relative_uri:
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="UNVERIFIED_URI",
            query_id=query_id,
            method=normalized_method,
            reason="URL path/query does not match the source-bound RESTCONF catalog entry",
        )

    normalized_headers = {str(key).lower(): str(value).strip() for key, value in headers.items()}
    if _media_type(normalized_headers.get("accept", "")) != query.accept.lower():
        return RestconfReadOnlyRequestDecision(
            allowed=False,
            status="ACCEPT_HEADER_MISMATCH",
            query_id=query_id,
            method=normalized_method,
            reason="Accept header does not match the source-bound RESTCONF query",
        )

    return RestconfReadOnlyRequestDecision(
        allowed=True,
        status="READ_ONLY_GET_ALLOWED",
        query_id=query_id,
        method=normalized_method,
        reason="request matches validated Cisco RESTCONF read-only catalog",
    )


def _bounded_text(body: str | bytes) -> str:
    if isinstance(body, bytes):
        encoded = body
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CiscoRestconfEvidenceError("RESTCONF evidence must be UTF-8") from exc
    elif isinstance(body, str):
        text = body
        encoded = body.encode("utf-8")
    else:
        raise CiscoRestconfEvidenceError("RESTCONF evidence body must be text or bytes")
    if not text.strip():
        raise CiscoRestconfEvidenceError("RESTCONF evidence body is empty")
    if len(encoded) > MAX_RESTCONF_BODY_BYTES:
        raise CiscoRestconfEvidenceError("RESTCONF evidence exceeds bounded body size")
    return text


def parse_restconf_root_discovery(
    *,
    status_code: int,
    content_type: str,
    body: str | bytes,
) -> RestconfRootEvidence:
    if status_code != 200:
        raise CiscoRestconfEvidenceError("RESTCONF root discovery requires HTTP 200")
    if _media_type(content_type) != "application/xrd+xml":
        raise CiscoRestconfEvidenceError("RESTCONF root discovery content type mismatch")
    text = _bounded_text(body)
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise CiscoRestconfEvidenceError("DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise CiscoRestconfEvidenceError(f"invalid RESTCONF root XRD: {exc}") from exc
    if root.tag != f"{{{XRD_NS}}}XRD":
        raise CiscoRestconfEvidenceError("RESTCONF root discovery expected an XRD document")
    links = [
        element
        for element in root.findall(f"{{{XRD_NS}}}Link")
        if element.attrib.get("rel") == "restconf"
    ]
    hrefs = sorted({element.attrib.get("href", "") for element in links if element.attrib.get("href")})
    if hrefs != ["/restconf"]:
        raise CiscoRestconfEvidenceError("RESTCONF root discovery must prove exactly /restconf")
    return RestconfRootEvidence(
        root_href="/restconf",
        digest_sha256=_canonical_sha256({"root_href": "/restconf"}),
    )


def _normalized_local_key(key: str) -> str:
    return key.rsplit(":", 1)[-1].strip().lower()


def _reject_sensitive_json(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            local = _normalized_local_key(str(key))
            if any(part in local for part in _SENSITIVE_KEY_PARTS):
                raise CiscoRestconfEvidenceError(f"sensitive RESTCONF JSON field at {path}")
            _reject_sensitive_json(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_json(child, f"{path}[{index}]")


def parse_yang_json_response(
    *,
    status_code: int,
    content_type: str,
    body: str | bytes,
) -> tuple[dict, str]:
    if status_code != 200:
        raise CiscoRestconfEvidenceError("RESTCONF read-only evidence requires HTTP 200")
    if _media_type(content_type) != "application/yang-data+json":
        raise CiscoRestconfEvidenceError("RESTCONF YANG JSON content type mismatch")
    text = _bounded_text(body)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CiscoRestconfEvidenceError(f"invalid RESTCONF JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise CiscoRestconfEvidenceError("RESTCONF YANG JSON root must be an object")
    _reject_sensitive_json(parsed)
    return parsed, _canonical_sha256(parsed)


def parse_native_identity_json(
    *,
    status_code: int,
    content_type: str,
    body: str | bytes,
) -> RestconfNativeIdentity:
    parsed, _ = parse_yang_json_response(
        status_code=status_code,
        content_type=content_type,
        body=body,
    )
    native = parsed.get("Cisco-IOS-XE-native:native")
    if not isinstance(native, dict):
        raise CiscoRestconfEvidenceError("RESTCONF identity response lacks Cisco native container")
    if set(native) != {"hostname", "version"}:
        raise CiscoRestconfEvidenceError(
            "RESTCONF identity response must contain only bounded hostname/version fields"
        )
    hostname = native.get("hostname")
    version = native.get("version")
    if not isinstance(hostname, str) or not hostname.strip():
        raise CiscoRestconfEvidenceError("RESTCONF identity hostname is missing")
    if not isinstance(version, str) or not version.strip():
        raise CiscoRestconfEvidenceError("RESTCONF identity IOS XE version is missing")
    identity = {"hostname": hostname.strip(), "iosxe_version": version.strip()}
    return RestconfNativeIdentity(
        hostname=identity["hostname"],
        iosxe_version=identity["iosxe_version"],
        digest_sha256=_canonical_sha256(identity),
    )
