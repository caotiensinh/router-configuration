"""Live Cisco IOS XE RESTCONF read-only probe.

The probe executes only source-bound GET requests from the validated RESTCONF
catalog. Credentials remain runtime-only, TLS verification is mandatory, and
persisted evidence is minimized and sanitized. C04 completion additionally
requires independently bound exact-platform evidence for the same target.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
from typing import Callable, Mapping

from .knowledge import CiscoOfflineKnowledge
from .platforms import assess_read_only_candidate, documentation_train
from .restconf_readonly import (
    MAX_RESTCONF_BODY_BYTES,
    RestconfCapabilityInventory,
    parse_native_identity_json,
    parse_restconf_capabilities_xml,
    parse_restconf_root_discovery,
    query_definition,
    validate_restconf_request,
)

_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


class CiscoRestconfProbeError(ValueError):
    """Raised for a sanitized, fail-closed live-probe failure."""


@dataclass(frozen=True)
class RestconfHttpEvidence:
    status_code: int
    content_type: str
    body: bytes
    peer_certificate_sha256: str


RequestFn = Callable[
    [str, str, Mapping[str, str], ssl.SSLContext, str, int, float, RestconfCapabilityInventory | None],
    RestconfHttpEvidence,
]


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _valid_sha256(value: str) -> bool:
    return bool(_SHA256_RE.fullmatch(value.lower()))


def _validate_host(host: str) -> str:
    value = host.strip()
    if (
        not value
        or "://" in value
        or "/" in value
        or "\\" in value
        or "@" in value
        or any(character.isspace() for character in value)
    ):
        raise CiscoRestconfProbeError("invalid_target_host")
    if ":" in value:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise CiscoRestconfProbeError("invalid_target_host") from exc
        if parsed.version != 6:
            raise CiscoRestconfProbeError("invalid_target_host")
        return parsed.compressed
    if not _HOSTNAME_RE.fullmatch(value):
        raise CiscoRestconfProbeError("invalid_target_host")
    return value.rstrip(".").lower()


def _validate_port(raw: str) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise CiscoRestconfProbeError("invalid_target_port") from exc
    if not 1 <= value <= 65535:
        raise CiscoRestconfProbeError("invalid_target_port")
    return value


def _validate_timeout(raw: str) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise CiscoRestconfProbeError("invalid_timeout") from exc
    if not 1.0 <= value <= 30.0:
        raise CiscoRestconfProbeError("invalid_timeout")
    return value


def _url_authority(host: str, port: int) -> str:
    display_host = f"[{host}]" if ":" in host else host
    return display_host if port == 443 else f"{display_host}:{port}"


def _build_ssl_context(ca_pem_b64: str | None) -> ssl.SSLContext:
    if ca_pem_b64:
        try:
            pem_bytes = base64.b64decode(ca_pem_b64, validate=True)
            pem = pem_bytes.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise CiscoRestconfProbeError("invalid_ca_bundle") from exc
        if "-----BEGIN CERTIFICATE-----" not in pem or "-----END CERTIFICATE-----" not in pem:
            raise CiscoRestconfProbeError("invalid_ca_bundle")
        try:
            context = ssl.create_default_context(cadata=pem)
        except (ssl.SSLError, ValueError) as exc:
            raise CiscoRestconfProbeError("invalid_ca_bundle") from exc
    else:
        context = ssl.create_default_context()

    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise CiscoRestconfProbeError("tls_verification_not_enforced")
    return context


def _authorization_header(username: str, password: str) -> str:
    if (
        not username
        or ":" in username
        or any(character in username for character in "\r\n")
        or any(character in password for character in "\r\n")
    ):
        raise CiscoRestconfProbeError("invalid_runtime_credentials")
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _https_get(
    query_id: str,
    url: str,
    headers: Mapping[str, str],
    ssl_context: ssl.SSLContext,
    host: str,
    port: int,
    timeout: float,
    observed_capabilities: RestconfCapabilityInventory | None,
) -> RestconfHttpEvidence:
    decision = validate_restconf_request(
        query_id=query_id,
        method="GET",
        url=url,
        headers=headers,
        verify_tls=True,
        allow_redirects=False,
        observed_capabilities=observed_capabilities,
    )
    if not decision.allowed:
        raise CiscoRestconfProbeError(decision.status.lower())

    query = query_definition(query_id)
    connection = http.client.HTTPSConnection(
        host=host,
        port=port,
        timeout=timeout,
        context=ssl_context,
    )
    try:
        connection.request("GET", query.relative_uri, headers=dict(headers))
        response = connection.getresponse()
        if 300 <= response.status <= 399:
            raise CiscoRestconfProbeError("redirect_response_rejected")
        certificate = (
            connection.sock.getpeercert(binary_form=True)
            if connection.sock is not None
            else None
        )
        body = response.read(MAX_RESTCONF_BODY_BYTES + 1)
        if len(body) > MAX_RESTCONF_BODY_BYTES:
            raise CiscoRestconfProbeError("response_body_too_large")
        if not certificate:
            raise CiscoRestconfProbeError("peer_certificate_unavailable")
        return RestconfHttpEvidence(
            status_code=response.status,
            content_type=response.getheader("Content-Type", ""),
            body=body,
            peer_certificate_sha256=hashlib.sha256(certificate).hexdigest(),
        )
    finally:
        connection.close()


def _base_evidence(source_sha: str, knowledge: CiscoOfflineKnowledge) -> dict:
    return {
        "schema_version": "cisco-c04-live-restconf-evidence/2",
        "source_sha": source_sha,
        "knowledge_digest_sha256": knowledge.digest_sha256,
        "stage": "live_readonly_probe",
        "live_target_observed": False,
        "c04_complete": False,
        "request_method_scope": ["GET"],
        "tls_certificate_verification_required": True,
        "redirect_following_allowed": False,
        "credentials_persisted": False,
        "platform_evidence_bound": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
        "write_operations_performed": False,
    }


def _platform_binding(
    *,
    target_host_sha256: str,
    model: str,
    platform_target_sha256: str,
    platform_evidence_sha256: str,
    iosxe_version: str,
) -> tuple[bool, str, str | None]:
    model = model.strip()
    target_digest = platform_target_sha256.strip().lower()
    evidence_digest = platform_evidence_sha256.strip().lower()
    if not model or not target_digest or not evidence_digest:
        return False, "PLATFORM_EVIDENCE_REQUIRED", None
    if not _valid_sha256(target_digest) or not _valid_sha256(evidence_digest):
        return False, "INVALID_PLATFORM_EVIDENCE_DIGEST", None
    if target_digest != target_host_sha256:
        return False, "PLATFORM_TARGET_BINDING_MISMATCH", None
    decision = assess_read_only_candidate(model, iosxe_version)
    if not decision.read_only_candidate:
        return False, decision.status, decision.family
    return True, decision.status, decision.family


def run_live_probe(
    environ: Mapping[str, str] | None = None,
    request_fn: RequestFn | None = None,
) -> dict:
    env = dict(os.environ if environ is None else environ)
    knowledge = CiscoOfflineKnowledge()
    source_sha = env.get("SOURCE_SHA", "").strip().lower()
    evidence = _base_evidence(source_sha, knowledge)

    if not _SHA40_RE.fullmatch(source_sha):
        evidence["result"] = "source_sha_missing_or_invalid"
        return evidence

    raw_host = env.get("CISCO_RESTCONF_HOST", "").strip()
    username = env.get("CISCO_RESTCONF_USERNAME", "")
    password = env.get("CISCO_RESTCONF_PASSWORD", "")
    missing_count = sum(not value for value in (raw_host, username, password))
    if missing_count:
        evidence["result"] = "credentials_missing"
        evidence["missing_required_value_count"] = missing_count
        return evidence

    try:
        host = _validate_host(raw_host)
        port = _validate_port(env.get("CISCO_RESTCONF_PORT", "443"))
        timeout = _validate_timeout(env.get("CISCO_RESTCONF_TIMEOUT_SECONDS", "10"))
        ssl_context = _build_ssl_context(env.get("CISCO_RESTCONF_CA_PEM_B64"))
        authorization = _authorization_header(username, password)
    except CiscoRestconfProbeError as exc:
        evidence["result"] = str(exc)
        return evidence

    target_host_sha256 = _sha256_text(raw_host)
    evidence["target_host_digest_sha256"] = target_host_sha256
    evidence["target_port"] = port
    base_url = f"https://{_url_authority(host, port)}"
    requester = request_fn or _https_get
    certificate_digests: set[str] = set()

    def execute(
        query_id: str,
        observed: RestconfCapabilityInventory | None = None,
    ) -> RestconfHttpEvidence:
        query = query_definition(query_id, knowledge)
        headers = {
            "Accept": query.accept,
            "Authorization": authorization,
        }
        url = base_url + query.relative_uri
        decision = validate_restconf_request(
            query_id=query_id,
            method="GET",
            url=url,
            headers=headers,
            verify_tls=True,
            allow_redirects=False,
            observed_capabilities=observed,
            knowledge=knowledge,
        )
        if not decision.allowed:
            raise CiscoRestconfProbeError(decision.status.lower())
        response = requester(
            query_id,
            url,
            headers,
            ssl_context,
            host,
            port,
            timeout,
            observed,
        )
        digest = response.peer_certificate_sha256.lower()
        if not _valid_sha256(digest):
            raise CiscoRestconfProbeError("invalid_peer_certificate_digest")
        certificate_digests.add(digest)
        return response

    try:
        root_response = execute("restconf-root-discovery")
        root = parse_restconf_root_discovery(
            status_code=root_response.status_code,
            content_type=root_response.content_type,
            body=root_response.body,
        )

        capability_response = execute("restconf-capabilities")
        capabilities = parse_restconf_capabilities_xml(
            status_code=capability_response.status_code,
            content_type=capability_response.content_type,
            body=capability_response.body,
        )
        if not capabilities.supports_fields:
            raise CiscoRestconfProbeError("required_capability_missing")

        identity_response = execute("native-identity", capabilities)
        identity = parse_native_identity_json(
            status_code=identity_response.status_code,
            content_type=identity_response.content_type,
            body=identity_response.body,
        )
        train = documentation_train(identity.iosxe_version)
        if train is None:
            raise CiscoRestconfProbeError("unverified_iosxe_version")
        if len(certificate_digests) != 1:
            raise CiscoRestconfProbeError("peer_certificate_changed")

        expected_cert = env.get("CISCO_RESTCONF_CERT_SHA256", "").strip().lower()
        peer_cert = next(iter(certificate_digests))
        if expected_cert:
            if not _valid_sha256(expected_cert):
                raise CiscoRestconfProbeError("invalid_expected_certificate_digest")
            if peer_cert != expected_cert:
                raise CiscoRestconfProbeError("peer_certificate_pin_mismatch")
    except Exception as exc:  # noqa: BLE001 - sanitize all untrusted runtime failures
        evidence["live_target_observed"] = True
        evidence["result"] = (
            str(exc)
            if isinstance(exc, CiscoRestconfProbeError)
            else "probe_process_failed"
        )
        evidence["failure_class"] = type(exc).__name__
        return evidence

    evidence.update(
        {
            "result": "live_restconf_verified_platform_binding_required",
            "live_target_observed": True,
            "restconf_root_digest_sha256": root.digest_sha256,
            "capability_inventory_digest_sha256": capabilities.digest_sha256,
            "capability_count": len(capabilities.capabilities),
            "fields_capability_observed": capabilities.supports_fields,
            "identity_digest_sha256": identity.digest_sha256,
            "hostname_digest_sha256": _sha256_text(identity.hostname),
            "iosxe_version": identity.iosxe_version,
            "documentation_train": train,
            "peer_certificate_sha256": peer_cert,
        }
    )

    bound, admission_status, family = _platform_binding(
        target_host_sha256=target_host_sha256,
        model=env.get("CISCO_RESTCONF_PLATFORM_MODEL", ""),
        platform_target_sha256=env.get("CISCO_RESTCONF_PLATFORM_TARGET_SHA256", ""),
        platform_evidence_sha256=env.get("CISCO_RESTCONF_PLATFORM_EVIDENCE_SHA256", ""),
        iosxe_version=identity.iosxe_version,
    )
    evidence["platform_evidence_bound"] = bound
    evidence["platform_admission_status"] = admission_status
    evidence["platform_family"] = family

    model = env.get("CISCO_RESTCONF_PLATFORM_MODEL", "").strip()
    platform_evidence_digest = env.get("CISCO_RESTCONF_PLATFORM_EVIDENCE_SHA256", "").strip().lower()
    if bound:
        evidence["admitted_model"] = model
        evidence["platform_evidence_digest_sha256"] = platform_evidence_digest
        evidence["result"] = "live_readonly_admitted"
        evidence["c04_complete"] = True

    evidence["evidence_digest_sha256"] = _canonical_sha256(
        {key: value for key, value in evidence.items() if key != "evidence_digest_sha256"}
    )
    return evidence


def write_evidence(path: str | Path, evidence: Mapping[str, object]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(dict(evidence), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    evidence = run_live_probe()
    write_evidence(args.output, evidence)
    print(
        json.dumps(
            {
                "stage": evidence["stage"],
                "result": evidence.get("result"),
                "c04_complete": evidence["c04_complete"],
                "source_sha": evidence["source_sha"],
            },
            sort_keys=True,
        )
    )
    return 0 if evidence.get("c04_complete") else 4


if __name__ == "__main__":
    raise SystemExit(main())
