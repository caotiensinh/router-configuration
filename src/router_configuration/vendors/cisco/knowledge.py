"""Offline Cisco IOS XE source-manifest loader and integrity checks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import resources
import json
from urllib.parse import urlparse


@dataclass(frozen=True)
class CiscoSourceRecord:
    source_id: str
    title: str
    url: str
    authority: str
    scope: str


class CiscoKnowledgeError(ValueError):
    """Raised when bundled Cisco knowledge metadata violates project rules."""


class CiscoOfflineKnowledge:
    def __init__(self) -> None:
        package = resources.files("router_configuration.vendors.cisco.data")
        self._source_manifest = json.loads(
            package.joinpath("official_sources.json").read_text(encoding="utf-8")
        )
        self._platform_matrix = json.loads(
            package.joinpath("platform_matrix.json").read_text(encoding="utf-8")
        )
        self._netconf_readonly_catalog = json.loads(
            package.joinpath("netconf_readonly_catalog.json").read_text(encoding="utf-8")
        )
        self._validate()

    @property
    def source_manifest(self) -> dict:
        return json.loads(json.dumps(self._source_manifest))

    @property
    def platform_matrix(self) -> dict:
        return json.loads(json.dumps(self._platform_matrix))

    @property
    def netconf_readonly_catalog(self) -> dict:
        return json.loads(json.dumps(self._netconf_readonly_catalog))

    @property
    def digest_sha256(self) -> str:
        payload = {
            "source_manifest": self._source_manifest,
            "platform_matrix": self._platform_matrix,
            "netconf_readonly_catalog": self._netconf_readonly_catalog,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def source_ids(self) -> tuple[str, ...]:
        return tuple(source["id"] for source in self._source_manifest["sources"])

    def source(self, source_id: str) -> CiscoSourceRecord:
        for item in self._source_manifest["sources"]:
            if item["id"] == source_id:
                return CiscoSourceRecord(
                    source_id=item["id"],
                    title=item["title"],
                    url=item["url"],
                    authority=item["authority"],
                    scope=item["scope"],
                )
        raise KeyError(source_id)

    def _validate(self) -> None:
        manifest = self._source_manifest
        matrix = self._platform_matrix
        netconf_catalog = self._netconf_readonly_catalog

        if manifest.get("schema_version") != "cisco-official-source-manifest/1":
            raise CiscoKnowledgeError("unsupported Cisco source-manifest schema")
        if manifest.get("vendor") != "Cisco" or manifest.get("os_family") != "IOS XE":
            raise CiscoKnowledgeError("Cisco manifest vendor/OS isolation mismatch")
        if manifest.get("runtime_internet_dependency") is not False:
            raise CiscoKnowledgeError("Cisco knowledge must remain offline-first")

        sources = manifest.get("sources")
        if not isinstance(sources, list) or not sources:
            raise CiscoKnowledgeError("Cisco source manifest must contain sources")

        seen: set[str] = set()
        for source in sources:
            source_id = source.get("id")
            if not isinstance(source_id, str) or not source_id or source_id in seen:
                raise CiscoKnowledgeError("Cisco source IDs must be unique non-empty strings")
            seen.add(source_id)
            if source.get("authority") != "official_cisco":
                raise CiscoKnowledgeError(f"unapproved Cisco source authority: {source_id}")
            url = source.get("url")
            if not isinstance(url, str):
                raise CiscoKnowledgeError(f"missing source URL: {source_id}")
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname not in {"www.cisco.com", "cisco.com"}:
                raise CiscoKnowledgeError(f"non-Cisco authoritative URL: {source_id}")
            forbidden = {"command", "commands", "cli", "payload", "password", "secret"}
            if forbidden.intersection(source):
                raise CiscoKnowledgeError(
                    f"source manifest must not embed executable/sensitive fields: {source_id}"
                )

        if matrix.get("schema_version") != "cisco-iosxe-platform-matrix/1":
            raise CiscoKnowledgeError("unsupported Cisco platform-matrix schema")
        if matrix.get("vendor") != "Cisco" or matrix.get("os_family") != "IOS XE":
            raise CiscoKnowledgeError("Cisco platform matrix vendor/OS isolation mismatch")

        boundaries = matrix.get("boundaries", {})
        required_false = (
            "nx_os_in_scope",
            "ios_xr_in_scope",
            "production_write_authorized",
            "physical_device_verified",
            "automatic_feature_support_inference",
        )
        for key in required_false:
            if boundaries.get(key) is not False:
                raise CiscoKnowledgeError(f"Cisco safety boundary must remain false: {key}")

        for family in matrix.get("families", []):
            if family.get("role") not in {"router", "switch"}:
                raise CiscoKnowledgeError("Cisco family role must be router or switch")
            refs = family.get("documentation_scope", [])
            if not refs or any(ref not in seen for ref in refs):
                raise CiscoKnowledgeError(
                    f"Cisco family references unknown authoritative source: {family.get('family')}"
                )

        if netconf_catalog.get("schema_version") != "cisco-iosxe-netconf-readonly-catalog/1":
            raise CiscoKnowledgeError("unsupported Cisco NETCONF read-only catalog schema")
        if (
            netconf_catalog.get("vendor") != "Cisco"
            or netconf_catalog.get("os_family") != "IOS XE"
        ):
            raise CiscoKnowledgeError("Cisco NETCONF catalog vendor/OS isolation mismatch")
        if netconf_catalog.get("write_authorized") is not False:
            raise CiscoKnowledgeError("Cisco NETCONF catalog must not authorize writes")
        if netconf_catalog.get("physical_device_verified") is not False:
            raise CiscoKnowledgeError(
                "Cisco NETCONF catalog cannot claim physical-device verification"
            )

        catalog_refs = netconf_catalog.get("documentation_source_ids", [])
        if not catalog_refs or any(ref not in seen for ref in catalog_refs):
            raise CiscoKnowledgeError(
                "Cisco NETCONF catalog references unknown authoritative sources"
            )

        allowed = netconf_catalog.get("allowed_rpc_operations", [])
        if not allowed:
            raise CiscoKnowledgeError("Cisco NETCONF catalog must define read-only RPCs")
        for operation in allowed:
            if operation.get("mutation") is not False:
                raise CiscoKnowledgeError(
                    f"Cisco NETCONF RPC must be non-mutating: {operation.get('name')}"
                )
            if operation.get("name") not in {"get", "get-config", "get-schema"}:
                raise CiscoKnowledgeError(
                    f"unapproved Cisco NETCONF read-only RPC: {operation.get('name')}"
                )

        blocked = set(netconf_catalog.get("blocked_rpc_operations", []))
        required_blocked = {
            "edit-config",
            "copy-config",
            "delete-config",
            "commit",
            "discard-changes",
            "lock",
            "unlock",
            "kill-session",
            "action",
        }
        if not required_blocked.issubset(blocked):
            raise CiscoKnowledgeError("Cisco NETCONF catalog is missing blocked write/control RPCs")

        for query in netconf_catalog.get("evidence_queries", []):
            refs = query.get("source_ids", [])
            if not refs or any(ref not in seen for ref in refs):
                raise CiscoKnowledgeError(
                    f"Cisco NETCONF query references unknown source: {query.get('id')}"
                )
            if query.get("secret_safe_scope") is not True:
                raise CiscoKnowledgeError(
                    f"Cisco NETCONF query must be bounded to secret-safe evidence: {query.get('id')}"
                )

        admission = netconf_catalog.get("admission_boundaries", {})
        if admission.get("live_target_required_for_c03_completion") is not True:
            raise CiscoKnowledgeError("C03 completion must require a live IOS XE target")
        if admission.get("synthetic_fixture_can_complete_c03") is not False:
            raise CiscoKnowledgeError("synthetic evidence must not complete C03")
        if admission.get("production_write_authorized") is not False:
            raise CiscoKnowledgeError("C03 catalog must not authorize production writes")
        if admission.get("physical_device_verified") is not False:
            raise CiscoKnowledgeError("C03 catalog must not claim physical hardware")
