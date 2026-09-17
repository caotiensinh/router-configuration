"""Offline Yamaha RTX3510 authoritative-source metadata and validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import resources
import json
from urllib.parse import urlparse


_ALLOWED_HOSTS = frozenset({
    "network.yamaha.com",
    "rtpro.yamaha.co.jp",
    "www.rtpro.yamaha.co.jp",
})
_FORBIDDEN_SOURCE_FIELDS = frozenset({
    "command",
    "commands",
    "cli",
    "payload",
    "password",
    "secret",
    "private_key",
    "private-key",
    "token",
})
_EXPECTED_READONLY_COMMANDS = frozenset(
    {
        "show environment",
        "show arp",
        "show ip route",
        "show ip route detail",
        "show status lan1",
        "show status lan2",
        "show status lan3",
        "show status lan4",
    }
)
_BLOCKED_SENSITIVE_READS = frozenset({"show config", "show log", "show techinfo"})


@dataclass(frozen=True)
class YamahaSourceRecord:
    source_id: str
    title: str
    url: str
    authority: str
    scope: str


class YamahaKnowledgeError(ValueError):
    """Raised when bundled Yamaha knowledge metadata violates project rules."""


class YamahaOfflineKnowledge:
    def __init__(self) -> None:
        package = resources.files("router_configuration.vendors.yamaha.data")
        self._source_manifest = json.loads(
            package.joinpath("official_sources.json").read_text(encoding="utf-8")
        )
        self._platform_matrix = json.loads(
            package.joinpath("platform_matrix.json").read_text(encoding="utf-8")
        )
        self._readonly_catalog = json.loads(
            package.joinpath("readonly_catalog.json").read_text(encoding="utf-8")
        )
        self._validate()

    @property
    def source_manifest(self) -> dict:
        return json.loads(json.dumps(self._source_manifest))

    @property
    def platform_matrix(self) -> dict:
        return json.loads(json.dumps(self._platform_matrix))

    @property
    def readonly_catalog(self) -> dict:
        return json.loads(json.dumps(self._readonly_catalog))

    @property
    def digest_sha256(self) -> str:
        payload = {
            "source_manifest": self._source_manifest,
            "platform_matrix": self._platform_matrix,
            "readonly_catalog": self._readonly_catalog,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def source_ids(self) -> tuple[str, ...]:
        return tuple(item["id"] for item in self._source_manifest["sources"])

    def source(self, source_id: str) -> YamahaSourceRecord:
        for item in self._source_manifest["sources"]:
            if item["id"] == source_id:
                return YamahaSourceRecord(
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

        if manifest.get("schema_version") != "yamaha-official-source-manifest/1":
            raise YamahaKnowledgeError("unsupported Yamaha source-manifest schema")
        if manifest.get("vendor") != "Yamaha" or manifest.get("product_family") != "RTX":
            raise YamahaKnowledgeError("Yamaha manifest vendor/product-family mismatch")
        if manifest.get("runtime_internet_dependency") is not False:
            raise YamahaKnowledgeError("Yamaha knowledge must remain offline-first")

        sources = manifest.get("sources")
        if not isinstance(sources, list) or not sources:
            raise YamahaKnowledgeError("Yamaha source manifest must contain sources")

        seen: set[str] = set()
        for item in sources:
            if not isinstance(item, dict):
                raise YamahaKnowledgeError("Yamaha source entries must be objects")
            source_id = item.get("id")
            if not isinstance(source_id, str) or not source_id or source_id in seen:
                raise YamahaKnowledgeError("Yamaha source IDs must be unique non-empty strings")
            seen.add(source_id)
            if item.get("authority") != "official_yamaha":
                raise YamahaKnowledgeError(f"unapproved Yamaha source authority: {source_id}")
            url = item.get("url")
            if not isinstance(url, str):
                raise YamahaKnowledgeError(f"missing source URL: {source_id}")
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
                raise YamahaKnowledgeError(f"non-Yamaha authoritative URL: {source_id}")
            if _FORBIDDEN_SOURCE_FIELDS.intersection(item):
                raise YamahaKnowledgeError(
                    f"source manifest must not embed executable/sensitive fields: {source_id}"
                )
            for required in ("title", "scope"):
                if not isinstance(item.get(required), str) or not item[required].strip():
                    raise YamahaKnowledgeError(
                        f"missing Yamaha source metadata {required}: {source_id}"
                    )

        if matrix.get("schema_version") != "yamaha-rtx-platform-matrix/1":
            raise YamahaKnowledgeError("unsupported Yamaha platform-matrix schema")
        if matrix.get("vendor") != "Yamaha" or matrix.get("product_family") != "RTX":
            raise YamahaKnowledgeError("Yamaha platform matrix vendor/product-family mismatch")
        if matrix.get("admission_mode") != "documentation_scoped_read_only_first":
            raise YamahaKnowledgeError("Yamaha baseline must remain read-only-first")

        models = matrix.get("models")
        if not isinstance(models, list) or len(models) != 1:
            raise YamahaKnowledgeError("Yamaha baseline must contain exactly one admitted model")
        model = models[0]
        if model.get("model") != "RTX3510" or model.get("role") != "router":
            raise YamahaKnowledgeError("Yamaha baseline model must be RTX3510 router")
        if model.get("admitted_firmware") != ["23.01.03"]:
            raise YamahaKnowledgeError("Yamaha baseline firmware must be exactly 23.01.03")
        refs = model.get("documentation_scope")
        if not isinstance(refs, list) or not refs or any(ref not in seen for ref in refs):
            raise YamahaKnowledgeError("Yamaha platform matrix references unknown source")

        boundaries = matrix.get("boundaries", {})
        for key in (
            "other_rtx_models_in_scope",
            "production_write_authorized",
            "physical_device_verified",
            "automatic_feature_support_inference",
        ):
            if boundaries.get(key) is not False:
                raise YamahaKnowledgeError(f"Yamaha safety boundary must remain false: {key}")

        self._validate_readonly_catalog(seen)

    def _validate_readonly_catalog(self, source_ids: set[str]) -> None:
        catalog = self._readonly_catalog
        if catalog.get("schema_version") != "yamaha-rtx3510-readonly-catalog/1":
            raise YamahaKnowledgeError("unsupported Yamaha read-only catalog schema")
        if catalog.get("vendor") != "Yamaha" or catalog.get("model") != "RTX3510":
            raise YamahaKnowledgeError("Yamaha read-only catalog identity mismatch")
        if catalog.get("firmware") != "23.01.03":
            raise YamahaKnowledgeError("Yamaha read-only catalog firmware mismatch")
        if catalog.get("write_authorized") is not False:
            raise YamahaKnowledgeError("Yamaha read-only catalog must not authorize writes")
        if catalog.get("physical_device_verified") is not False:
            raise YamahaKnowledgeError("Yamaha read-only catalog cannot claim physical hardware")

        queries = catalog.get("queries")
        if not isinstance(queries, list) or not queries:
            raise YamahaKnowledgeError("Yamaha read-only catalog must contain queries")
        observed_commands: set[str] = set()
        query_ids: set[str] = set()
        for query in queries:
            if not isinstance(query, dict):
                raise YamahaKnowledgeError("Yamaha read-only queries must be objects")
            query_id = query.get("id")
            command = query.get("command")
            if not isinstance(query_id, str) or not query_id or query_id in query_ids:
                raise YamahaKnowledgeError("Yamaha read-only query IDs must be unique")
            query_ids.add(query_id)
            if not isinstance(command, str) or not command.startswith("show "):
                raise YamahaKnowledgeError(f"Yamaha query is not a show command: {query_id}")
            if any(token in command for token in ("\n", "\r", "|", ";")):
                raise YamahaKnowledgeError(f"unsafe Yamaha read-only command syntax: {query_id}")
            if command in observed_commands:
                raise YamahaKnowledgeError(f"duplicate Yamaha read-only command: {command}")
            observed_commands.add(command)
            if command in _BLOCKED_SENSITIVE_READS:
                raise YamahaKnowledgeError(f"sensitive Yamaha read is not baseline-safe: {command}")
            refs = query.get("source_ids")
            if not isinstance(refs, list) or not refs or any(ref not in source_ids for ref in refs):
                raise YamahaKnowledgeError(f"Yamaha query references unknown source: {query_id}")
            if query.get("secret_safe_scope") is not True:
                raise YamahaKnowledgeError(f"Yamaha query must be secret-safe: {query_id}")
            if not isinstance(query.get("response_kind"), str) or not query["response_kind"]:
                raise YamahaKnowledgeError(f"Yamaha query response kind is missing: {query_id}")

        if observed_commands != _EXPECTED_READONLY_COMMANDS:
            raise YamahaKnowledgeError("Yamaha read-only catalog command set changed unexpectedly")
        if set(catalog.get("blocked_sensitive_read_examples", [])) != _BLOCKED_SENSITIVE_READS:
            raise YamahaKnowledgeError("Yamaha sensitive-read blocklist changed unexpectedly")

        boundaries = catalog.get("admission_boundaries", {})
        for key in (
            "unlisted_commands_allowed",
            "pipelines_allowed",
            "synthetic_fixture_can_claim_physical_device",
            "production_write_authorized",
            "physical_device_verified",
        ):
            if boundaries.get(key) is not False:
                raise YamahaKnowledgeError(f"Yamaha read-only boundary must remain false: {key}")
