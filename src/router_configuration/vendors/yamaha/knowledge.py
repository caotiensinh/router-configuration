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
        self._validate()

    @property
    def source_manifest(self) -> dict:
        return json.loads(json.dumps(self._source_manifest))

    @property
    def platform_matrix(self) -> dict:
        return json.loads(json.dumps(self._platform_matrix))

    @property
    def digest_sha256(self) -> str:
        payload = {
            "source_manifest": self._source_manifest,
            "platform_matrix": self._platform_matrix,
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
