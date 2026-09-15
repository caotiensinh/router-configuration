from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Iterable


class DocumentationAuthority(IntEnum):
    LEGACY = 10
    CURRENT_OFFICIAL = 100


@dataclass(frozen=True)
class MikroTikDocumentationSource:
    name: str
    url: str
    authority: DocumentationAuthority
    machine_readable: bool
    purpose: str
    offline_role: str


MANUAL_ROOT = "https://manual.mikrotik.com/docs/"
LEGACY_HELP_ROOT = "https://help.mikrotik.com/docs/"
LLMS_INDEX = "https://manual.mikrotik.com/llms.txt"
LLMS_FULL = "https://manual.mikrotik.com/llms-full.txt"
SITEMAP = "https://manual.mikrotik.com/sitemap.xml"

_TOPIC_PATHS = {
    "introduction": "introduction/",
    "api": "developer-guides/api/",
    "rest_api": "developer-guides/rest-api/",
    "configuration_management": "getting-started/configuration-management/",
    "backup": "getting-started/configuration-management/backup/",
    "first_time_configuration": "getting-started/first-time-configuration/",
    "security": "getting-started/securing-your-router/",
    "firewall": "firewall-and-quality-of-service/firewall/",
    "connection_tracking": "firewall-and-quality-of-service/connection-tracking/",
    "wireguard": "virtual-private-networks/wireguard/",
    "console": "management-tools/console/",
    "bridge_vlan": "bridging-and-switching/",
    "files": "system-information-and-utilities/files/",
}


def documentation_sources() -> tuple[MikroTikDocumentationSource, ...]:
    """Return sources in authority order; the current manual wins conflicts."""
    return (
        MikroTikDocumentationSource(
            name="routeros-current-manual",
            url=MANUAL_ROOT,
            authority=DocumentationAuthority.CURRENT_OFFICIAL,
            machine_readable=True,
            purpose="Primary source of truth for current RouterOS behavior.",
            offline_role="source-of-truth used to build versioned local snapshots",
        ),
        MikroTikDocumentationSource(
            name="routeros-llms-index",
            url=LLMS_INDEX,
            authority=DocumentationAuthority.CURRENT_OFFICIAL,
            machine_readable=True,
            purpose="Discover current manual pages without crawling HTML navigation.",
            offline_role="page catalog and completeness manifest",
        ),
        MikroTikDocumentationSource(
            name="routeros-llms-full",
            url=LLMS_FULL,
            authority=DocumentationAuthority.CURRENT_OFFICIAL,
            machine_readable=True,
            purpose="Bulk ingestion snapshot for offline indexing and diffing.",
            offline_role="full-text corpus snapshot; runtime never requires Internet",
        ),
        MikroTikDocumentationSource(
            name="routeros-sitemap",
            url=SITEMAP,
            authority=DocumentationAuthority.CURRENT_OFFICIAL,
            machine_readable=True,
            purpose="Completeness check for documentation synchronization.",
            offline_role="snapshot completeness cross-check",
        ),
        MikroTikDocumentationSource(
            name="routeros-legacy-help",
            url=LEGACY_HELP_ROOT,
            authority=DocumentationAuthority.LEGACY,
            machine_readable=False,
            purpose="Historical context only; never override current manual behavior.",
            offline_role="optional historical comparison only",
        ),
    )


def topic_url(topic: str, *, markdown: bool = False) -> str:
    key = topic.strip().lower()
    try:
        path = _TOPIC_PATHS[key]
    except KeyError as exc:
        raise KeyError(f"unknown MikroTik documentation topic: {topic}") from exc
    url = MANUAL_ROOT + path
    if markdown:
        return url.rstrip("/") + ".md"
    return url


def topic_urls(topics: Iterable[str], *, markdown: bool = False) -> tuple[str, ...]:
    return tuple(sorted({topic_url(topic, markdown=markdown) for topic in topics}))


def bundled_data_dir() -> Path:
    """Return the install-local MikroTik knowledge data directory."""
    return Path(__file__).resolve().parent / "data"
