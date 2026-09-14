from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
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
    "security": "getting-started/securing-your-router/",
    "firewall": "firewall-and-quality-of-service/firewall/",
    "wireguard": "virtual-private-networks/wireguard/",
    "console": "management-tools/console/",
}


def documentation_sources() -> tuple[MikroTikDocumentationSource, ...]:
    """Return sources in authority order; current manual always wins conflicts."""
    return (
        MikroTikDocumentationSource(
            name="routeros-current-manual",
            url=MANUAL_ROOT,
            authority=DocumentationAuthority.CURRENT_OFFICIAL,
            machine_readable=True,
            purpose="Primary source of truth for current RouterOS behavior.",
        ),
        MikroTikDocumentationSource(
            name="routeros-llms-index",
            url=LLMS_INDEX,
            authority=DocumentationAuthority.CURRENT_OFFICIAL,
            machine_readable=True,
            purpose="Discover current manual pages without crawling HTML navigation.",
        ),
        MikroTikDocumentationSource(
            name="routeros-llms-full",
            url=LLMS_FULL,
            authority=DocumentationAuthority.CURRENT_OFFICIAL,
            machine_readable=True,
            purpose="Bulk ingestion snapshot for offline indexing and diffing.",
        ),
        MikroTikDocumentationSource(
            name="routeros-sitemap",
            url=SITEMAP,
            authority=DocumentationAuthority.CURRENT_OFFICIAL,
            machine_readable=True,
            purpose="Completeness check for documentation synchronization.",
        ),
        MikroTikDocumentationSource(
            name="routeros-legacy-help",
            url=LEGACY_HELP_ROOT,
            authority=DocumentationAuthority.LEGACY,
            machine_readable=False,
            purpose="Historical context only; never override current manual behavior.",
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
