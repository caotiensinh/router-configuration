"""Backward-compatible imports for the MikroTik vendor domain.

New MikroTik documentation/knowledge code belongs under
``router_configuration.vendors.mikrotik``. This module remains only so existing
callers do not break while the repository migrates vendor code into isolated
namespaces.
"""

from .vendors.mikrotik.docs import (
    DocumentationAuthority,
    LEGACY_HELP_ROOT,
    LLMS_FULL,
    LLMS_INDEX,
    MANUAL_ROOT,
    SITEMAP,
    MikroTikDocumentationSource,
    bundled_data_dir,
    documentation_sources,
    topic_url,
    topic_urls,
)

__all__ = [
    "DocumentationAuthority",
    "LEGACY_HELP_ROOT",
    "LLMS_FULL",
    "LLMS_INDEX",
    "MANUAL_ROOT",
    "SITEMAP",
    "MikroTikDocumentationSource",
    "bundled_data_dir",
    "documentation_sources",
    "topic_url",
    "topic_urls",
]
