"""Cisco IOS XE vendor domain.

The Cisco domain is intentionally isolated from MikroTik and other vendors.
Initial code provides only authoritative-source, platform, version, and
read-only admission primitives. It does not authorize Cisco configuration
writes.
"""

from .knowledge import CiscoKnowledgeError, CiscoOfflineKnowledge, CiscoSourceRecord
from .platforms import (
    CiscoDeviceRole,
    CiscoPlatformDecision,
    CiscoPlatformFamily,
    assess_read_only_candidate,
    classify_platform,
    documentation_train,
    normalize_model,
    platform_families,
)

__all__ = [
    "CiscoDeviceRole",
    "CiscoKnowledgeError",
    "CiscoOfflineKnowledge",
    "CiscoPlatformDecision",
    "CiscoPlatformFamily",
    "CiscoSourceRecord",
    "assess_read_only_candidate",
    "classify_platform",
    "documentation_train",
    "normalize_model",
    "platform_families",
]
