"""Cisco IOS XE vendor domain.

The Cisco domain is intentionally isolated from MikroTik and other vendors.
Initial code provides authoritative-source, platform, version, and read-only
admission primitives. It does not authorize Cisco configuration writes.
"""

from .knowledge import CiscoKnowledgeError, CiscoOfflineKnowledge, CiscoSourceRecord
from .netconf_readonly import (
    CISCO_NATIVE_NS,
    NETCONF_BASE_NS,
    NETCONF_MONITORING_NS,
    CiscoNetconfEvidenceError,
    NetconfCapability,
    NetconfHelloEvidence,
    NetconfReadOnlyRpcDecision,
    NetconfSchemaInventory,
    NetconfSchemaRecord,
    parse_iosxe_native_version_reply,
    parse_schema_inventory_reply,
    parse_server_hello,
    validate_read_only_rpc,
)
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
    "CISCO_NATIVE_NS",
    "NETCONF_BASE_NS",
    "NETCONF_MONITORING_NS",
    "CiscoDeviceRole",
    "CiscoKnowledgeError",
    "CiscoNetconfEvidenceError",
    "CiscoOfflineKnowledge",
    "CiscoPlatformDecision",
    "CiscoPlatformFamily",
    "CiscoSourceRecord",
    "NetconfCapability",
    "NetconfHelloEvidence",
    "NetconfReadOnlyRpcDecision",
    "NetconfSchemaInventory",
    "NetconfSchemaRecord",
    "assess_read_only_candidate",
    "classify_platform",
    "documentation_train",
    "normalize_model",
    "parse_iosxe_native_version_reply",
    "parse_schema_inventory_reply",
    "parse_server_hello",
    "platform_families",
    "validate_read_only_rpc",
]
