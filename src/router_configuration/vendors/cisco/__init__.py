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
from .restconf_readonly import (
    CiscoRestconfEvidenceError,
    RestconfNativeIdentity,
    RestconfQueryDefinition,
    RestconfReadOnlyRequestDecision,
    RestconfRootEvidence,
    parse_native_identity_json,
    parse_restconf_root_discovery,
    parse_yang_json_response,
    query_definition,
    validate_restconf_request,
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
    "CiscoRestconfEvidenceError",
    "CiscoSourceRecord",
    "NetconfCapability",
    "NetconfHelloEvidence",
    "NetconfReadOnlyRpcDecision",
    "NetconfSchemaInventory",
    "NetconfSchemaRecord",
    "RestconfNativeIdentity",
    "RestconfQueryDefinition",
    "RestconfReadOnlyRequestDecision",
    "RestconfRootEvidence",
    "assess_read_only_candidate",
    "classify_platform",
    "documentation_train",
    "normalize_model",
    "parse_iosxe_native_version_reply",
    "parse_native_identity_json",
    "parse_restconf_root_discovery",
    "parse_schema_inventory_reply",
    "parse_server_hello",
    "parse_yang_json_response",
    "platform_families",
    "query_definition",
    "validate_read_only_rpc",
    "validate_restconf_request",
]
