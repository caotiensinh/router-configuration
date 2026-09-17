"""Yamaha RTX3510 vendor domain.

The Yamaha domain is isolated from other vendors and starts with exact
model/firmware, authoritative-source, read-only admission, and conservative
state-normalization primitives. It does not authorize configuration writes.
"""

from .knowledge import YamahaKnowledgeError, YamahaOfflineKnowledge, YamahaSourceRecord
from .normalized import (
    YAMAHA_NORMALIZED_STATE_SCHEMA,
    YamahaIPv4Route,
    YamahaNormalizedStateError,
    build_normalized_state,
    parse_ipv4_routes,
    validate_normalized_state,
)
from .platforms import (
    YamahaPlatformDecision,
    assess_read_only_candidate,
    normalize_firmware,
    normalize_model,
)
from .readonly import (
    YamahaEnvironmentIdentity,
    YamahaReadOnlyCommandDecision,
    YamahaReadOnlyEvidenceError,
    build_readonly_evidence,
    normalize_read_only_command,
    parse_environment_identity,
    validate_read_only_command,
    validate_readonly_evidence,
)

__all__ = [
    "YAMAHA_NORMALIZED_STATE_SCHEMA",
    "YamahaEnvironmentIdentity",
    "YamahaIPv4Route",
    "YamahaKnowledgeError",
    "YamahaNormalizedStateError",
    "YamahaOfflineKnowledge",
    "YamahaPlatformDecision",
    "YamahaReadOnlyCommandDecision",
    "YamahaReadOnlyEvidenceError",
    "YamahaSourceRecord",
    "assess_read_only_candidate",
    "build_normalized_state",
    "build_readonly_evidence",
    "normalize_firmware",
    "normalize_model",
    "normalize_read_only_command",
    "parse_environment_identity",
    "parse_ipv4_routes",
    "validate_normalized_state",
    "validate_read_only_command",
    "validate_readonly_evidence",
]
