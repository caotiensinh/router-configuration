"""Yamaha RTX3510 vendor domain.

The Yamaha domain is isolated from other vendors and starts with exact
model/firmware, authoritative-source, and read-only admission primitives.
It does not authorize configuration writes.
"""

from .knowledge import YamahaKnowledgeError, YamahaOfflineKnowledge, YamahaSourceRecord
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
    "YamahaEnvironmentIdentity",
    "YamahaKnowledgeError",
    "YamahaOfflineKnowledge",
    "YamahaPlatformDecision",
    "YamahaReadOnlyCommandDecision",
    "YamahaReadOnlyEvidenceError",
    "YamahaSourceRecord",
    "assess_read_only_candidate",
    "build_readonly_evidence",
    "normalize_firmware",
    "normalize_model",
    "normalize_read_only_command",
    "parse_environment_identity",
    "validate_read_only_command",
    "validate_readonly_evidence",
]
