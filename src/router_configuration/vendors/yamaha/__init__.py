"""Yamaha RTX3510 vendor domain.

The Yamaha domain is isolated from other vendors and starts with exact
model/firmware, authoritative-source, read-only admission, conservative state
normalization, and bounded dry-run rendering. It does not authorize writes.
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
from .renderer import (
    YAMAHA_RENDER_PLAN_SCHEMA,
    YamahaRenderError,
    YamahaStaticRouteIntent,
    render_candidate_plan,
    validate_candidate_plan,
)

__all__ = [
    "YAMAHA_NORMALIZED_STATE_SCHEMA",
    "YAMAHA_RENDER_PLAN_SCHEMA",
    "YamahaEnvironmentIdentity",
    "YamahaIPv4Route",
    "YamahaKnowledgeError",
    "YamahaNormalizedStateError",
    "YamahaOfflineKnowledge",
    "YamahaPlatformDecision",
    "YamahaReadOnlyCommandDecision",
    "YamahaReadOnlyEvidenceError",
    "YamahaRenderError",
    "YamahaSourceRecord",
    "YamahaStaticRouteIntent",
    "assess_read_only_candidate",
    "build_normalized_state",
    "build_readonly_evidence",
    "normalize_firmware",
    "normalize_model",
    "normalize_read_only_command",
    "parse_environment_identity",
    "parse_ipv4_routes",
    "render_candidate_plan",
    "validate_candidate_plan",
    "validate_normalized_state",
    "validate_read_only_command",
    "validate_readonly_evidence",
]
