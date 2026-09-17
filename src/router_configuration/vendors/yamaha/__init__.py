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

__all__ = [
    "YamahaKnowledgeError",
    "YamahaOfflineKnowledge",
    "YamahaPlatformDecision",
    "YamahaSourceRecord",
    "assess_read_only_candidate",
    "normalize_firmware",
    "normalize_model",
]
