from __future__ import annotations

from dataclasses import dataclass
import re

from .approval_binding import routeros_base_version


_NUMERIC_VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


def _numeric(value: str) -> tuple[int, int, int]:
    base = routeros_base_version(value)
    match = _NUMERIC_VERSION.match(base)
    if not match:
        raise ValueError(f"RouterOS version is not numerically comparable: {value!r}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


@dataclass(frozen=True)
class VersionConstraint:
    knowledge_id: str
    source_url: str
    minimum: str | None = None
    maximum: str | None = None

    def supports(self, observed_version: str) -> bool:
        observed = _numeric(observed_version)
        if self.minimum is not None and observed < _numeric(self.minimum):
            return False
        if self.maximum is not None and observed > _numeric(self.maximum):
            return False
        return True


def require_supported_version(observed_version: str, constraint: VersionConstraint) -> None:
    if not constraint.knowledge_id.strip() or not constraint.source_url.startswith("https://"):
        raise ValueError("version constraint requires authoritative knowledge provenance")
    if not constraint.supports(observed_version):
        raise ValueError("UNSUPPORTED_FOR_VERSION")
