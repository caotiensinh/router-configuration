from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from router_configuration.adapters.base import AdapterPreflight
from router_configuration.m02_state_engine import ChangePlan
from router_configuration.types import Vendor


class OmadaApiSurface(str, Enum):
    OFFICIAL = "official"
    EXPERIMENTAL = "experimental"


@dataclass(frozen=True)
class OmadaCompatibility:
    controller_version: str
    official_features: frozenset[str]


class OmadaAdapter:
    """Omada adapter policy with explicit official/experimental separation."""

    vendor = Vendor.OMADA

    def __init__(
        self,
        compatibility: OmadaCompatibility,
        *,
        surface: OmadaApiSurface = OmadaApiSurface.OFFICIAL,
        production: bool = True,
    ) -> None:
        if production and surface is OmadaApiSurface.EXPERIMENTAL:
            raise ValueError("experimental Omada API surface is disabled in production")
        self.compatibility = compatibility
        self.surface = surface
        self.production = production

    def preflight(self, plan: ChangePlan) -> AdapterPreflight:
        missing: set[str] = set()
        for operation in plan.operations:
            root = operation.path.split(".", 1)[0].lower()
            if root and root not in self.compatibility.official_features:
                missing.add(root)

        reasons = tuple(
            f"controller capability map does not declare feature: {name}"
            for name in sorted(missing)
        )
        return AdapterPreflight(ready=not reasons, reasons=reasons)

    def render_dry_run(self, plan: ChangePlan) -> tuple[str, ...]:
        return tuple(
            f"OMADA-{self.surface.value.upper()} {operation.kind.value} {operation.path}"
            for operation in plan.operations
        )
