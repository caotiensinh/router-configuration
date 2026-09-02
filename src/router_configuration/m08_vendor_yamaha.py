from __future__ import annotations

from dataclasses import dataclass

from router_configuration.adapters.base import AdapterPreflight
from router_configuration.m02_state_engine import ChangePlan
from router_configuration.types import Vendor


@dataclass(frozen=True)
class YamahaAdapterCapabilities:
    ssh_cli: bool = True
    config_backup: bool = True
    lua: bool = True
    policy_routing: bool = True
    wireguard: bool = False


class YamahaAdapter:
    """Dry-run-first Yamaha RTX adapter boundary.

    Vendor command generation and SSH transport are intentionally not enabled in
    the foundation phase. This prevents an untested command renderer from being
    mistaken for a production writer.
    """

    vendor = Vendor.YAMAHA

    def __init__(self, capabilities: YamahaAdapterCapabilities | None = None) -> None:
        self.capabilities = capabilities or YamahaAdapterCapabilities()

    def preflight(self, plan: ChangePlan) -> AdapterPreflight:
        reasons: list[str] = []
        for operation in plan.operations:
            if "wireguard" in operation.path.lower() and not self.capabilities.wireguard:
                reasons.append("Yamaha target capability map does not include WireGuard")
        return AdapterPreflight(ready=not reasons, reasons=tuple(reasons))

    def render_dry_run(self, plan: ChangePlan) -> tuple[str, ...]:
        return tuple(
            f"YAMAHA-INTENT {operation.kind.value} {operation.path}"
            for operation in plan.operations
        )
