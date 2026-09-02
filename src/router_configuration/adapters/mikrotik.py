from __future__ import annotations

from router_configuration.adapters.base import AdapterPreflight
from router_configuration.m02_state_engine import ChangePlan
from router_configuration.types import Vendor


class MikroTikReferenceAdapter:
    """Reference adapter boundary.

    This early adapter intentionally renders neutral operations only. It does not
    connect to RouterOS and does not emit executable RouterOS commands yet.
    """

    vendor = Vendor.MIKROTIK

    def preflight(self, plan: ChangePlan) -> AdapterPreflight:
        return AdapterPreflight(ready=True)

    def render_dry_run(self, plan: ChangePlan) -> tuple[str, ...]:
        return tuple(
            f"{operation.kind.value.upper()} {operation.path} risk={int(operation.risk)}"
            for operation in plan.operations
        )
