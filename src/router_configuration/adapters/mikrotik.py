from __future__ import annotations

from typing import Any, Mapping

from router_configuration.adapters.base import AdapterPreflight
from router_configuration.m02_state_engine import ChangePlan
from router_configuration.mikrotik_intent import (
    MikroTikIntentPlan,
    compile_mikrotik_operator_intent,
)
from router_configuration.mikrotik_tool_registry import (
    MikroTikToolSpec,
    mikrotik_tool_catalog,
    tools_for_intent,
)
from router_configuration.types import Vendor


class MikroTikReferenceAdapter:
    """Reference adapter boundary for MikroTik RouterOS.

    The adapter exposes documentation-grounded operator-intent compilation and
    an intent-scoped micro-tool catalog. It still does not open a write
    transport. Existing RouterOS renderers, safety admission and transaction
    lifecycle remain the only path toward future execution.
    """

    vendor = Vendor.MIKROTIK

    def preflight(self, plan: ChangePlan) -> AdapterPreflight:
        return AdapterPreflight(ready=True)

    def render_dry_run(self, plan: ChangePlan) -> tuple[str, ...]:
        return tuple(
            f"{operation.kind.value.upper()} {operation.path} risk={int(operation.risk)}"
            for operation in plan.operations
        )

    def compile_operator_intent(self, request: Mapping[str, Any]) -> MikroTikIntentPlan:
        return compile_mikrotik_operator_intent(request)

    def tool_catalog(self) -> tuple[MikroTikToolSpec, ...]:
        return mikrotik_tool_catalog()

    def tools_for_intent(
        self,
        intent_kind: str,
        *,
        include_writes: bool = False,
        include_capture: bool = False,
    ) -> tuple[MikroTikToolSpec, ...]:
        """Select only tools relevant to the requested outcome.

        ``include_writes`` exposes write-tool metadata for planning/review only;
        it does not authorize or execute configuration changes.
        """
        return tools_for_intent(
            intent_kind,
            include_writes=include_writes,
            include_capture=include_capture,
        )
