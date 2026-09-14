from __future__ import annotations

from typing import Iterable

from .catalog_validation import validate_tool_catalog
from .normalized_operation import NormalizedRouterOSOperation
from .tool_registry import MikroTikToolSpec


def generate_tool(operation: NormalizedRouterOSOperation) -> MikroTikToolSpec:
    """Create a typed tool contract from already-normalized authoritative metadata.

    This factory does not parse prose, invent CLI syntax, or execute RouterOS.
    """

    return MikroTikToolSpec(
        name=operation.name,
        routeros_path=operation.routeros_path,
        action=operation.action,
        mode=operation.mode,
        preferred_transport=operation.preferred_transport,
        required_policies=operation.required_policies,
        features=frozenset(operation.features),
        documentation_url=operation.documentation_url,
        management_critical=operation.management_critical,
        continuous=operation.continuous,
    )


def generate_catalog(operations: Iterable[NormalizedRouterOSOperation]) -> tuple[MikroTikToolSpec, ...]:
    tools = tuple(sorted((generate_tool(operation) for operation in operations), key=lambda item: item.name))
    findings = validate_tool_catalog(tools)
    if findings:
        rendered = "; ".join(f"{item.code}:{item.tool_name}" for item in findings)
        raise ValueError("generated tool catalog failed validation: " + rendered)
    return tools
