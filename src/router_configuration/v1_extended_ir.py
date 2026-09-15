from __future__ import annotations

from typing import Any, Mapping

from .pbr_intent import normalize_pbr_intent
from .safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetCompiler, SafeSubsetIR
from .vlan_intent import normalize_vlan_intent


class V1ExtendedIRError(ValueError):
    pass


def _intent(profile: Mapping[str, Any]) -> Mapping[str, Any]:
    value = profile.get("intent")
    if not isinstance(value, Mapping):
        raise V1ExtendedIRError("profile intent must be an object")
    return value


def _existing_ids(operations: list[IntentOperation]) -> set[str]:
    ids = [item.operation_id for item in operations]
    if len(ids) != len(set(ids)):
        raise V1ExtendedIRError("base compiler returned duplicate operation IDs")
    return set(ids)


def compile_v1_extended_ir(profile: Mapping[str, Any]) -> SafeSubsetIR:
    """Extend the accepted core compiler with VLAN/PBR vendor-neutral operations.

    The base compiler remains authoritative for existing v0.1 behavior. This
    adapter is additive and generation-only: it adds no RouterOS commands,
    transports, credentials or resolved secrets.
    """

    base = SafeSubsetCompiler().compile(profile)
    operations = list(base.operations)
    seen = _existing_ids(operations)
    intent = _intent(profile)

    segmentation = intent.get("segmentation")
    if segmentation is not None:
        if not isinstance(segmentation, Mapping):
            raise V1ExtendedIRError("intent.segmentation must be an object")
        if segmentation.get("enabled") is True:
            normalized = normalize_vlan_intent(segmentation)
            operation_id = "switching.vlan.segmentation"
            if operation_id in seen:
                raise V1ExtendedIRError(f"duplicate operation ID: {operation_id}")
            operations.append(
                IntentOperation(
                    operation_id=operation_id,
                    feature="vlan",
                    resource="vlan_segmentation_policy",
                    attributes=dict(normalized.attributes),
                    risk=IntentRisk.HIGH,
                    requires=("interfaces", "switching", "ip_addresses", "management_path"),
                )
            )
            seen.add(operation_id)

    pbr = intent.get("pbr")
    if pbr is not None:
        if not isinstance(pbr, Mapping):
            raise V1ExtendedIRError("intent.pbr must be an object")
        if pbr.get("enabled") is True:
            normalized = normalize_pbr_intent(pbr)
            operation_id = "routing.pbr.rules"
            if operation_id in seen:
                raise V1ExtendedIRError(f"duplicate operation ID: {operation_id}")
            operations.append(
                IntentOperation(
                    operation_id=operation_id,
                    feature="pbr",
                    resource="policy_routing_rules",
                    attributes=dict(normalized.attributes),
                    risk=IntentRisk.HIGH,
                    requires=("routing", "firewall", "management_path"),
                )
            )
            seen.add(operation_id)

    operations.sort(key=lambda item: item.operation_id)
    return SafeSubsetIR(device_id=base.device_id, operations=tuple(operations))


class V1ExtendedSafeSubsetCompiler:
    """Class-compatible product adapter for the v1 extended safe-subset compiler."""

    def compile(self, profile: Mapping[str, Any]) -> SafeSubsetIR:
        return compile_v1_extended_ir(profile)
