from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .m04_multiwan import MultiWanPlanner, PccBucket, WeightedWanPolicy


@dataclass(frozen=True)
class RouterOSPccRenderSpec:
    buckets: tuple[PccBucket, ...]
    classifier: str
    ingress_interface_list: str
    exclude_local_destinations: bool
    connection_state: str
    require_unmarked_connection: bool
    fasttrack_compatible: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-pcc-render-spec/1",
            "classifier": self.classifier,
            "ingress_interface_list": self.ingress_interface_list,
            "exclude_local_destinations": self.exclude_local_destinations,
            "connection_state": self.connection_state,
            "require_unmarked_connection": self.require_unmarked_connection,
            "fasttrack_compatible": self.fasttrack_compatible,
            "buckets": [
                {
                    "wan_name": bucket.wan_name,
                    "denominator": bucket.denominator,
                    "remainder": bucket.remainder,
                    "classifier": bucket.classifier,
                }
                for bucket in self.buckets
            ],
            "write_authorized": False,
        }


@dataclass(frozen=True)
class RouterOSPccAssessment:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    spec: RouterOSPccRenderSpec | None = None

    @property
    def ok(self) -> bool:
        return not self.errors and self.spec is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "spec": self.spec.as_dict() if self.spec is not None else None,
            "write_authorized": False,
        }


def _enabled(value: Any) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes"}


def _active_fasttrack_rules(state: Mapping[str, Any]) -> tuple[str, ...]:
    firewall = state.get("firewall", {})
    if not isinstance(firewall, Mapping):
        return ()
    rows = firewall.get("filter", [])
    if not isinstance(rows, list):
        return ()

    found: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        if str(row.get("action") or "").strip().lower() != "fasttrack-connection":
            continue
        if _enabled(row.get("disabled")):
            continue
        identifier = str(row.get(".id") or row.get("comment") or f"index:{index}")
        found.append(identifier)
    return tuple(sorted(found))


def assess_routeros_pcc(
    *,
    ir: Mapping[str, Any],
    state: Mapping[str, Any],
    core_interface_list: str = "routercfg-CORE",
    max_buckets: int = 64,
) -> RouterOSPccAssessment:
    """Build a non-executable PCC specification after fail-safe checks.

    This function deliberately produces no RouterOS commands. It freezes the
    invariants the eventual mangle renderer must honor: classify only new,
    previously unmarked connections arriving from the trusted/core side, never
    classify router-local destinations, and refuse an active FastTrack policy
    until an explicit compatibility design exists for marked flows.
    """

    errors: list[str] = []
    warnings: list[str] = []

    if ir.get("schema_version") != "config-safe-subset-ir/1":
        errors.append("unsupported or missing safe-subset IR schema")
        return RouterOSPccAssessment(tuple(errors), tuple(warnings))
    if ir.get("vendor_commands_present") is not False:
        errors.append("PCC planning requires command-free safe-subset IR")
    if ir.get("write_transport_present") is not False:
        errors.append("PCC planning refuses IR containing a write transport")

    candidates: list[Mapping[str, Any]] = []
    operations = ir.get("operations", [])
    if isinstance(operations, list):
        for operation in operations:
            if not isinstance(operation, Mapping):
                continue
            if str(operation.get("resource") or "") == "path_distribution_policy":
                candidates.append(operation)
    if len(candidates) != 1:
        errors.append("PCC planning requires exactly one path_distribution_policy operation")
        return RouterOSPccAssessment(tuple(sorted(set(errors))), tuple(warnings))

    attributes = candidates[0].get("attributes", {})
    if not isinstance(attributes, Mapping):
        errors.append("path_distribution_policy attributes must be an object")
        return RouterOSPccAssessment(tuple(errors), tuple(warnings))
    if str(attributes.get("mode") or "") != "capacity_weighted":
        errors.append("RouterOS PCC planning supports only capacity_weighted mode")

    weights = attributes.get("weights")
    if not isinstance(weights, Mapping) or len(weights) < 2:
        errors.append("capacity-weighted PCC requires at least two WAN weights")
        return RouterOSPccAssessment(tuple(sorted(set(errors))), tuple(warnings))

    try:
        policy = WeightedWanPolicy(
            tuple(sorted((str(name), int(weight)) for name, weight in weights.items()))
        )
        buckets = MultiWanPlanner().build_pcc_buckets(
            policy,
            max_buckets=max_buckets,
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"PCC weight plan: {exc}")
        return RouterOSPccAssessment(tuple(sorted(set(errors))), tuple(warnings))

    fasttrack = _active_fasttrack_rules(state)
    if fasttrack:
        errors.append(
            "active FastTrack rules conflict with non-main PCC routing marks; explicit FastTrack exclusion/removal policy is required before rendering: "
            + ", ".join(fasttrack)
        )

    if not core_interface_list.strip():
        errors.append("PCC ingress interface list must not be empty")

    if errors:
        return RouterOSPccAssessment(tuple(sorted(set(errors))), tuple(sorted(set(warnings))))

    spec = RouterOSPccRenderSpec(
        buckets=buckets,
        classifier="both-addresses-and-ports",
        ingress_interface_list=core_interface_list,
        exclude_local_destinations=True,
        connection_state="new",
        require_unmarked_connection=True,
        fasttrack_compatible=False,
    )
    return RouterOSPccAssessment((), tuple(sorted(set(warnings))), spec)
