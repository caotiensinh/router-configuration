from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .m04_multiwan import MultiWanPlanner, PccBucket, WeightedWanPolicy


@dataclass(frozen=True)
class RouterOSPccRenderSpec:
    buckets: tuple[PccBucket, ...]
    routing_tables: tuple[tuple[str, str], ...]
    classifier: str
    ingress_interface_list: str
    scope: str
    exclude_local_destinations: bool
    connection_state: str
    require_unmarked_connection: bool
    fasttrack_compatible: bool

    def table_for(self, wan_name: str) -> str:
        for name, table in self.routing_tables:
            if name == wan_name:
                return table
        raise KeyError(wan_name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-pcc-render-spec/1",
            "classifier": self.classifier,
            "ingress_interface_list": self.ingress_interface_list,
            "scope": self.scope,
            "exclude_local_destinations": self.exclude_local_destinations,
            "connection_state": self.connection_state,
            "require_unmarked_connection": self.require_unmarked_connection,
            "fasttrack_compatible": self.fasttrack_compatible,
            "routing_tables": dict(self.routing_tables),
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


def _active_dstnat_rules(state: Mapping[str, Any]) -> tuple[str, ...]:
    firewall = state.get("firewall", {})
    if not isinstance(firewall, Mapping):
        return ()
    rows = firewall.get("nat", [])
    if not isinstance(rows, list):
        return ()

    found: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        if str(row.get("chain") or "").strip().lower() != "dstnat":
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

    v0.1 is intentionally outbound-core-only. It classifies only new,
    previously unmarked connections arriving from the core side, excludes
    router-local destinations, and refuses active FastTrack or dstnat because
    those require explicit compatibility/session-symmetry policy before a safe
    production renderer may be generated.
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

    paths = attributes.get("paths")
    routing_tables: list[tuple[str, str]] = []
    if not isinstance(paths, Mapping) or set(paths) != {name for name, _ in policy.weights}:
        errors.append("PCC planning requires an explicit path and dedicated routing table for every weighted WAN")
    else:
        seen_tables: set[str] = set()
        for wan_name, _ in policy.weights:
            path = paths.get(wan_name)
            if not isinstance(path, Mapping):
                errors.append(f"PCC path for WAN {wan_name!r} must be an object")
                continue
            table = str(path.get("table") or "").strip()
            if not table or table == "main":
                errors.append(f"PCC WAN {wan_name!r} requires a dedicated non-main routing table")
                continue
            if table in seen_tables:
                errors.append(f"PCC routing table {table!r} is assigned to multiple WANs")
                continue
            seen_tables.add(table)
            routing_tables.append((wan_name, table))

    fasttrack = _active_fasttrack_rules(state)
    if fasttrack:
        errors.append(
            "active FastTrack rules conflict with non-main PCC routing marks; explicit FastTrack exclusion/removal policy is required before rendering: "
            + ", ".join(fasttrack)
        )

    dstnat = _active_dstnat_rules(state)
    if dstnat:
        errors.append(
            "active dstnat rules require explicit inbound connection symmetry before outbound-only PCC rendering: "
            + ", ".join(dstnat)
        )

    if not core_interface_list.strip():
        errors.append("PCC ingress interface list must not be empty")

    if errors:
        return RouterOSPccAssessment(tuple(sorted(set(errors))), tuple(sorted(set(warnings))))

    spec = RouterOSPccRenderSpec(
        buckets=buckets,
        routing_tables=tuple(routing_tables),
        classifier="both-addresses-and-ports",
        ingress_interface_list=core_interface_list,
        scope="outbound_core_only",
        exclude_local_destinations=True,
        connection_state="new",
        require_unmarked_connection=True,
        fasttrack_compatible=False,
    )
    return RouterOSPccAssessment((), tuple(sorted(set(warnings))), spec)
