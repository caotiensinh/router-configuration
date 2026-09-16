from router_configuration.m02_state_engine import ChangeOperation, ChangePlan
from router_configuration.ordered_execution import OrderedExecutionError, build_ordered_execution_plan
from router_configuration.types import OperationKind, RiskLevel


def op(path: str, kind: OperationKind, risk: RiskLevel) -> ChangeOperation:
    return ChangeOperation(path=path, kind=kind, before=None, after=True, risk=risk)


def test_dependency_wins_over_risk_and_plan_is_non_executable() -> None:
    plan = ChangePlan(
        plan_id="plan-1",
        operations=(
            op("management.control", OperationKind.UPDATE, RiskLevel.CRITICAL_CHANGE),
            op("service.vlan", OperationKind.CREATE, RiskLevel.BOUNDED_CHANGE),
            op("legacy.rule", OperationKind.DELETE, RiskLevel.NETWORK_CHANGE),
        ),
    )
    ordered = build_ordered_execution_plan(
        plan,
        dependencies={"service.vlan": ("management.control",)},
    )
    assert [step.path for step in ordered.steps] == ["legacy.rule", "management.control", "service.vlan"]
    assert ordered.apply_available is False
    assert ordered.transport_present is False
    assert ordered.write_authorized is False


def test_ready_operations_are_deterministic_and_delete_is_late_on_equal_risk() -> None:
    plan = ChangePlan(
        plan_id="plan-2",
        operations=(
            op("z.delete", OperationKind.DELETE, RiskLevel.NETWORK_CHANGE),
            op("b.update", OperationKind.UPDATE, RiskLevel.NETWORK_CHANGE),
            op("a.create", OperationKind.CREATE, RiskLevel.NETWORK_CHANGE),
        ),
    )
    first = build_ordered_execution_plan(plan)
    second = build_ordered_execution_plan(plan)
    assert [step.path for step in first.steps] == ["a.create", "b.update", "z.delete"]
    assert first.ordering_sha256 == second.ordering_sha256


def test_unknown_dependency_and_cycle_fail_closed() -> None:
    plan = ChangePlan(
        plan_id="plan-3",
        operations=(
            op("a", OperationKind.UPDATE, RiskLevel.BOUNDED_CHANGE),
            op("b", OperationKind.UPDATE, RiskLevel.BOUNDED_CHANGE),
        ),
    )
    try:
        build_ordered_execution_plan(plan, dependencies={"a": ("missing",)})
    except OrderedExecutionError as exc:
        assert "unknown operation" in str(exc)
    else:
        raise AssertionError("unknown dependency must fail")

    try:
        build_ordered_execution_plan(plan, dependencies={"a": ("b",), "b": ("a",)})
    except OrderedExecutionError as exc:
        assert "cycle" in str(exc)
    else:
        raise AssertionError("dependency cycle must fail")
