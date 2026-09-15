from router_configuration.m02_state_engine import StateEngine
from router_configuration.types import OperationKind, RiskLevel


def test_desired_state_diff_is_deterministic_and_explicit() -> None:
    desired = {
        "vlans": {"10": {"name": "users"}, "20": {"name": "voice"}},
        "dns": ["1.1.1.1", "8.8.8.8"],
    }
    actual = {
        "vlans": {"10": {"name": "legacy"}, "30": {"name": "remove-me"}},
        "dns": ["8.8.8.8"],
    }

    first = StateEngine().build_plan(desired, actual)
    second = StateEngine().build_plan(desired, actual)

    assert first == second
    assert first.plan_id == second.plan_id
    assert [op.path for op in first.operations] == sorted(op.path for op in first.operations)
    kinds = {op.kind for op in first.operations}
    assert {OperationKind.CREATE, OperationKind.UPDATE, OperationKind.DELETE} <= kinds
    assert all(op.risk >= RiskLevel.BOUNDED_CHANGE for op in first.operations)


def test_desired_state_diff_noop_and_critical_management_risk() -> None:
    engine = StateEngine()
    assert engine.build_plan({"a": 1}, {"a": 1}).is_noop

    plan = engine.build_plan(
        {"management": {"address": "192.0.2.10"}},
        {"management": {"address": "192.0.2.9"}},
    )
    assert plan.max_risk is RiskLevel.CRITICAL_CHANGE
    op = plan.operations[0]
    assert op.before == "192.0.2.9"
    assert op.after == "192.0.2.10"
