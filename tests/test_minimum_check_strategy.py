from router_configuration.rca_graph import (
    DiagnosticCheck,
    Evidence,
    EvidenceRCAGraph,
    EvidenceState,
    Hypothesis,
)


def test_minimum_check_plan_deduplicates_and_prefers_lowest_cost() -> None:
    graph = EvidenceRCAGraph([Evidence("a", EvidenceState.CONFIRMED, "probe")])
    h1 = Hypothesis("h1", required_evidence=("a", "b", "c"))
    h2 = Hypothesis("h2", required_evidence=("b", "d"))
    plan = graph.minimum_check_plan(
        [h1, h2],
        [DiagnosticCheck("b", 2), DiagnosticCheck("b", 1), DiagnosticCheck("c", 3), DiagnosticCheck("d", 1, False)],
    )
    assert [item.evidence_id for item in plan.checks] == ["b", "c"]
    assert plan.blocked_evidence == ("d",)
    assert plan.executable is False


def test_mutating_checks_require_explicit_authorization_and_run_after_read_only() -> None:
    graph = EvidenceRCAGraph()
    h = Hypothesis("h", required_evidence=("read", "write"))
    checks = [DiagnosticCheck("write", 0, False), DiagnosticCheck("read", 5, True)]
    blocked = graph.minimum_check_plan([h], checks)
    assert blocked.blocked_evidence == ("write",)
    allowed = graph.minimum_check_plan([h], checks, allow_mutating=True)
    assert [item.evidence_id for item in allowed.checks] == ["read", "write"]
    assert allowed.executable is True


def test_negative_cost_is_rejected() -> None:
    graph = EvidenceRCAGraph()
    h = Hypothesis("h", required_evidence=("x",))
    try:
        graph.minimum_check_plan([h], [DiagnosticCheck("x", -1)])
    except ValueError as exc:
        assert "non-negative" in str(exc)
    else:
        raise AssertionError("negative diagnostic cost must be rejected")
