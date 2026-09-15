from router_configuration.rca_graph import (
    Evidence,
    EvidenceRCAGraph,
    EvidenceState,
    Hypothesis,
)


def test_missing_required_evidence_is_unknown() -> None:
    graph = EvidenceRCAGraph([Evidence("link_up", EvidenceState.CONFIRMED, "probe")])
    result = graph.assess(Hypothesis("route_ok", required_evidence=("link_up", "route_present")))
    assert result.state is EvidenceState.UNKNOWN
    assert result.missing == ("route_present",)


def test_confirmed_contradiction_rejects_hypothesis() -> None:
    graph = EvidenceRCAGraph(
        [
            Evidence("route_present", EvidenceState.CONFIRMED, "device"),
            Evidence("acl_drop", EvidenceState.CONFIRMED, "counter"),
        ]
    )
    result = graph.assess(
        Hypothesis(
            "routing_root_cause",
            required_evidence=("route_present",),
            contradicting_evidence=("acl_drop",),
        )
    )
    assert result.state is EvidenceState.REJECTED
    assert result.contradictions == ("acl_drop",)


def test_all_required_evidence_confirms_and_next_checks_are_deterministic() -> None:
    graph = EvidenceRCAGraph(
        [
            Evidence("a", EvidenceState.CONFIRMED, "probe"),
            Evidence("c", EvidenceState.UNKNOWN, "probe"),
        ]
    )
    hypothesis = Hypothesis("h", required_evidence=("c", "b", "a"))
    assert graph.next_checks(hypothesis) == ("b", "c")

    confirmed = EvidenceRCAGraph(
        [
            Evidence("a", EvidenceState.CONFIRMED, "probe"),
            Evidence("b", EvidenceState.CONFIRMED, "probe"),
            Evidence("c", EvidenceState.CONFIRMED, "probe"),
        ]
    ).assess(hypothesis)
    assert confirmed.state is EvidenceState.CONFIRMED
