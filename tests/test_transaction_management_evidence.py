from router_configuration.transaction_management_evidence import (
    build_management_reachability_evidence,
)


def test_management_evidence_requires_all_windows_and_independent_session():
    payload = build_management_reachability_evidence(
        evidence_ref="evidence://chr-management-run-1",
        before={"attempts": 3, "successes": 3},
        during_apply={"attempts": 40, "successes": 40},
        after={"attempts": 3, "successes": 3},
        independent_session=True,
        mutation_visible_during_apply=True,
    ).as_dict()
    assert payload["management_ok"] is True
    assert payload["management_survival_during_apply"] is True
    assert payload["all_probes_successful"] is True
    assert payload["transport_present"] is False
    assert payload["write_authorized"] is False


def test_management_evidence_does_not_overclaim_partial_success():
    payload = build_management_reachability_evidence(
        evidence_ref="evidence://chr-management-run-2",
        before={"attempts": 2, "successes": 2},
        during_apply={"attempts": 10, "successes": 9},
        after={"attempts": 2, "successes": 2},
        independent_session=True,
        mutation_visible_during_apply=True,
    ).as_dict()
    assert payload["management_ok"] is False
    assert payload["management_survival_during_apply"] is False
