import pytest

from router_configuration.readback_verification import (
    ReadBackVerificationError,
    build_readback_verification,
)


def evidence(**overrides):
    base = {
        "evidence_ref": "runtime-evidence/omada/fresh-readback",
        "fresh_read": True,
        "independently_acquired": True,
        "apply_observation_reused": False,
    }
    base.update(overrides)
    return base


def test_exact_fresh_readback_passes_without_execution_capability() -> None:
    desired = {"network": {"vlan": 20, "enabled": True}}
    result = build_readback_verification(
        source_plan_id="plan-20",
        desired_managed_state=desired,
        readback_managed_state={"network": {"vlan": 20, "enabled": True}},
        evidence=evidence(),
    ).as_dict()
    assert result["acceptance"] == "PASS"
    assert result["verification_state"] == "VERIFIED"
    assert result["drift_count"] == 0
    assert result["readback_matches_desired"] is True
    assert result["transport_present"] is False
    assert result["apply_available"] is False
    assert result["write_authorized"] is False


def test_readback_mismatch_returns_deterministic_drift_evidence() -> None:
    result = build_readback_verification(
        source_plan_id="plan-21",
        desired_managed_state={"network": {"vlan": 20}},
        readback_managed_state={"network": {"vlan": 30, "unexpected": True}},
        evidence=evidence(),
    ).as_dict()
    assert result["acceptance"] == "FAIL"
    assert result["verification_state"] == "MISMATCH"
    assert result["drift_count"] == 2
    assert [item["path"] for item in result["drift"]] == ["network.unexpected", "network.vlan"]


def test_stale_reused_or_secret_bearing_evidence_fails_closed() -> None:
    desired = {"x": 1}
    with pytest.raises(ReadBackVerificationError, match="fresh_read=true"):
        build_readback_verification(
            source_plan_id="plan-a",
            desired_managed_state=desired,
            readback_managed_state=desired,
            evidence=evidence(fresh_read=False),
        )
    with pytest.raises(ReadBackVerificationError, match="apply_observation_reused=false"):
        build_readback_verification(
            source_plan_id="plan-b",
            desired_managed_state=desired,
            readback_managed_state=desired,
            evidence=evidence(apply_observation_reused=True),
        )
    with pytest.raises(ReadBackVerificationError, match="secret fields"):
        build_readback_verification(
            source_plan_id="plan-c",
            desired_managed_state=desired,
            readback_managed_state=desired,
            evidence=evidence(token="should-not-exist"),
        )
