import unittest

from router_configuration.vendors.cisco.switch_state import (
    SwitchNormalizedState,
    switch_state_catalog_digest,
)
from router_configuration.vendors.cisco.switch_state_evidence_ingest import (
    CiscoSwitchStateEvidenceError,
    ingest_switch_state_evidence,
)


def normalized_state(**overrides):
    values = dict(
        model="C9300-24T",
        iosxe_version="17.18.1a",
        documentation_train="17.18",
        platform_family="Catalyst 9300",
        schema_inventory_digest_sha256="a" * 64,
        observed_modules=("Cisco-IOS-XE-interfaces-oper", "openconfig-vlan"),
        interfaces=(),
        vlans=(),
        mac_entries=(),
        stp_instances=(),
        switched_vlans=(),
        catalog_digest_sha256=switch_state_catalog_digest(),
        state_digest_sha256="b" * 64,
        trunk_state_verified=True,
        c06_contract_complete=True,
        c06_complete=False,
        production_write_authorized=False,
        physical_device_verified=False,
    )
    values.update(overrides)
    return SwitchNormalizedState(**values)


def evidence(state=None, **overrides):
    state = state or normalized_state()
    payload = {
        "schema_version": "cisco-c06-live-switch-state-evidence/1",
        "target_id": "sw-core-01",
        "source_sha": "1" * 40,
        "source_run_id": "run-c06-001",
        "transport": "netconf",
        "evidence_origin": "live_iosxe_switch_readonly",
        "live_read_observed": True,
        "read_only": True,
        "write_attempted": False,
        "synthetic_fixture": False,
        "state_digest_sha256": state.state_digest_sha256,
        "schema_inventory_digest_sha256": state.schema_inventory_digest_sha256,
        "catalog_digest_sha256": state.catalog_digest_sha256,
        "repository_live_evidence_accepted": False,
        "c06_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    payload.update(overrides)
    return payload


class CiscoSwitchStateEvidenceIngestTests(unittest.TestCase):
    def test_candidate_binds_normalized_state_without_promoting_completion(self):
        state = normalized_state()
        first = ingest_switch_state_evidence(evidence(state), state=state)
        second = ingest_switch_state_evidence(evidence(state), state=state)
        self.assertEqual(first, second)
        self.assertTrue(first["candidate_claims_live_read"])
        self.assertFalse(first["repository_live_evidence_accepted"])
        self.assertFalse(first["c06_complete"])
        self.assertFalse(first["physical_device_verified"])
        self.assertFalse(first["production_write_authorized"])
        self.assertEqual(len(first["ingest_record_sha256"]), 64)

    def test_state_schema_and_catalog_digests_must_match(self):
        state = normalized_state()
        for field in ("state_digest_sha256", "schema_inventory_digest_sha256", "catalog_digest_sha256"):
            with self.subTest(field=field):
                with self.assertRaises(CiscoSwitchStateEvidenceError):
                    ingest_switch_state_evidence(evidence(state, **{field: "9" * 64}), state=state)

    def test_normalized_state_contract_must_already_be_satisfied(self):
        with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "must satisfy the C06 contract"):
            state = normalized_state(c06_contract_complete=False)
            ingest_switch_state_evidence(evidence(state), state=state)
        with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "must satisfy the C06 contract"):
            state = normalized_state(trunk_state_verified=False)
            ingest_switch_state_evidence(evidence(state), state=state)

    def test_synthetic_nonlive_or_write_evidence_is_rejected(self):
        state = normalized_state()
        bad = (
            {"synthetic_fixture": True},
            {"live_read_observed": False},
            {"read_only": False},
            {"write_attempted": True},
            {"evidence_origin": "synthetic_fixture"},
        )
        for override in bad:
            with self.subTest(override=override):
                with self.assertRaises(CiscoSwitchStateEvidenceError):
                    ingest_switch_state_evidence(evidence(state, **override), state=state)

    def test_candidate_cannot_self_promote(self):
        state = normalized_state()
        for field in ("repository_live_evidence_accepted", "c06_complete", "physical_device_verified", "production_write_authorized"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "cannot self-promote"):
                    ingest_switch_state_evidence(evidence(state, **{field: True}), state=state)

    def test_state_object_cannot_arrive_preaccepted(self):
        state = normalized_state(c06_complete=True)
        with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "safety boundary"):
            ingest_switch_state_evidence(evidence(state), state=state)
        state = normalized_state(physical_device_verified=True)
        with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "safety boundary"):
            ingest_switch_state_evidence(evidence(state), state=state)

    def test_source_target_and_transport_are_bounded(self):
        state = normalized_state()
        with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "target_id"):
            ingest_switch_state_evidence(evidence(state, target_id="bad target"), state=state)
        with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "Git SHA"):
            ingest_switch_state_evidence(evidence(state, source_sha="bad"), state=state)
        with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "source_run_id"):
            ingest_switch_state_evidence(evidence(state, source_run_id="bad run"), state=state)
        with self.assertRaisesRegex(CiscoSwitchStateEvidenceError, "transport"):
            ingest_switch_state_evidence(evidence(state, transport="ssh-cli"), state=state)


if __name__ == "__main__":
    unittest.main()
