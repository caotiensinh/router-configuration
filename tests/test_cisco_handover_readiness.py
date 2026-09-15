import unittest

from router_configuration.vendors.cisco.handover_readiness import (
    CiscoHandoverReadinessError,
    assess_c12_handover_readiness,
)

STAGES = ("C06", "C07", "C08", "C09", "C10", "C11")


def complete_map(value=True):
    return {stage: value for stage in STAGES}


def evidence_map():
    return {stage: str(index + 1) * 64 for index, stage in enumerate(STAGES)}


class CiscoHandoverReadinessTests(unittest.TestCase):
    def test_all_prerequisites_can_only_reach_c12_human_review_readiness(self):
        first = assess_c12_handover_readiness(
            stage_complete=complete_map(True),
            evidence_sha256=evidence_map(),
            physical_device_verified=True,
        )
        second = assess_c12_handover_readiness(
            stage_complete=complete_map(True),
            evidence_sha256=evidence_map(),
            physical_device_verified=True,
        )
        self.assertEqual(first, second)
        self.assertTrue(first.ready_for_c12_human_review)
        self.assertEqual(first.blockers, ())
        self.assertFalse(first.c12_complete)
        self.assertFalse(first.production_writer_available)
        self.assertFalse(first.production_write_authorized)
        self.assertEqual(len(first.readiness_sha256), 64)

    def test_incomplete_stages_are_reported_as_blockers(self):
        stages = complete_map(True)
        stages["C09"] = False
        stages["C10"] = False
        result = assess_c12_handover_readiness(
            stage_complete=stages,
            evidence_sha256=evidence_map(),
            physical_device_verified=True,
        )
        self.assertFalse(result.ready_for_c12_human_review)
        self.assertEqual(result.blockers, ("C09_INCOMPLETE", "C10_INCOMPLETE"))
        self.assertFalse(result.c12_complete)

    def test_c11_complete_requires_physical_verification(self):
        result = assess_c12_handover_readiness(
            stage_complete=complete_map(True),
            evidence_sha256=evidence_map(),
            physical_device_verified=False,
        )
        self.assertFalse(result.ready_for_c12_human_review)
        self.assertIn("C11_PHYSICAL_DEVICE_NOT_VERIFIED", result.blockers)

    def test_physical_verification_cannot_precede_c11_completion(self):
        stages = complete_map(True)
        stages["C11"] = False
        with self.assertRaisesRegex(CiscoHandoverReadinessError, "cannot be true"):
            assess_c12_handover_readiness(
                stage_complete=stages,
                evidence_sha256=evidence_map(),
                physical_device_verified=True,
            )

    def test_production_write_capability_or_authority_is_rejected(self):
        for field in ("production_writer_available", "production_write_authorized"):
            with self.subTest(field=field):
                kwargs = {field: True}
                with self.assertRaisesRegex(CiscoHandoverReadinessError, "production write"):
                    assess_c12_handover_readiness(
                        stage_complete=complete_map(True),
                        evidence_sha256=evidence_map(),
                        physical_device_verified=True,
                        **kwargs,
                    )

    def test_stage_keys_must_be_exact(self):
        stages = complete_map(True)
        stages["C12"] = False
        with self.assertRaisesRegex(CiscoHandoverReadinessError, "exactly C06 through C11"):
            assess_c12_handover_readiness(
                stage_complete=stages,
                evidence_sha256=evidence_map(),
                physical_device_verified=True,
            )

    def test_evidence_keys_and_digests_must_be_exact(self):
        evidence = evidence_map()
        evidence.pop("C08")
        with self.assertRaisesRegex(CiscoHandoverReadinessError, "evidence_sha256"):
            assess_c12_handover_readiness(
                stage_complete=complete_map(True),
                evidence_sha256=evidence,
                physical_device_verified=True,
            )
        evidence = evidence_map()
        evidence["C08"] = "bad"
        with self.assertRaisesRegex(CiscoHandoverReadinessError, "valid evidence SHA-256"):
            assess_c12_handover_readiness(
                stage_complete=complete_map(True),
                evidence_sha256=evidence,
                physical_device_verified=True,
            )

    def test_stage_completion_must_be_boolean(self):
        stages = complete_map(True)
        stages["C08"] = 1
        with self.assertRaisesRegex(CiscoHandoverReadinessError, "must be boolean"):
            assess_c12_handover_readiness(
                stage_complete=stages,
                evidence_sha256=evidence_map(),
                physical_device_verified=True,
            )

    def test_evidence_bundle_changes_when_stage_evidence_changes(self):
        baseline = assess_c12_handover_readiness(
            stage_complete=complete_map(True),
            evidence_sha256=evidence_map(),
            physical_device_verified=True,
        )
        changed_evidence = evidence_map()
        changed_evidence["C10"] = "f" * 64
        changed = assess_c12_handover_readiness(
            stage_complete=complete_map(True),
            evidence_sha256=changed_evidence,
            physical_device_verified=True,
        )
        self.assertNotEqual(baseline.evidence_bundle_sha256, changed.evidence_bundle_sha256)
        self.assertNotEqual(baseline.readiness_sha256, changed.readiness_sha256)


if __name__ == "__main__":
    unittest.main()
