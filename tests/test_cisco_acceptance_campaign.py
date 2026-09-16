import unittest

from router_configuration.vendors.cisco.acceptance_campaign import (
    CiscoAcceptanceCampaignError,
    build_acceptance_campaign_manifest,
)

STAGES = ("c03", "c04", "c05", "c06", "c08", "c09", "c10", "c11", "c12")


def gates(status="ready"):
    return {
        stage: {
            "status": status,
            "run_ref": None,
            "artifact_sha256": None,
            "decision_sha256": None,
            "production_write_authorized": False,
        }
        for stage in STAGES
    }


class CiscoAcceptanceCampaignTests(unittest.TestCase):
    def test_ready_campaign_is_deterministic_and_non_authorizing(self):
        first = build_acceptance_campaign_manifest(source_sha="1" * 40, gates=gates())
        second = build_acceptance_campaign_manifest(source_sha="1" * 40, gates=gates())
        self.assertEqual(first, second)
        self.assertEqual(first["accepted_gate_count"], 0)
        self.assertFalse(first["all_acceptance_gates_closed"])
        self.assertFalse(first["production_write_authorized"])
        self.assertEqual(len(first["campaign_sha256"]), 64)
        self.assertIn("workflow", first["gates"]["c03"]["execution_surface"])

    def test_accepted_status_requires_real_run_artifact_and_decision_refs(self):
        items = gates()
        items["c03"].update(
            {
                "status": "accepted",
                "run_ref": "gha:123456",
                "artifact_sha256": "2" * 64,
                "decision_sha256": "3" * 64,
            }
        )
        result = build_acceptance_campaign_manifest(source_sha="1" * 40, gates=items)
        self.assertEqual(result["accepted_gate_count"], 1)
        self.assertFalse(result["all_acceptance_gates_closed"])

        items = gates()
        items["c03"]["status"] = "accepted"
        with self.assertRaisesRegex(CiscoAcceptanceCampaignError, "requires run_ref"):
            build_acceptance_campaign_manifest(source_sha="1" * 40, gates=items)

    def test_write_authority_and_missing_gate_fail_closed(self):
        items = gates()
        items["c11"]["production_write_authorized"] = True
        with self.assertRaisesRegex(CiscoAcceptanceCampaignError, "production write authority"):
            build_acceptance_campaign_manifest(source_sha="1" * 40, gates=items)

        items = gates()
        del items["c12"]
        with self.assertRaisesRegex(CiscoAcceptanceCampaignError, "exactly"):
            build_acceptance_campaign_manifest(source_sha="1" * 40, gates=items)


if __name__ == "__main__":
    unittest.main()
