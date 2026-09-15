import unittest

from router_configuration.vendors.mikrotik.troubleshooting import (
    EvidenceState,
    assess_graph,
    internet_access_graph,
)


class MikroTikTroubleshootingTests(unittest.TestCase):
    def test_failed_node_is_only_candidate_after_dependencies_pass(self):
        graph = internet_access_graph()
        result = assess_graph(
            graph,
            {
                "device_inventory": EvidenceState.PASS,
                "interface_state": EvidenceState.PASS,
                "addressing": EvidenceState.PASS,
                "routing": EvidenceState.FAIL,
            },
        )
        self.assertEqual(result.candidates, ("routing",))
        self.assertFalse(result.root_cause_confirmed)

    def test_failure_without_dependency_evidence_is_not_root_cause_candidate(self):
        result = assess_graph(internet_access_graph(), {"policy": "fail"})
        self.assertNotIn("policy", result.candidates)
        self.assertFalse(result.root_cause_confirmed)


if __name__ == "__main__":
    unittest.main()
