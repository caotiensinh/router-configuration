import unittest
from pathlib import Path

from router_configuration.governance import acknowledge, authorize, load_governance_snapshot


class RepositoryGovernanceTests(unittest.TestCase):
    def test_current_repository_governance_is_complete_and_hash_bound(self):
        root = Path(__file__).resolve().parents[1]
        snapshot = load_governance_snapshot(root, vendors=("mikrotik",))
        self.assertEqual(len(snapshot.master_rules_sha256), 64)
        self.assertEqual(len(snapshot.agents_sha256), 64)
        self.assertGreaterEqual(len(snapshot.scoped_rule_sha256), 5)
        self.assertEqual(len(snapshot.vendor_rule_sha256), 1)

        auth = authorize(snapshot, acknowledge(snapshot))
        self.assertTrue(auth.authorized_for_project_work)
        self.assertTrue(auth.authorized_for_repository_write)
        self.assertFalse(auth.authorized_for_production_execution)
        self.assertIn("EXECUTION_POLICY_NOT_PASSED", auth.blockers)
        self.assertIn("PRODUCTION_APPROVAL_NOT_RECEIVED", auth.blockers)


if __name__ == "__main__":
    unittest.main()
