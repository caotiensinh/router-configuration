import tempfile
import unittest
from pathlib import Path

from router_configuration.governance import (
    GovernanceAcknowledgement,
    GovernanceError,
    acknowledge,
    authorize,
    load_governance_snapshot,
    require_production_execution,
    require_repository_write,
)


class GovernanceGateTests(unittest.TestCase):
    def _root(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        (root / "governance").mkdir()
        (root / "vendors/mikrotik").mkdir(parents=True)
        (root / "MASTER_RULES.md").write_text("master", encoding="utf-8")
        (root / "AGENTS.md").write_text("MASTER_RULES.md", encoding="utf-8")
        (root / "governance/AI_POLICY.md").write_text("policy", encoding="utf-8")
        (root / "vendors/mikrotik/VENDOR_RULES.md").write_text("vendor", encoding="utf-8")
        return tmp, root

    def test_missing_master_rules_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(GovernanceError, "MASTER_RULES_MISSING"):
                load_governance_snapshot(directory)

    def test_repository_write_requires_current_acknowledgement(self):
        tmp, root = self._root()
        self.addCleanup(tmp.cleanup)
        snapshot = load_governance_snapshot(root, vendors=("mikrotik",))
        denied = authorize(snapshot, None)
        self.assertFalse(denied.authorized_for_repository_write)
        with self.assertRaises(GovernanceError):
            require_repository_write(denied)
        allowed = authorize(snapshot, acknowledge(snapshot))
        self.assertTrue(allowed.authorized_for_repository_write)

    def test_rule_change_invalidates_old_acknowledgement(self):
        tmp, root = self._root()
        self.addCleanup(tmp.cleanup)
        before = load_governance_snapshot(root, vendors=("mikrotik",))
        ack = acknowledge(before)
        (root / "MASTER_RULES.md").write_text("master changed", encoding="utf-8")
        after = load_governance_snapshot(root, vendors=("mikrotik",))
        denied = authorize(after, ack)
        self.assertIn("STALE_OR_MISMATCHED_GOVERNANCE_ACKNOWLEDGEMENT", denied.blockers)

    def test_production_execution_requires_execution_gate_and_approval(self):
        tmp, root = self._root()
        self.addCleanup(tmp.cleanup)
        snapshot = load_governance_snapshot(root, vendors=("mikrotik",))
        ack = acknowledge(snapshot)
        auth = authorize(snapshot, ack, execution_policy_passed=False, approval_received=True)
        self.assertFalse(auth.authorized_for_production_execution)
        with self.assertRaises(GovernanceError):
            require_production_execution(auth)
        auth = authorize(snapshot, ack, execution_policy_passed=True, approval_received=True)
        self.assertTrue(auth.authorized_for_production_execution)

    def test_forged_hashes_do_not_authorize(self):
        tmp, root = self._root()
        self.addCleanup(tmp.cleanup)
        snapshot = load_governance_snapshot(root, vendors=("mikrotik",))
        forged = GovernanceAcknowledgement(
            master_rules_sha256="0" * 64,
            agents_sha256=snapshot.agents_sha256,
            scoped_rule_sha256=snapshot.scoped_rule_sha256,
            vendor_rule_sha256=snapshot.vendor_rule_sha256,
        )
        self.assertFalse(authorize(snapshot, forged).authorized_for_project_work)


if __name__ == "__main__":
    unittest.main()
