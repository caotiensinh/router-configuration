import unittest

from router_configuration.harness import (
    DeploymentSpec,
    Environment,
    EvidenceKind,
    EvidenceRecord,
    ExecutionStage,
    HarnessEngine,
    HarnessRun,
    OperatorMode,
)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.engine = HarnessEngine()
        self.spec = DeploymentSpec(
            device_id="rd-router-01",
            vendor="mikrotik",
            management_target="192.168.11.1",
            environment=Environment.PRODUCTION,
            operator_mode=OperatorMode.GUIDED,
            site_name="rd",
            allow_write=True,
        )

    def test_production_workflow_requires_evidence_in_order(self):
        run = HarnessRun(self.spec)
        self.assertEqual(self.engine.advance(run).next_stage, ExecutionStage.DISCOVER)
        self.assertFalse(self.engine.advance(run).allowed)
        run.record(EvidenceRecord(EvidenceKind.DEVICE_FACTS, True, "CCR2116 facts"))
        self.assertTrue(self.engine.advance(run).allowed)
        self.assertEqual(run.stage, ExecutionStage.INSPECT)

    def test_write_is_disabled_by_default(self):
        spec = DeploymentSpec("r1", "mikrotik", "192.0.2.1")
        run = HarnessRun(spec, stage=ExecutionStage.APPROVAL)
        run.record(EvidenceRecord(EvidenceKind.APPROVAL, True, "approved plan"))
        decision = self.engine.evaluate_advance(run)
        self.assertFalse(decision.allowed)
        self.assertIn("writes are disabled by deployment spec", decision.reasons)

    def test_failed_preflight_evidence_blocks_approval(self):
        run = HarnessRun(self.spec, stage=ExecutionStage.PREFLIGHT)
        run.record(EvidenceRecord(EvidenceKind.CAPABILITY_CHECK, True, "supported"))
        run.record(EvidenceRecord(EvidenceKind.MANAGEMENT_PATH, False, "no alternate management path"))
        run.record(EvidenceRecord(EvidenceKind.CONNECTIVITY_BASELINE, True, "baseline captured"))
        decision = self.engine.evaluate_advance(run)
        self.assertFalse(decision.allowed)
        self.assertTrue(any("management_path" in item for item in decision.reasons))

    def test_failed_verify_routes_to_rollback(self):
        run = HarnessRun(self.spec, stage=ExecutionStage.VERIFY)
        run.record(EvidenceRecord(EvidenceKind.VERIFY_RESULT, False, "default route lost"))
        decision = self.engine.advance(run)
        self.assertTrue(decision.allowed)
        self.assertEqual(run.stage, ExecutionStage.ROLLBACK)

    def test_rollback_requires_success_evidence_before_complete(self):
        run = HarnessRun(self.spec, stage=ExecutionStage.ROLLBACK)
        self.assertFalse(self.engine.advance(run).allowed)
        run.record(EvidenceRecord(EvidenceKind.ROLLBACK_RESULT, True, "restored"))
        self.assertTrue(self.engine.advance(run).allowed)
        self.assertEqual(run.stage, ExecutionStage.COMPLETE)

    def test_guided_mode_has_operator_guidance_for_change_stages(self):
        for stage in (
            ExecutionStage.DISCOVER,
            ExecutionStage.INSPECT,
            ExecutionStage.PLAN,
            ExecutionStage.VALIDATE,
            ExecutionStage.BACKUP,
            ExecutionStage.PREFLIGHT,
            ExecutionStage.APPROVAL,
            ExecutionStage.APPLY,
            ExecutionStage.VERIFY,
            ExecutionStage.SAVE,
            ExecutionStage.ROLLBACK,
        ):
            guide = self.engine.guide(stage)
            self.assertTrue(guide.purpose)
            self.assertTrue(guide.success_criteria)
            self.assertTrue(guide.failure_action)

    def test_production_backup_is_a_hard_gate(self):
        run = HarnessRun(self.spec, stage=ExecutionStage.BACKUP)
        decision = self.engine.evaluate_advance(run)
        self.assertFalse(decision.allowed)
        self.assertIn("missing evidence: backup", decision.reasons)


if __name__ == "__main__":
    unittest.main()
