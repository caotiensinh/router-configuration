import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from router_configuration.production_transaction_readiness import (
    build_production_transaction_readiness,
)
from router_configuration.routerctl import main as routerctl_main
from router_configuration.transaction_backup_evidence import (
    build_transaction_backup_evidence,
)
from router_configuration.transaction_envelope import build_transaction_envelope
from router_configuration.transaction_lifecycle import (
    initialize_transaction_lifecycle,
    transition_transaction_lifecycle,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


class RouterctlProductionOutcomeTests(unittest.TestCase):
    def _base(self):
        pre_state = _sha("pre-state")
        plan = {
            "schema_version": "routeros-render-plan/1",
            "device_id": "rd-router-01",
            "source_ir_sha256": _sha("ir"),
            "claim": "generation_complete",
            "complete": True,
            "command_format": "routeros-script/1",
            "commands": [],
            "blocked_operations": [],
            "secret_references": [],
            "vendor_commands_present": False,
            "secrets_resolved": False,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
        plan["render_sha256"] = _canonical_sha256(plan)
        sanitized = build_transaction_backup_evidence(
            kind="sanitized_export",
            artifact_ref="artifact://prechange/sanitized-export.rsc",
            sha256=_sha("sanitized"),
            pre_state_sha256=pre_state,
        ).as_dict()
        protected = build_transaction_backup_evidence(
            kind="protected_ephemeral_binary",
            artifact_ref="protected-ref://router-backup/prechange-001",
            sha256=_sha("protected"),
            pre_state_sha256=pre_state,
        ).as_dict()
        envelope = build_transaction_envelope(
            render_plan=plan,
            pre_state_sha256=pre_state,
            backup=sanitized,
            approval={
                "approved": True,
                "plan_sha256": plan["render_sha256"],
                "approver_ref": "operator://approval/001",
            },
            management_path={"ok": True, "evidence_ref": "evidence://management/prechange"},
            connectivity_baseline={"ok": True, "evidence_ref": "evidence://connectivity/prechange"},
        ).as_dict()
        lifecycle = initialize_transaction_lifecycle(envelope=envelope).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="authorized",
            evidence={
                "evidence_ref": "evidence://approval/authorized",
                "authorized": True,
                "exact_envelope_revalidated": True,
                "transaction_id": envelope["transaction_id"],
            },
        ).as_dict()
        checks = ("management", "wan", "dns", "routing")
        readiness = build_production_transaction_readiness(
            profile={"intent": {"vpn": {"wireguard": {"enabled": False}}}},
            envelope=envelope,
            lifecycle=lifecycle,
            backups=[sanitized, protected],
            management_path={
                "schema_version": "routeros-production-management-readiness/1",
                "pre_change_reachable": True,
                "independent_probe": True,
                "monitor_during_apply": True,
                "post_apply_verification_required": True,
                "rollback_recovery_verification_required": True,
                "evidence_ref": "evidence://management/readiness",
            },
            verification_contract={
                "schema_version": "routeros-production-verification-contract/1",
                "stop_on_failure": True,
                "checks": {
                    name: {
                        "required": True,
                        "readback_required": True,
                        "behavior_verification_required": True,
                        "evidence_ref": f"evidence://contract/{name}",
                    }
                    for name in checks
                },
            },
            rollback_contract={
                "schema_version": "routeros-production-rollback-contract/1",
                "stop_further_changes": True,
                "assess_state": True,
                "rollback_required_on_verification_failure": True,
                "verify_restored_state": True,
                "incident_evidence_required": True,
                "strategy_ref": "evidence://rollback/strategy",
            },
        ).as_dict()
        return pre_state, lifecycle, readiness

    @staticmethod
    def _write(root: Path, name: str, payload) -> Path:
        path = root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _run(self, root: Path, readiness, lifecycle, evidence):
        output = root / "outcome.json"
        argv = [
            "production-outcome-check",
            "--readiness", str(self._write(root, "readiness.json", readiness)),
            "--lifecycle", str(self._write(root, "lifecycle.json", lifecycle)),
            "--verification-evidence", str(self._write(root, "verification.json", evidence)),
            "--output", str(output),
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = routerctl_main(argv)
        return rc, output, stdout.getvalue()

    def test_cli_accepts_verified_success_without_runtime_capability(self):
        pre_state, lifecycle, readiness = self._base()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="apply_observed",
            evidence={
                "evidence_ref": "evidence://runtime/apply",
                "exact_plan_revalidated": True,
                "exact_pre_state_revalidated": True,
                "backup_revalidated": True,
                "management_path_revalidated": True,
                "connectivity_revalidated": True,
                "apply_completed": True,
            },
        ).as_dict()
        post_state = _sha("post-state")
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verification_pending",
            evidence={"evidence_ref": "evidence://runtime/verify", "post_state_sha256": post_state},
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verified",
            evidence={
                "evidence_ref": "evidence://runtime/verified",
                "management_ok": True,
                "connectivity_ok": True,
                "intended_state_ok": True,
                "post_state_sha256": post_state,
            },
        ).as_dict()
        evidence = {
            "schema_version": "routeros-production-verification-evidence/1",
            "checks": {
                name: {"ok": True, "evidence_ref": f"evidence://post/{name}"}
                for name in readiness["required_verification_checks"]
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            rc, output, stdout = self._run(Path(tmp), readiness, lifecycle, evidence)
            self.assertEqual(rc, 0, stdout)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["outcome"], "verified_success")
            self.assertTrue(payload["deployment_success"])
            self.assertFalse(payload["production_writer_available"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_cli_accepts_verified_rollback_recovery_as_not_success(self):
        pre_state, lifecycle, readiness = self._base()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rollback_required",
            evidence={
                "evidence_ref": "evidence://runtime/rollback-required",
                "failure_observed": True,
                "failure_reason_ref": "evidence://runtime/failure",
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rollback_observed",
            evidence={
                "evidence_ref": "evidence://runtime/rollback-observed",
                "rollback_completed": True,
                "rollback_state_sha256": pre_state,
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rolled_back",
            evidence={
                "evidence_ref": "evidence://runtime/rolled-back",
                "management_recovered": True,
                "connectivity_recovered": True,
                "managed_objects_reconciled": True,
                "rollback_state_sha256": pre_state,
            },
        ).as_dict()
        evidence = {
            "schema_version": "routeros-production-verification-evidence/1",
            "checks": {
                name: {"ok": name != "dns", "evidence_ref": f"evidence://failed/{name}"}
                for name in readiness["required_verification_checks"]
            },
            "failure_observed": True,
            "recovery": {
                "management_recovered": True,
                "connectivity_recovered": True,
                "managed_objects_reconciled": True,
                "rollback_state_sha256": pre_state,
                "evidence_ref": "evidence://recovery/verified",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            rc, output, stdout = self._run(Path(tmp), readiness, lifecycle, evidence)
            self.assertEqual(rc, 0, stdout)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["outcome"], "failure_recovered")
            self.assertFalse(payload["deployment_success"])
            self.assertTrue(payload["failure_recovered"])

    def test_cli_rejects_tampered_readiness(self):
        _, lifecycle, readiness = self._base()
        readiness["required_verification_checks"] = ["management"]
        evidence = {
            "schema_version": "routeros-production-verification-evidence/1",
            "checks": {"management": {"ok": True, "evidence_ref": "evidence://post/management"}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            rc, output, stdout = self._run(Path(tmp), readiness, lifecycle, evidence)
            self.assertEqual(rc, 12)
            self.assertFalse(output.exists())
            summary = json.loads(stdout)
            self.assertEqual(summary["claim"], "production_outcome_blocked")
            self.assertFalse(summary["production_writer_available"])
            self.assertFalse(summary["write_authorized"])


if __name__ == "__main__":
    unittest.main()
