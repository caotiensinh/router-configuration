import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

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


class RouterctlProductionReadinessTests(unittest.TestCase):
    def _write(self, root: Path, name: str, payload) -> Path:
        path = root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _fixture(self, root: Path):
        pre_state = _sha("pre-state")
        render_plan = {
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
        render_plan["render_sha256"] = _canonical_sha256(render_plan)
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
            render_plan=render_plan,
            pre_state_sha256=pre_state,
            backup=sanitized,
            approval={
                "approved": True,
                "plan_sha256": render_plan["render_sha256"],
                "approver_ref": "operator://approval/001",
            },
            management_path={
                "ok": True,
                "evidence_ref": "evidence://management/prechange",
            },
            connectivity_baseline={
                "ok": True,
                "evidence_ref": "evidence://connectivity/prechange",
            },
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
        profile = {"intent": {"vpn": {"wireguard": {"enabled": False}}}}
        management = {
            "schema_version": "routeros-production-management-readiness/1",
            "pre_change_reachable": True,
            "independent_probe": True,
            "monitor_during_apply": True,
            "post_apply_verification_required": True,
            "rollback_recovery_verification_required": True,
            "evidence_ref": "evidence://management/readiness",
        }
        verification = {
            "schema_version": "routeros-production-verification-contract/1",
            "stop_on_failure": True,
            "checks": {
                name: {
                    "required": True,
                    "readback_required": True,
                    "behavior_verification_required": True,
                    "evidence_ref": f"evidence://verification/{name}",
                }
                for name in ("management", "wan", "dns", "routing")
            },
        }
        rollback = {
            "schema_version": "routeros-production-rollback-contract/1",
            "stop_further_changes": True,
            "assess_state": True,
            "rollback_required_on_verification_failure": True,
            "verify_restored_state": True,
            "incident_evidence_required": True,
            "strategy_ref": "evidence://rollback/strategy",
        }
        return {
            "profile": self._write(root, "profile.json", profile),
            "envelope": self._write(root, "envelope.json", envelope),
            "lifecycle": self._write(root, "lifecycle.json", lifecycle),
            "sanitized": self._write(root, "sanitized.json", sanitized),
            "protected": self._write(root, "protected.json", protected),
            "management": self._write(root, "management.json", management),
            "verification": self._write(root, "verification.json", verification),
            "rollback": self._write(root, "rollback.json", rollback),
        }

    def _argv(self, fixture, output):
        return [
            "production-readiness-check",
            "--profile", str(fixture["profile"]),
            "--envelope", str(fixture["envelope"]),
            "--lifecycle", str(fixture["lifecycle"]),
            "--sanitized-backup", str(fixture["sanitized"]),
            "--protected-backup", str(fixture["protected"]),
            "--management", str(fixture["management"]),
            "--verification-contract", str(fixture["verification"]),
            "--rollback-contract", str(fixture["rollback"]),
            "--output", str(output),
        ]

    def test_cli_writes_private_readiness_verdict_without_runtime_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            output = root / "readiness.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = routerctl_main(self._argv(fixture, output))
            self.assertEqual(rc, 0, stdout.getvalue())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["ready"])
            self.assertFalse(payload["transport_present"])
            self.assertFalse(payload["apply_available"])
            self.assertFalse(payload["production_writer_available"])
            self.assertFalse(payload["write_authorized"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            text = (Path(__file__).resolve().parents[1] / "src/router_configuration/routerctl.py").read_text(encoding="utf-8")
            command_block = text.split("def command_production_readiness_check", 1)[1].split("def command_guided_start", 1)[0]
            self.assertNotIn("--router-url", command_block)
            self.assertNotIn("--username", command_block)
            self.assertNotIn("--password", command_block)

    def test_cli_fails_closed_when_management_guard_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            management = json.loads(fixture["management"].read_text(encoding="utf-8"))
            management["monitor_during_apply"] = False
            fixture["management"].write_text(json.dumps(management), encoding="utf-8")
            output = root / "readiness.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = routerctl_main(self._argv(fixture, output))
            self.assertEqual(rc, 11)
            self.assertFalse(output.exists())
            summary = json.loads(stdout.getvalue())
            self.assertFalse(summary["ok"])
            self.assertEqual(summary["claim"], "production_readiness_blocked")
            self.assertFalse(summary["production_writer_available"])
            self.assertFalse(summary["write_authorized"])


if __name__ == "__main__":
    unittest.main()
