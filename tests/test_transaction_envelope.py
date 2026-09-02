import hashlib
import json
import unittest

from router_configuration.transaction_backup_evidence import build_transaction_backup_evidence
from router_configuration.transaction_envelope import (
    TransactionEnvelopeError,
    build_transaction_envelope,
)


def canonical_sha(payload):
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def render_plan():
    payload = {
        "schema_version": "routeros-render-plan/1",
        "commands": [],
        "blocked_operations": [],
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    payload["render_sha256"] = canonical_sha(payload)
    return payload


def backup_evidence(pre_state_sha256="a" * 64):
    return build_transaction_backup_evidence(
        kind="sanitized_export",
        artifact_ref="artifact://chr/routercfg-before-change.rsc",
        sha256="b" * 64,
        pre_state_sha256=pre_state_sha256,
    ).as_dict()


def build(**overrides):
    plan = overrides.pop("render_plan", render_plan())
    kwargs = {
        "render_plan": plan,
        "pre_state_sha256": "a" * 64,
        "backup": backup_evidence(),
        "approval": {
            "approved": True,
            "plan_sha256": plan["render_sha256"],
            "approver_ref": "change-approval-001",
        },
        "management_path": {"ok": True, "evidence_ref": "evidence/management.json"},
        "connectivity_baseline": {"ok": True, "evidence_ref": "evidence/connectivity.json"},
    }
    kwargs.update(overrides)
    return build_transaction_envelope(**kwargs).as_dict()


class TransactionEnvelopeTests(unittest.TestCase):
    def test_successful_envelope_is_generation_only_and_deterministic(self):
        first = build()
        second = build()
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], "routeros-transaction-envelope/1")
        self.assertFalse(first["transport_present"])
        self.assertFalse(first["apply_available"])
        self.assertFalse(first["production_writer_available"])
        self.assertFalse(first["write_authorized"])
        self.assertFalse(first["secret_values_present"])
        self.assertEqual(len(first["transaction_id"]), 64)
        self.assertEqual(len(first["envelope_sha256"]), 64)
        self.assertEqual(
            first["bindings"]["backup"]["pre_state_sha256"],
            first["bindings"]["pre_state_sha256"],
        )

    def test_tampered_render_plan_is_rejected(self):
        plan = render_plan()
        plan["commands"] = [{"command": "/ip/address/add"}]
        with self.assertRaisesRegex(TransactionEnvelopeError, "digest mismatch"):
            build(render_plan=plan)

    def test_render_plan_with_transport_is_rejected(self):
        plan = render_plan()
        plan["transport_present"] = True
        plan["render_sha256"] = canonical_sha({k: v for k, v in plan.items() if k != "render_sha256"})
        with self.assertRaisesRegex(TransactionEnvelopeError, "must not contain a transport"):
            build(render_plan=plan)

    def test_unreadable_backup_evidence_is_rejected(self):
        backup = backup_evidence()
        backup["readable"] = False
        with self.assertRaisesRegex(TransactionEnvelopeError, "backup evidence verification failed"):
            build(backup=backup)

    def test_backup_must_bind_exact_pre_state(self):
        with self.assertRaisesRegex(TransactionEnvelopeError, "backup evidence verification failed"):
            build(backup=backup_evidence("c" * 64))

    def test_approval_must_bind_exact_plan(self):
        with self.assertRaisesRegex(TransactionEnvelopeError, "exact render plan"):
            build(
                approval={
                    "approved": True,
                    "plan_sha256": "c" * 64,
                    "approver_ref": "approval-1",
                }
            )

    def test_management_path_failure_is_rejected(self):
        with self.assertRaisesRegex(TransactionEnvelopeError, "management path"):
            build(management_path={"ok": False, "evidence_ref": "evidence/mgmt.json"})

    def test_connectivity_baseline_failure_is_rejected(self):
        with self.assertRaisesRegex(TransactionEnvelopeError, "connectivity baseline"):
            build(connectivity_baseline={"ok": False, "evidence_ref": "evidence/net.json"})

    def test_invalid_digest_is_rejected(self):
        with self.assertRaisesRegex(TransactionEnvelopeError, "SHA-256"):
            build(pre_state_sha256="not-a-digest")

    def test_secret_values_are_not_copied_from_render_plan(self):
        payload = build()
        rendered = json.dumps(payload, sort_keys=True)
        self.assertNotIn("private_key", rendered)
        self.assertNotIn("password", rendered)
        self.assertNotIn("token", rendered)
        self.assertNotIn(".backup", rendered)


if __name__ == "__main__":
    unittest.main()
