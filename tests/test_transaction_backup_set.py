import unittest

from router_configuration.transaction_backup_evidence import build_transaction_backup_evidence
from router_configuration.transaction_backup_set import build_transaction_backup_set


PRE_STATE = "a" * 64


def _export():
    return build_transaction_backup_evidence(
        kind="sanitized_export",
        artifact_ref="artifact://prechange-export.rsc",
        sha256="b" * 64,
        pre_state_sha256=PRE_STATE,
    ).as_dict()


def _binary(state=PRE_STATE):
    return build_transaction_backup_evidence(
        kind="protected_ephemeral_binary",
        artifact_ref="protected-ref://backup-object-001",
        sha256="c" * 64,
        pre_state_sha256=state,
    ).as_dict()


class TransactionBackupSetTests(unittest.TestCase):
    def test_backup_set_requires_complementary_bound_artifacts(self):
        payload = build_transaction_backup_set(
            sanitized_export=_export(),
            protected_binary=_binary(),
        ).as_dict()
        self.assertTrue(payload["production_backup_requirements_satisfied"])
        self.assertFalse(payload["repository_contains_binary_backup"])
        self.assertTrue(payload["protected_storage_required"])
        self.assertFalse(payload["restore_available"])
        self.assertFalse(payload["production_writer_available"])
        self.assertFalse(payload["write_authorized"])

    def test_backup_set_rejects_mismatched_pre_state(self):
        with self.assertRaisesRegex(ValueError, "different pre-state"):
            build_transaction_backup_set(
                sanitized_export=_export(),
                protected_binary=_binary("d" * 64),
            )


if __name__ == "__main__":
    unittest.main()
