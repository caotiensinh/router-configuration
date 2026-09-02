from __future__ import annotations

import copy
import unittest

from router_configuration.transaction_backup_evidence import (
    TransactionBackupEvidenceError,
    build_transaction_backup_evidence,
    validate_transaction_backup_evidence,
)


class TransactionBackupEvidenceTests(unittest.TestCase):
    def test_sanitized_export_is_deterministic_and_repository_safe(self):
        first = build_transaction_backup_evidence(
            kind="sanitized_export",
            artifact_ref="artifact://chr/pre-state-export.rsc",
            sha256="b" * 64,
            pre_state_sha256="a" * 64,
        ).as_dict()
        second = build_transaction_backup_evidence(
            kind="sanitized_export",
            artifact_ref="artifact://chr/pre-state-export.rsc",
            sha256="b" * 64,
            pre_state_sha256="a" * 64,
        ).as_dict()
        self.assertEqual(first, second)
        self.assertTrue(first["repository_safe"])
        self.assertFalse(first["binary_payload_present"])
        self.assertFalse(first["protected_storage_required"])
        self.assertFalse(first["production_writer_available"])
        self.assertFalse(first["write_authorized"])
        validate_transaction_backup_evidence(
            first,
            expected_pre_state_sha256="a" * 64,
        )

    def test_binary_backup_is_only_an_opaque_protected_reference(self):
        evidence = build_transaction_backup_evidence(
            kind="protected_ephemeral_binary",
            artifact_ref="protected-ref://run-336999/backup-01",
            sha256="c" * 64,
            pre_state_sha256="a" * 64,
        ).as_dict()
        self.assertTrue(evidence["protected_storage_required"])
        self.assertFalse(evidence["binary_payload_present"])
        validate_transaction_backup_evidence(evidence)

    def test_repository_safe_export_rejects_binary_backup_path(self):
        with self.assertRaisesRegex(TransactionBackupEvidenceError, "binary \\.backup"):
            build_transaction_backup_evidence(
                kind="sanitized_export",
                artifact_ref="artifact://chr/pre-state.backup",
                sha256="b" * 64,
                pre_state_sha256="a" * 64,
            )

    def test_protected_reference_rejects_storage_location(self):
        with self.assertRaisesRegex(TransactionBackupEvidenceError, "protected-ref"):
            build_transaction_backup_evidence(
                kind="protected_ephemeral_binary",
                artifact_ref="https://storage.example.invalid/router.backup",
                sha256="b" * 64,
                pre_state_sha256="a" * 64,
            )

    def test_tampering_and_cross_state_reuse_are_rejected(self):
        evidence = build_transaction_backup_evidence(
            kind="sanitized_export",
            artifact_ref="artifact://chr/pre-state.json",
            sha256="b" * 64,
            pre_state_sha256="a" * 64,
        ).as_dict()
        with self.assertRaisesRegex(TransactionBackupEvidenceError, "different pre-state"):
            validate_transaction_backup_evidence(
                evidence,
                expected_pre_state_sha256="d" * 64,
            )

        tampered = copy.deepcopy(evidence)
        tampered["sha256"] = "e" * 64
        with self.assertRaisesRegex(TransactionBackupEvidenceError, "digest mismatch"):
            validate_transaction_backup_evidence(tampered)

    def test_unexpected_fields_and_embedded_binary_claim_are_rejected(self):
        evidence = build_transaction_backup_evidence(
            kind="sanitized_export",
            artifact_ref="artifact://chr/pre-state.json",
            sha256="b" * 64,
            pre_state_sha256="a" * 64,
        ).as_dict()
        with_extra = copy.deepcopy(evidence)
        with_extra["storage_url"] = "https://forbidden.invalid/object"
        with self.assertRaisesRegex(TransactionBackupEvidenceError, "unexpected fields"):
            validate_transaction_backup_evidence(with_extra)

        embedded = copy.deepcopy(evidence)
        embedded["binary_payload_present"] = True
        with self.assertRaisesRegex(TransactionBackupEvidenceError, "must not be embedded"):
            validate_transaction_backup_evidence(embedded)


if __name__ == "__main__":
    unittest.main()
