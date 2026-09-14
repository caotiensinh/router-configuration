import unittest

from router_configuration.vendors.mikrotik.evidence_schema import build_diagnostic_evidence


class MikroTikDiagnosticEvidenceTests(unittest.TestCase):
    def test_sanitized_evidence_is_hash_bound_and_non_authorizing(self):
        evidence = build_diagnostic_evidence(
            source_tool="mikrotik.interface.list",
            collected_at="2026-09-14T00:00:00Z",
            payload={"interfaces": [{"name": "ether1", "running": True}]},
        )
        self.assertEqual(len(evidence.sha256), 64)
        self.assertFalse(evidence.as_dict()["write_authorized"])

    def test_secret_like_value_is_rejected(self):
        with self.assertRaises(ValueError):
            build_diagnostic_evidence(
                source_tool="mikrotik.inventory.system_resource",
                collected_at="2026-09-14T00:00:00Z",
                payload={"nested": {"password": "do-not-store"}},
            )

    def test_explicit_redaction_is_allowed(self):
        build_diagnostic_evidence(
            source_tool="mikrotik.inventory.system_resource",
            collected_at="2026-09-14T00:00:00Z",
            payload={"private_key": "<redacted>"},
        )


if __name__ == "__main__":
    unittest.main()
