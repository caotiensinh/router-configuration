import hashlib
import json
import unittest

from router_configuration.vendors.cisco.netconf_evidence_redaction import (
    CiscoNetconfRedactionError,
    redact_live_netconf_evidence,
)


def canonical_sha256(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def successful_evidence():
    item = {
        "schema_version": "cisco-c03-live-evidence/1",
        "source_sha": "1" * 40,
        "stage": "live_readonly_verified",
        "live_target_observed": True,
        "hostkey_verified": True,
        "write_operations_performed": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
        "c03_complete": True,
        "target_host": "10.0.0.10",
        "target_port": 830,
        "hostname": "lab-rtr-01",
        "session_id": 77,
        "required_models_present": True,
        "missing_required_models": [],
        "iosxe_version": "17.18.1a",
        "admitted_model": "C8000V",
        "interface_count": 2,
    }
    item["evidence_digest_sha256"] = canonical_sha256(item)
    return item


class CiscoNetconfEvidenceRedactionTests(unittest.TestCase):
    def test_successful_probe_is_redacted_deterministically(self):
        evidence = successful_evidence()
        first = redact_live_netconf_evidence(evidence)
        second = redact_live_netconf_evidence(evidence)
        self.assertEqual(first, second)
        self.assertNotIn("target_host", first)
        self.assertNotIn("hostname", first)
        self.assertNotIn("session_id", first)
        self.assertEqual(first["target_host_digest_sha256"], hashlib.sha256(b"10.0.0.10").hexdigest())
        self.assertEqual(first["hostname_digest_sha256"], hashlib.sha256(b"lab-rtr-01").hexdigest())
        self.assertTrue(first["runtime_identity_redacted"])
        self.assertFalse(first["repository_c03_complete"])
        self.assertFalse(first["repository_evidence_accepted"])
        self.assertEqual(len(first["repository_record_sha256"]), 64)

    def test_tampered_probe_digest_is_rejected(self):
        evidence = successful_evidence()
        evidence["hostname"] = "tampered"
        with self.assertRaisesRegex(CiscoNetconfRedactionError, "digest mismatch"):
            redact_live_netconf_evidence(evidence)

    def test_unsuccessful_or_unsafe_probe_is_rejected(self):
        evidence = successful_evidence()
        evidence["c03_complete"] = False
        evidence["evidence_digest_sha256"] = canonical_sha256({k: v for k, v in evidence.items() if k != "evidence_digest_sha256"})
        with self.assertRaises(CiscoNetconfRedactionError):
            redact_live_netconf_evidence(evidence)

        evidence = successful_evidence()
        evidence["production_write_authorized"] = True
        evidence["evidence_digest_sha256"] = canonical_sha256({k: v for k, v in evidence.items() if k != "evidence_digest_sha256"})
        with self.assertRaisesRegex(CiscoNetconfRedactionError, "safety boundary"):
            redact_live_netconf_evidence(evidence)

    def test_sensitive_key_is_rejected_recursively(self):
        evidence = successful_evidence()
        evidence["nested"] = {"api_token": "x"}
        evidence["evidence_digest_sha256"] = canonical_sha256({k: v for k, v in evidence.items() if k != "evidence_digest_sha256"})
        with self.assertRaisesRegex(CiscoNetconfRedactionError, "sensitive key"):
            redact_live_netconf_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
