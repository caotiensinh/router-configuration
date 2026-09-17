import json
import unittest

from router_configuration.vendors.cisco.physical_acceptance import CiscoPhysicalAcceptanceError
from router_configuration.vendors.cisco.physical_evidence_ingest import (
    CiscoPhysicalEvidenceIngestError,
    ingest_physical_readonly_evidence_json,
)


def fixture(**overrides):
    payload = {
        "schema_version": "cisco-c11-physical-readonly-evidence/1",
        "target_kind": "physical_switch",
        "model": "C9300-24T",
        "iosxe_version": "17.18.1a",
        "transport": "netconf",
        "source_sha": "a" * 40,
        "source_run_id": "run-c11-001",
        "schema_inventory_digest_sha256": "1" * 64,
        "observation_digest_sha256": "2" * 64,
        "target_identity_digest_sha256": "3" * 64,
        "human_attestation_digest_sha256": "4" * 64,
        "evidence_origin": "operator_attested_physical_iosxe",
        "human_attested": True,
        "read_only": True,
        "write_attempted": False,
        "virtualization": False,
        "repository_physical_evidence_accepted": False,
        "c11_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    payload.update(overrides)
    return payload


class CiscoPhysicalEvidenceIngestTests(unittest.TestCase):
    def test_valid_candidate_is_only_eligible_for_human_acceptance(self):
        raw = json.dumps(fixture(), sort_keys=True)
        first = ingest_physical_readonly_evidence_json(raw)
        second = ingest_physical_readonly_evidence_json(raw)
        self.assertEqual(first, second)
        self.assertTrue(first["eligible_for_human_acceptance"])
        self.assertFalse(first["repository_physical_evidence_accepted"])
        self.assertFalse(first["c11_complete"])
        self.assertFalse(first["physical_device_verified"])
        self.assertFalse(first["production_write_authorized"])
        self.assertEqual(len(first["ingest_record_sha256"]), 64)

    def test_duplicate_unknown_and_missing_fields_fail_closed(self):
        raw = json.dumps(fixture())[:-1] + ',"model":"C9500-24Y4C"}'
        with self.assertRaisesRegex(CiscoPhysicalEvidenceIngestError, "duplicate JSON key"):
            ingest_physical_readonly_evidence_json(raw)
        item = fixture(extra_field=True)
        with self.assertRaisesRegex(CiscoPhysicalEvidenceIngestError, "unknown C11"):
            ingest_physical_readonly_evidence_json(json.dumps(item))
        item = fixture()
        del item["transport"]
        with self.assertRaisesRegex(CiscoPhysicalEvidenceIngestError, "missing C11"):
            ingest_physical_readonly_evidence_json(json.dumps(item))

    def test_self_promotion_is_rejected(self):
        for field in (
            "repository_physical_evidence_accepted",
            "c11_complete",
            "physical_device_verified",
            "production_write_authorized",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CiscoPhysicalEvidenceIngestError, "cannot self-promote"):
                    ingest_physical_readonly_evidence_json(json.dumps(fixture(**{field: True})))

    def test_virtual_platform_family_is_rejected_even_when_flag_is_false(self):
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "virtual platform family"):
            ingest_physical_readonly_evidence_json(json.dumps(fixture(
                target_kind="physical_router",
                model="C8000V",
                iosxe_version="26.1.1",
            )))

    def test_physical_router_model_is_admitted(self):
        result = ingest_physical_readonly_evidence_json(json.dumps(fixture(
            target_kind="physical_router",
            model="C8200-1N-4T",
            iosxe_version="26.1.1",
            transport="restconf",
        )))
        self.assertEqual(result["platform_family"], "Catalyst 8200")
        self.assertEqual(result["role"], "router")

    def test_sensitive_unknown_metadata_is_rejected(self):
        item = fixture()
        item["password"] = "should-not-exist"
        with self.assertRaises(CiscoPhysicalEvidenceIngestError):
            ingest_physical_readonly_evidence_json(json.dumps(item))

    def test_readonly_human_attestation_and_nonvirtual_semantics_are_required(self):
        bad_cases = (
            {"human_attested": False},
            {"read_only": False},
            {"write_attempted": True},
            {"virtualization": True},
            {"evidence_origin": "synthetic_fixture"},
        )
        for override in bad_cases:
            with self.subTest(override=override):
                with self.assertRaises(Exception):
                    ingest_physical_readonly_evidence_json(json.dumps(fixture(**override)))

    def test_input_type_utf8_size_and_source_run_id_are_bounded(self):
        with self.assertRaises(CiscoPhysicalEvidenceIngestError):
            ingest_physical_readonly_evidence_json(123)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CiscoPhysicalEvidenceIngestError, "strict UTF-8"):
            ingest_physical_readonly_evidence_json(b"\xff")
        with self.assertRaisesRegex(CiscoPhysicalEvidenceIngestError, "source_run_id"):
            ingest_physical_readonly_evidence_json(json.dumps(fixture(source_run_id="bad run id\n")))


if __name__ == "__main__":
    unittest.main()
