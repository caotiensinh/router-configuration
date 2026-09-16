import copy
import unittest

from router_configuration.vendors.cisco.c12_handover_manifest import (
    CiscoC12HandoverManifestError,
    build_c12_handover_manifest,
)


def stages():
    result = {}
    for index, stage in enumerate(("c06", "c07", "c08", "c09", "c10", "c11"), start=1):
        result[stage] = {
            "complete": True,
            "evidence_sha256": f"{index:x}" * 64,
            "production_write_authorized": False,
        }
    result["c11"]["physical_device_verified"] = True
    return result


class CiscoC12HandoverManifestTests(unittest.TestCase):
    def test_ready_manifest_never_completes_c12_or_authorizes_write(self):
        result = build_c12_handover_manifest(
            stages(),
            handover_id="HO-C12-001",
            owner_ref="ops:owner-01",
        )
        self.assertTrue(result["ready_for_c12_human_review"])
        self.assertFalse(result["c12_complete"])
        self.assertFalse(result["production_writer_available"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(set(result["stage_evidence_sha256"]), {"c06", "c07", "c08", "c09", "c10", "c11"})
        self.assertEqual(len(result["manifest_sha256"]), 64)

    def test_incomplete_stage_is_rejected(self):
        item = stages()
        item["c10"]["complete"] = False
        with self.assertRaisesRegex(CiscoC12HandoverManifestError, "C10 is not complete"):
            build_c12_handover_manifest(item, handover_id="HO-C12-001", owner_ref="ops:owner-01")

    def test_c11_requires_physical_verification(self):
        item = stages()
        item["c11"]["physical_device_verified"] = False
        with self.assertRaisesRegex(CiscoC12HandoverManifestError, "physical device verification"):
            build_c12_handover_manifest(item, handover_id="HO-C12-001", owner_ref="ops:owner-01")

    def test_stage_write_authority_is_rejected(self):
        item = stages()
        item["c09"]["production_write_authorized"] = True
        with self.assertRaisesRegex(CiscoC12HandoverManifestError, "production write authority"):
            build_c12_handover_manifest(item, handover_id="HO-C12-001", owner_ref="ops:owner-01")


if __name__ == "__main__":
    unittest.main()
