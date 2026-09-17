import unittest

from router_configuration.vendors.cisco import (
    CiscoDeviceRole,
    CiscoOfflineKnowledge,
    assess_read_only_candidate,
    classify_platform,
    documentation_train,
)


class CiscoIOSXEDomainTests(unittest.TestCase):
    def test_router_and_switch_families_are_isolated(self) -> None:
        router = classify_platform("C8300-2N2S-6T")
        switch = classify_platform("C9300-24T")

        self.assertIsNotNone(router)
        self.assertEqual(router.role, CiscoDeviceRole.ROUTER)
        self.assertEqual(router.family, "Catalyst 8300")

        self.assertIsNotNone(switch)
        self.assertEqual(switch.role, CiscoDeviceRole.SWITCH)
        self.assertEqual(switch.family, "Catalyst 9300")

    def test_other_cisco_operating_system_families_do_not_cross_admit(self) -> None:
        self.assertIsNone(classify_platform("N9K-C93180YC-FX"))
        self.assertIsNone(classify_platform("NCS-540"))

    def test_documentation_train_is_fail_closed(self) -> None:
        self.assertEqual(documentation_train("17.18.1a"), "17.18")
        self.assertEqual(documentation_train("26.1.1"), "26")
        self.assertIsNone(documentation_train("17.12.4"))
        self.assertIsNone(documentation_train("unknown"))

    def test_documented_candidate_never_implies_write_authority(self) -> None:
        decision = assess_read_only_candidate("C9300-48P", "26.1.1")
        self.assertEqual(decision.status, "DOCUMENTED_READ_ONLY_CANDIDATE")
        self.assertTrue(decision.read_only_candidate)
        self.assertFalse(decision.write_authorized)
        self.assertFalse(decision.physical_device_verified)

    def test_unknown_platform_and_version_fail_closed(self) -> None:
        platform = assess_read_only_candidate("ISR4451-X", "17.18.1")
        version = assess_read_only_candidate("C9300-24T", "17.12.4")

        self.assertEqual(platform.status, "UNVERIFIED_PLATFORM")
        self.assertFalse(platform.read_only_candidate)
        self.assertEqual(version.status, "UNVERIFIED_VERSION")
        self.assertFalse(version.read_only_candidate)

    def test_offline_manifest_uses_only_official_cisco_sources(self) -> None:
        knowledge = CiscoOfflineKnowledge()
        self.assertGreaterEqual(len(knowledge.source_ids()), 6)
        for source_id in knowledge.source_ids():
            source = knowledge.source(source_id)
            self.assertEqual(source.authority, "official_cisco")
            self.assertTrue(source.url.startswith("https://www.cisco.com/"))

    def test_platform_matrix_retains_safety_boundaries(self) -> None:
        knowledge = CiscoOfflineKnowledge()
        matrix = knowledge.platform_matrix
        boundaries = matrix["boundaries"]

        self.assertFalse(boundaries["nx_os_in_scope"])
        self.assertFalse(boundaries["ios_xr_in_scope"])
        self.assertFalse(boundaries["production_write_authorized"])
        self.assertFalse(boundaries["physical_device_verified"])
        self.assertFalse(boundaries["automatic_feature_support_inference"])

        roles = {entry["role"] for entry in matrix["families"]}
        self.assertEqual(roles, {"router", "switch"})

    def test_offline_knowledge_digest_is_deterministic(self) -> None:
        first = CiscoOfflineKnowledge().digest_sha256
        second = CiscoOfflineKnowledge().digest_sha256
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)


if __name__ == "__main__":
    unittest.main()
