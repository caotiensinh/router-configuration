import unittest

from router_configuration.vendors.cisco.physical_acceptance import (
    CiscoPhysicalAcceptanceError,
    load_physical_acceptance_catalog,
    physical_acceptance_catalog_digest,
    validate_physical_readonly_claim,
)

D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
SOURCE_SHA = "a" * 40


class CiscoPhysicalAcceptanceTests(unittest.TestCase):
    def _claim(self, **overrides):
        values = dict(
            target_kind="physical_switch",
            model="C9300-24T",
            iosxe_version="17.18.1a",
            transport="netconf",
            source_sha=SOURCE_SHA,
            schema_inventory_digest_sha256=D1,
            observation_digest_sha256=D2,
            target_identity_digest_sha256=D3,
            human_attestation_digest_sha256=D4,
            evidence_origin="operator_attested_physical_iosxe",
            human_attested=True,
            read_only=True,
            write_attempted=False,
            virtualization=False,
        )
        values.update(overrides)
        return validate_physical_readonly_claim(**values)

    def test_catalog_keeps_physical_gate_human_only(self):
        catalog = load_physical_acceptance_catalog()
        self.assertTrue(catalog["human_attestation_required"])
        self.assertTrue(catalog["read_only_required"])
        self.assertFalse(catalog["synthetic_fixture_can_complete_c11"])
        self.assertFalse(catalog["virtual_evidence_can_complete_c11"])
        self.assertFalse(catalog["automatic_physical_device_verification"])
        self.assertFalse(catalog["production_write_authorized"])
        self.assertEqual(len(physical_acceptance_catalog_digest()), 64)

    def test_valid_switch_claim_is_only_eligible_for_human_review(self):
        first = self._claim()
        second = self._claim()
        self.assertEqual(first.contract_digest_sha256, second.contract_digest_sha256)
        self.assertEqual(first.role, "switch")
        self.assertEqual(first.platform_family, "Catalyst 9300")
        self.assertTrue(first.eligible_for_human_acceptance)
        self.assertFalse(first.synthetic_fixture_can_complete_c11)
        self.assertFalse(first.c11_complete)
        self.assertFalse(first.physical_device_verified)
        self.assertFalse(first.production_write_authorized)

    def test_physical_router_and_restconf_are_admitted(self):
        claim = self._claim(
            target_kind="physical_router",
            model="C8200-1N-4T",
            iosxe_version="26.1.1",
            transport="restconf",
        )
        self.assertEqual(claim.role, "router")
        self.assertEqual(claim.platform_family, "Catalyst 8200")
        self.assertEqual(claim.transport, "restconf")

    def test_virtual_platform_family_cannot_be_labeled_physical(self):
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "virtual platform family"):
            self._claim(target_kind="physical_router", model="C8000V", iosxe_version="26.1.1")

    def test_virtualization_is_rejected(self):
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "virtual evidence"):
            self._claim(virtualization=True)

    def test_missing_human_attestation_is_rejected(self):
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "human attestation"):
            self._claim(human_attested=False)
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "operator-attested"):
            self._claim(evidence_origin="synthetic_fixture")

    def test_write_attempt_or_non_readonly_session_is_rejected(self):
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "read-only"):
            self._claim(write_attempted=True)
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "read-only"):
            self._claim(read_only=False)

    def test_target_kind_must_match_admitted_role(self):
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "conflicts"):
            self._claim(target_kind="physical_router")
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "target_kind"):
            self._claim(target_kind="virtual_switch")

    def test_unknown_platform_or_version_fails_closed(self):
        with self.assertRaises(CiscoPhysicalAcceptanceError):
            self._claim(model="UNKNOWN-BOX")
        with self.assertRaises(CiscoPhysicalAcceptanceError):
            self._claim(iosxe_version="17.17.1")

    def test_only_readonly_transports_are_admitted(self):
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "transport"):
            self._claim(transport="ssh-cli")

    def test_all_identity_and_evidence_digests_are_required(self):
        for field in (
            "schema_inventory_digest_sha256",
            "observation_digest_sha256",
            "target_identity_digest_sha256",
            "human_attestation_digest_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "sha256"):
                    self._claim(**{field: "bad"})

    def test_exact_source_sha_is_required(self):
        with self.assertRaisesRegex(CiscoPhysicalAcceptanceError, "40-character"):
            self._claim(source_sha="short")

    def test_contract_digest_changes_when_evidence_identity_changes(self):
        first = self._claim()
        second = self._claim(observation_digest_sha256="5" * 64)
        self.assertNotEqual(first.contract_digest_sha256, second.contract_digest_sha256)


if __name__ == "__main__":
    unittest.main()
