import unittest

from router_configuration.verified_cli_registry import (
    VerifiedCliRegistry,
    VerifiedCliRegistryError,
    build_verified_cli_entry,
)


SOURCE_SHA = "a" * 64


def entry(**overrides):
    values = {
        "command_id": "omada.cli.test.001",
        "command": "verified vendor command placeholder",
        "operation": "READ_ONLY_CHECK",
        "mode": "privileged",
        "model": "MODEL-X",
        "hardware_version": "V1",
        "firmware": "1.2.3",
        "region": "JP",
        "source_url": "https://support.omadanetworks.com/en/document/111643/",
        "source_sha256": SOURCE_SHA,
        "source_locator": "section:verified-example",
        "verification_state": "VENDOR_DOCUMENT_VERIFIED",
    }
    values.update(overrides)
    return build_verified_cli_entry(**values)


class VerifiedCliRegistryTests(unittest.TestCase):
    def test_exact_verified_entry_can_be_looked_up(self):
        registry = VerifiedCliRegistry([entry()])
        found = registry.exact_lookup(
            "omada.cli.test.001",
            model="MODEL-X",
            hardware_version="V1",
            firmware="1.2.3",
            region="JP",
        )
        self.assertEqual(found.command_id, "omada.cli.test.001")
        self.assertFalse(found.as_dict()["executable"])
        self.assertFalse(registry.as_dict()["fallback_matching"])

    def test_sibling_or_version_fallback_is_forbidden(self):
        registry = VerifiedCliRegistry([entry()])
        with self.assertRaises(VerifiedCliRegistryError):
            registry.exact_lookup(
                "omada.cli.test.001",
                model="MODEL-Y",
                hardware_version="V1",
                firmware="1.2.3",
                region="JP",
            )

    def test_unverified_entry_is_rejected(self):
        with self.assertRaises(VerifiedCliRegistryError):
            entry(verification_state="AI_INFERRED")

    def test_wildcard_applicability_is_rejected(self):
        with self.assertRaises(VerifiedCliRegistryError):
            entry(model="*")

    def test_duplicate_command_id_is_rejected(self):
        item = entry()
        with self.assertRaises(VerifiedCliRegistryError):
            VerifiedCliRegistry([item, item])


if __name__ == "__main__":
    unittest.main()
