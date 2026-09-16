import unittest

from router_configuration.vendors.cisco.c08_validator_registry import (
    CiscoC08ValidatorRegistryError,
    build_validator_registry,
    validate_with_registry,
)


def valid(payload):
    return {"validated": payload.get("value") == 7, "apply_authorized": False}


class CiscoC08ValidatorRegistryTests(unittest.TestCase):
    def test_exact_feature_dispatch_is_deterministic_and_non_authorizing(self):
        registry = build_validator_registry([("interface.example.set", valid)])
        first = validate_with_registry("interface.example.set", {"value": 7}, registry=registry)
        second = validate_with_registry("interface.example.set", {"value": 7}, registry=registry)
        self.assertEqual(first, second)
        self.assertTrue(first["validation_result"]["validated"])
        self.assertFalse(first["apply_authorized"])
        self.assertFalse(first["production_write_authorized"])
        self.assertEqual(len(first["dispatch_record_sha256"]), 64)

    def test_duplicate_unknown_and_malformed_features_fail_closed(self):
        with self.assertRaisesRegex(CiscoC08ValidatorRegistryError, "duplicate"):
            build_validator_registry([("interface.example.set", valid), ("interface.example.set", valid)])
        registry = build_validator_registry([("interface.example.set", valid)])
        with self.assertRaisesRegex(CiscoC08ValidatorRegistryError, "no validator"):
            validate_with_registry("interface.unknown.set", {}, registry=registry)
        with self.assertRaisesRegex(CiscoC08ValidatorRegistryError, "invalid feature"):
            validate_with_registry("BAD FEATURE", {}, registry=registry)

    def test_validator_cannot_grant_apply_or_production_authority(self):
        for field in ("apply_authorized", "production_write_authorized"):
            def unsafe(_payload, field=field):
                return {field: True}
            registry = build_validator_registry([("interface.example.set", unsafe)])
            with self.assertRaisesRegex(CiscoC08ValidatorRegistryError, "pre-write boundary"):
                validate_with_registry("interface.example.set", {}, registry=registry)

    def test_non_mapping_or_non_json_result_fails_closed(self):
        registry = build_validator_registry([("interface.example.set", lambda _: ["bad"])])
        with self.assertRaisesRegex(CiscoC08ValidatorRegistryError, "mapping"):
            validate_with_registry("interface.example.set", {}, registry=registry)
        registry = build_validator_registry([("interface.example.set", lambda _: {"bad": {1, 2}})])
        with self.assertRaisesRegex(CiscoC08ValidatorRegistryError, "canonical JSON"):
            validate_with_registry("interface.example.set", {}, registry=registry)


if __name__ == "__main__":
    unittest.main()
