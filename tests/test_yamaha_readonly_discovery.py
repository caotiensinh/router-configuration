import copy
import unittest

from router_configuration.vendors.yamaha import (
    YamahaOfflineKnowledge,
    YamahaReadOnlyEvidenceError,
    build_readonly_evidence,
    parse_environment_identity,
    validate_read_only_command,
    validate_readonly_evidence,
)


class YamahaRTX3510ReadOnlyDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.outputs = {
            "show environment": (
                "RTX3510 Rev.23.01.03\n"
                "CPU: 3%\n"
                "Memory: 22%\n"
                "Running firmware: exec0\n"
            ),
            "show arp": "192.0.2.10 00:11:22:33:44:55 lan1\n",
            "show ip route": "192.0.2.0/24 gateway 192.0.2.1 lan1\n",
            "show ip route detail": "192.0.2.0/24 gateway 192.0.2.1 lan1 metric 1\n",
            "show status lan1": "LAN1\nLink: Up\n",
            "show status lan2": "LAN2\nLink: Down\n",
            "show status lan3": "LAN3\nLink: Up\n",
            "show status lan4": "LAN4\nLink: Up\n",
        }

    def test_catalog_is_exact_fail_closed_and_source_bound(self) -> None:
        catalog = YamahaOfflineKnowledge().readonly_catalog
        self.assertEqual(catalog["model"], "RTX3510")
        self.assertEqual(catalog["firmware"], "23.01.03")
        self.assertFalse(catalog["write_authorized"])
        self.assertFalse(catalog["physical_device_verified"])
        self.assertEqual(len(catalog["queries"]), 8)
        for query in catalog["queries"]:
            self.assertTrue(query["command"].startswith("show "))
            self.assertTrue(query["secret_safe_scope"])
            self.assertTrue(query["source_ids"])

    def test_allowlist_accepts_only_documented_baseline_commands(self) -> None:
        for command in self.outputs:
            with self.subTest(command=command):
                decision = validate_read_only_command(command)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.status, "ALLOWED_READ_ONLY_COMMAND")
                self.assertFalse(decision.mutation)
                self.assertIsNotNone(decision.query_id)

    def test_whitespace_is_normalized_but_command_meaning_is_not_guessed(self) -> None:
        decision = validate_read_only_command("  show   ip   route  ")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_command, "show ip route")
        self.assertFalse(validate_read_only_command("SHOW IP ROUTE").allowed)

    def test_sensitive_or_mutating_commands_are_blocked(self) -> None:
        for command in (
            "show config",
            "show log",
            "show techinfo",
            "show status lan5",
            "show ip route | grep default",
            "save",
            "ip lan1 address 192.0.2.1/24",
        ):
            with self.subTest(command=command):
                decision = validate_read_only_command(command)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.status, "BLOCKED_UNVERIFIED_COMMAND")

    def test_environment_identity_requires_exact_admitted_model_and_firmware(self) -> None:
        identity = parse_environment_identity(self.outputs["show environment"])
        self.assertEqual(identity.model, "RTX3510")
        self.assertEqual(identity.firmware, "23.01.03")
        self.assertTrue(identity.read_only_candidate)
        self.assertFalse(identity.write_authorized)
        self.assertFalse(identity.physical_device_verified)

        with self.assertRaises(YamahaReadOnlyEvidenceError):
            parse_environment_identity("RTX3510 Rev.23.01.02\n")
        with self.assertRaises(YamahaReadOnlyEvidenceError):
            parse_environment_identity("RTX1300 Rev.23.01.03\n")

    def test_evidence_is_digest_bound_and_never_claims_live_hardware(self) -> None:
        record = build_readonly_evidence(self.outputs)
        validate_readonly_evidence(record)

        self.assertEqual(record["model"], "RTX3510")
        self.assertEqual(record["firmware"], "23.01.03")
        self.assertFalse(record["raw_outputs_embedded"])
        self.assertFalse(record["transport_verified"])
        self.assertFalse(record["least_privilege_verified"])
        self.assertFalse(record["live_device_verified"])
        self.assertFalse(record["physical_device_verified"])
        self.assertFalse(record["production_write_authorized"])
        self.assertEqual(len(record["record_sha256"]), 64)

    def test_required_discovery_coverage_is_enforced(self) -> None:
        incomplete = dict(self.outputs)
        incomplete.pop("show status lan4")
        with self.assertRaises(YamahaReadOnlyEvidenceError):
            build_readonly_evidence(incomplete)

    def test_unlisted_command_cannot_enter_evidence(self) -> None:
        outputs = dict(self.outputs)
        outputs["show config"] = "login user admin *\n"
        with self.assertRaises(YamahaReadOnlyEvidenceError):
            build_readonly_evidence(outputs)

    def test_evidence_tampering_is_rejected(self) -> None:
        record = build_readonly_evidence(self.outputs)
        tampered = copy.deepcopy(record)
        tampered["commands"][0]["output_bytes"] += 1
        with self.assertRaises(YamahaReadOnlyEvidenceError):
            validate_readonly_evidence(tampered)

    def test_evidence_cannot_self_promote_hardware_or_write_authority(self) -> None:
        record = build_readonly_evidence(self.outputs)
        for field in (
            "transport_verified",
            "least_privilege_verified",
            "live_device_verified",
            "physical_device_verified",
            "production_write_authorized",
        ):
            with self.subTest(field=field):
                overclaim = copy.deepcopy(record)
                overclaim[field] = True
                with self.assertRaises(YamahaReadOnlyEvidenceError):
                    validate_readonly_evidence(overclaim)


if __name__ == "__main__":
    unittest.main()
