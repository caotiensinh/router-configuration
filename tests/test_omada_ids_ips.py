import unittest

from router_configuration.omada_ids_ips import IdsIpsContractError, build_ids_ips_plan


SOURCES = (
    "https://support.omadanetworks.com/en/document/111217/",
    "https://support.omadanetworks.com/en/document/131799/",
)


def plan(**overrides):
    values = {
        "controller_version": "6.3",
        "model": "ER-VERIFIED-FIXTURE",
        "hardware_version": "V1",
        "firmware": "1.0.0",
        "region": "JP",
        "mode": "IDS",
        "security_level": "HIGH",
        "effective_time": "always",
        "geo_enforcer": True,
        "source_refs": SOURCES,
        "verification_state": "VENDOR_DOCUMENT_VERIFIED",
    }
    values.update(overrides)
    return build_ids_ips_plan(**values)


class OmadaIdsIpsTests(unittest.TestCase):
    def test_ids_is_report_only_and_non_executable(self):
        data = plan().as_dict()
        self.assertTrue(data["ids_reports_only"])
        self.assertIsNone(data["ips_block_seconds"])
        self.assertFalse(data["executable"])
        self.assertTrue(data["throughput_reduction_warning"])

    def test_ips_records_vendor_documented_block_interval(self):
        data = plan(mode="IPS").as_dict()
        self.assertFalse(data["ids_reports_only"])
        self.assertEqual(data["ips_block_seconds"], 300)

    def test_unverified_applicability_fails_closed(self):
        with self.assertRaises(IdsIpsContractError):
            plan(verification_state="AI_INFERRED")

    def test_wildcard_scope_is_rejected(self):
        with self.assertRaises(IdsIpsContractError):
            plan(model="*")

    def test_secret_material_is_rejected(self):
        with self.assertRaises(IdsIpsContractError):
            plan(extra={"client_secret": "forbidden"})


if __name__ == "__main__":
    unittest.main()
