import unittest

from router_configuration.omada_portal_auth import PortalAuthError, build_portal_auth_plan


SOURCES = (
    "https://support.omadanetworks.com/en/document/111643/",
    "https://support.omadanetworks.com/us/document/12927/",
)


class OmadaPortalAuthTests(unittest.TestCase):
    def test_builds_document_bound_hotspot_plan(self):
        plan = build_portal_auth_plan(
            controller_version="6.2",
            target_kind="ssid",
            target_id="guest-wifi",
            authentication_type="hotspot_voucher",
            source_refs=SOURCES,
        ).as_dict()
        self.assertEqual(plan["authentication_type"], "HOTSPOT_VOUCHER")
        self.assertTrue(plan["controller_must_remain_online"])
        self.assertIsNone(plan["radius_vlan_assignment_supported"])
        self.assertFalse(plan["executable"])
        self.assertEqual(plan["evidence_class"], "VENDOR_DOCUMENT_VERIFIED")

    def test_radius_portal_records_documented_vlan_limit(self):
        plan = build_portal_auth_plan(
            controller_version="6.2",
            target_kind="lan",
            target_id="guest-lan",
            authentication_type="radius_server",
            source_refs=SOURCES,
        ).as_dict()
        self.assertFalse(plan["radius_vlan_assignment_supported"])

    def test_unknown_authentication_type_fails_closed(self):
        with self.assertRaises(PortalAuthError):
            build_portal_auth_plan(
                controller_version="6.2",
                target_kind="ssid",
                target_id="guest",
                authentication_type="magic-login",
                source_refs=SOURCES,
            )

    def test_secret_bearing_extra_is_rejected(self):
        with self.assertRaises(PortalAuthError):
            build_portal_auth_plan(
                controller_version="6.2",
                target_kind="ssid",
                target_id="guest",
                authentication_type="simple_password",
                source_refs=SOURCES,
                extra={"password": "do-not-store"},
            )

    def test_non_official_source_is_rejected(self):
        with self.assertRaises(PortalAuthError):
            build_portal_auth_plan(
                controller_version="6.2",
                target_kind="ssid",
                target_id="guest",
                authentication_type="hotspot_voucher",
                source_refs=("https://example.com/portal",),
            )


if __name__ == "__main__":
    unittest.main()
