import unittest

from router_configuration.omada_remote_access_vpn import RemoteAccessVpnError, build_remote_access_vpn_plan


class OmadaRemoteAccessVpn510Tests(unittest.TestCase):
    def base(self, **overrides):
        kwargs = dict(
            protocol="wireguard",
            model="ER-series",
            firmware="1.0.0",
            region="JP",
            controller_version="6.2",
            mode="controller",
            client_pool=["10.250.0.0/24"],
            protected_networks=["192.168.11.0/24"],
            credential_ref="secret://omada/vpn/client-1",
        )
        kwargs.update(overrides)
        return kwargs

    def test_plan_is_scoped_secret_safe_and_non_authorizing(self):
        plan = build_remote_access_vpn_plan(**self.base()).as_dict()
        self.assertEqual(plan["protocol"], "WIREGUARD")
        self.assertEqual(plan["mode"], "CONTROLLER")
        self.assertFalse(plan["write_authorized"])
        self.assertFalse(plan["hardware_verified"])
        self.assertTrue(plan["credential_ref"].startswith("secret://"))

    def test_client_pool_overlap_fails_closed(self):
        with self.assertRaises(RemoteAccessVpnError):
            build_remote_access_vpn_plan(**self.base(client_pool=["192.168.11.128/25"]))

    def test_plaintext_secret_fields_are_rejected(self):
        with self.assertRaises(RemoteAccessVpnError):
            build_remote_access_vpn_plan(**self.base(extra={"password": "do-not-store"}))

    def test_unknown_protocol_or_mode_fails_closed(self):
        with self.assertRaises(RemoteAccessVpnError):
            build_remote_access_vpn_plan(**self.base(protocol="magicvpn"))
        with self.assertRaises(RemoteAccessVpnError):
            build_remote_access_vpn_plan(**self.base(mode="cloud-magic"))


if __name__ == "__main__":
    unittest.main()
