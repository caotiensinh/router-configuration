import unittest

from router_configuration.mikrotik_intent import (
    MikroTikIntentError,
    compile_mikrotik_operator_intent,
    compile_secure_internet_gateway,
    compile_site_to_site_wireguard,
)


class MikroTikIntentTests(unittest.TestCase):
    def test_secure_internet_compiles_human_goal_to_safe_policy(self):
        plan = compile_secure_internet_gateway(
            {
                "lan_cidr": "192.168.10.0/24",
                "lan_interface": "bridge-lan",
                "wan_interface": "ether1",
                "wan_addressing": "dhcp",
                "credential_ref": "env://ROUTEROS_PASSWORD",
            }
        ).as_dict()
        self.assertEqual(plan["kind"], "secure_internet_gateway")
        self.assertEqual(plan["facts"]["lan_cidr"], "192.168.10.0/24")
        self.assertEqual(plan["derived_policy"]["wan_to_lan_unsolicited"], "deny")
        self.assertEqual(plan["derived_policy"]["wan_to_router_management"], "deny")
        self.assertEqual(plan["derived_policy"]["wan_echo_request"], "deny")
        self.assertEqual(
            plan["derived_policy"]["icmp_control_errors"],
            "preserve_required_ipv4_control_messages",
        )
        self.assertFalse(plan["write_authorized"])
        self.assertFalse(plan["vendor_commands_present"])
        self.assertFalse(plan["transport_present"])
        self.assertEqual(plan["secret_references"], ["env://ROUTEROS_PASSWORD"])
        self.assertFalse(any("config." in name for name in plan["tool_names"]))

    def test_static_wan_is_blocked_until_required_facts_exist(self):
        plan = compile_secure_internet_gateway(
            {
                "lan_cidr": "192.168.10.0/24",
                "lan_interface": "bridge-lan",
                "wan_interface": "ether1",
                "wan_addressing": "static",
            }
        )
        self.assertFalse(plan.ready_for_planning)
        self.assertIn("static WAN requires wan_address", plan.blockers)
        self.assertIn("static WAN requires wan_gateway", plan.blockers)

    def test_plaintext_credential_is_refused(self):
        with self.assertRaisesRegex(MikroTikIntentError, "secret reference"):
            compile_secure_internet_gateway(
                {
                    "lan_cidr": "192.168.10.0/24",
                    "lan_interface": "bridge-lan",
                    "wan_interface": "ether1",
                    "credential_ref": "admin-password",
                }
            )

    def test_site_to_site_derives_no_default_route_and_auto_key_policy(self):
        plan = compile_site_to_site_wireguard(
            {
                "local_site_id": "tokyo",
                "remote_site_id": "nagoya",
                "local_lan_cidr": "192.168.10.0/24",
                "remote_lan_cidr": "192.168.20.0/24",
                "local_credential_ref": "vault://routers/tokyo",
                "remote_credential_ref": "vault://routers/nagoya",
            }
        ).as_dict()
        self.assertFalse(plan["derived_policy"]["default_route_over_vpn"])
        self.assertEqual(plan["derived_policy"]["internet_breakout"], "local_at_each_site")
        self.assertIn("generate_unique_keypair", plan["derived_policy"]["key_management"])
        self.assertIn("WireGuard_handshake_is_recent", plan["verification"])
        self.assertFalse(any("config." in name for name in plan["tool_names"]))

    def test_site_to_site_refuses_overlapping_lans(self):
        with self.assertRaisesRegex(MikroTikIntentError, "overlap"):
            compile_site_to_site_wireguard(
                {
                    "local_site_id": "a",
                    "remote_site_id": "b",
                    "local_lan_cidr": "192.168.1.0/24",
                    "remote_lan_cidr": "192.168.1.128/25",
                }
            )

    def test_dispatcher_rejects_unknown_intent(self):
        with self.assertRaisesRegex(MikroTikIntentError, "kind must be"):
            compile_mikrotik_operator_intent({"kind": "magic"})


if __name__ == "__main__":
    unittest.main()
