import unittest

from router_configuration.vendors.mikrotik.knowledge import MikroTikOfflineKnowledge
from router_configuration.vendors.mikrotik.reference_measure import measure_pre_post


class MikroTikReferenceMeasureTests(unittest.TestCase):
    def test_secure_internet_pre_post_uses_official_knowledge_rules(self):
        pre = {
            "routeros_version_recorded": True,
            "knowledge_version_recorded": True,
            "management_path_survives": True,
            "post_state_matches_desired": False,
            "established_related_preserved": True,
            "invalid_state_dropped": False,
            "unsolicited_wan_to_lan_denied": False,
            "wan_management_denied": False,
            "management_sources_restricted": False,
            "lan_can_reach_internet": True,
            "desired_state_idempotent": False,
        }
        post = {key: True for key in pre}
        comparison = measure_pre_post(
            intent_kind="secure_internet_gateway",
            pre_evidence=pre,
            post_evidence=post,
        )
        self.assertTrue(comparison.post_ready)
        self.assertIn("firewall.invalid", comparison.fixed)
        self.assertIn("management.wan", comparison.fixed)
        self.assertFalse(comparison.regressed)
        self.assertTrue(
            all(item.source_url.startswith("https://manual.mikrotik.com/") for item in comparison.post.results)
        )

    def test_missing_post_evidence_blocks_wireguard_completion(self):
        keys = {
            "routeros_version_recorded": True,
            "knowledge_version_recorded": True,
            "management_path_survives": True,
            "post_state_matches_desired": True,
            "wireguard_allowed_addresses_non_overlapping": True,
            "wireguard_handshake_recent": True,
            "site_lans_bidirectionally_reachable": True,
            "internet_default_route_remains_local": True,
            "undeclared_vpn_forwarding_denied": True,
        }
        comparison = measure_pre_post(
            intent_kind="site_to_site_wireguard",
            pre_evidence=keys,
            post_evidence=keys,
        )
        self.assertFalse(comparison.post_ready)
        self.assertIn("idempotency", comparison.remaining_nonconformant)

    def test_bundled_knowledge_contains_script_authorities(self):
        store = MikroTikOfflineKnowledge.bundled()
        self.assertEqual(store.get("cli-reference").topic, "syntax-authority")
        self.assertEqual(store.get("scripting-import-validation").topic, "script-validation")


if __name__ == "__main__":
    unittest.main()
