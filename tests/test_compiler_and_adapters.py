import unittest

from router_configuration.adapters.mikrotik import MikroTikReferenceAdapter
from router_configuration.m02_state_engine import StateEngine
from router_configuration.m03_config_compiler import ConfigCompiler
from router_configuration.m08_vendor_yamaha import YamahaAdapter
from router_configuration.m10_vendor_omada import (
    OmadaAdapter,
    OmadaApiSurface,
    OmadaCompatibility,
)


class CompilerTests(unittest.TestCase):
    def test_plaintext_secret_is_rejected(self):
        findings = ConfigCompiler().validate(
            {"vpn": {"private_key": "plaintext-value"}}
        )
        self.assertTrue(findings)

    def test_secret_reference_is_preserved_not_resolved(self):
        compiled = ConfigCompiler().compile(
            {"vpn": {"private_key": "vault://routers/rd01/wireguard"}}
        )
        self.assertEqual(len(compiled.fields), 1)
        self.assertTrue(compiled.fields[0].secret_reference)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.plan = StateEngine().build_plan(
            {"routing": {"policy": "wan10g"}},
            {"routing": {"policy": "wan1g"}},
        )

    def test_mikrotik_reference_adapter_is_dry_run_only(self):
        adapter = MikroTikReferenceAdapter()
        self.assertTrue(adapter.preflight(self.plan).ready)
        rendered = adapter.render_dry_run(self.plan)
        self.assertIn("routing.policy", rendered[0])

    def test_yamaha_rejects_wireguard_intent(self):
        plan = StateEngine().build_plan(
            {"vpn": {"wireguard": {"enabled": True}}},
            {"vpn": {"wireguard": {"enabled": False}}},
        )
        decision = YamahaAdapter().preflight(plan)
        self.assertFalse(decision.ready)

    def test_omada_experimental_surface_is_blocked_in_production(self):
        compatibility = OmadaCompatibility(
            controller_version="6.x",
            official_features=frozenset({"routing", "wan", "vpn"}),
        )
        with self.assertRaises(ValueError):
            OmadaAdapter(
                compatibility,
                surface=OmadaApiSurface.EXPERIMENTAL,
                production=True,
            )

    def test_omada_capability_map_blocks_unknown_root(self):
        compatibility = OmadaCompatibility(
            controller_version="6.x",
            official_features=frozenset({"wan"}),
        )
        decision = OmadaAdapter(compatibility).preflight(self.plan)
        self.assertFalse(decision.ready)


if __name__ == "__main__":
    unittest.main()
