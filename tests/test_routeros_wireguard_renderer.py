import copy
import hashlib
import json
import unittest
from pathlib import Path

from router_configuration.routeros_wireguard_renderer import (
    PRIVATE_KEY_PLACEHOLDER,
    RouterOSWireGuardRenderError,
    render_routeros_wireguard,
)
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KEY_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
PUBLIC_KEY_B = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="


def wireguard_ir(*, peers=None):
    if peers is None:
        peers = [
            {
                "name": "branch-a",
                "public_key": PUBLIC_KEY_A,
                "tunnel_address": "10.250.0.2/32",
                "allowed_addresses": ["10.250.0.2/32", "10.40.0.0/24"],
                "routes": ["10.40.0.0/24"],
                "endpoint_address": "198.51.100.10",
                "endpoint_port": 51820,
                "persistent_keepalive": 25,
                "responder": False,
            },
            {
                "name": "branch-b",
                "public_key": PUBLIC_KEY_B,
                "tunnel_address": "10.250.0.3/32",
                "allowed_addresses": ["10.250.0.3/32", "10.50.0.0/24"],
                "routes": ["10.50.0.0/24"],
                "responder": True,
            },
        ]
    return SafeSubsetIR(
        device_id="chr-wireguard-lab",
        operations=(
            IntentOperation(
                operation_id="vpn.wireguard",
                feature="vpn",
                resource="wireguard_policy",
                attributes={
                    "enabled": True,
                    "name": "wg-enterprise",
                    "addresses": ["10.250.0.1/24"],
                    "listen_port": 51820,
                    "mtu": 1420,
                    "peers": peers,
                },
                risk=IntentRisk.HIGH,
                requires=("wireguard", "firewall", "management_path"),
                secret_references=("vault://routers/rd-router-01/wireguard-private-key",),
            ),
        ),
    ).as_dict()


def resign(payload):
    unsigned = copy.deepcopy(payload)
    unsigned.pop("ir_sha256", None)
    payload["ir_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return payload


class RouterOSWireGuardRendererTests(unittest.TestCase):
    def test_plan_is_deterministic_and_secret_binding_remains_unresolved(self):
        first = render_routeros_wireguard(ir=wireguard_ir()).as_dict()
        second = render_routeros_wireguard(ir=wireguard_ir()).as_dict()
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], "routeros-wireguard-template-plan/1")
        self.assertEqual(first["scope"], "generation_only_deferred_secret_binding")
        self.assertFalse(first["secrets_resolved"])
        self.assertFalse(first["transport_present"])
        self.assertFalse(first["apply_available"])
        self.assertFalse(first["write_authorized"])
        binding = first["secret_bindings"][PRIVATE_KEY_PLACEHOLDER]
        self.assertEqual(binding["reference"], "vault://routers/rd-router-01/wireguard-private-key")
        self.assertFalse(binding["resolved"])

        templates = [item["template"] for item in first["command_templates"]]
        rendered = "\n".join(templates)
        self.assertIn(PRIVATE_KEY_PLACEHOLDER, rendered)
        self.assertNotIn("vault://", rendered)
        self.assertNotIn("ROUTEROS_PASSWORD", rendered)

    def test_routeros_templates_cover_interface_addresses_peers_and_explicit_routes(self):
        plan = render_routeros_wireguard(ir=wireguard_ir()).as_dict()
        ids = [item["command_id"] for item in plan["command_templates"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids[0], "wireguard.10.interface")
        self.assertEqual(sum(item["section"] == "wireguard_address" for item in plan["command_templates"]), 1)
        self.assertEqual(sum(item["section"] == "wireguard_peer" for item in plan["command_templates"]), 2)
        self.assertEqual(sum(item["section"] == "wireguard_route" for item in plan["command_templates"]), 2)
        source = "\n".join(item["template"] for item in plan["command_templates"])
        self.assertIn('/interface/wireguard/add name="wg-enterprise"', source)
        self.assertIn('allowed-address="10.250.0.2/32,10.40.0.0/24"', source)
        self.assertIn('endpoint-address="198.51.100.10" endpoint-port=51820', source)
        self.assertIn('gateway="wg-enterprise"', source)

    def test_unbounded_allowed_address_is_rejected(self):
        peers = [
            {
                "name": "branch-a",
                "public_key": PUBLIC_KEY_A,
                "tunnel_address": "10.250.0.2/32",
                "allowed_addresses": ["10.250.0.2/32", "0.0.0.0/0"],
                "routes": [],
            }
        ]
        with self.assertRaisesRegex(RouterOSWireGuardRenderError, "bounded IPv4 CIDR"):
            render_routeros_wireguard(ir=wireguard_ir(peers=peers))

    def test_allowed_address_overlap_between_peers_is_rejected(self):
        peers = [
            {
                "name": "branch-a",
                "public_key": PUBLIC_KEY_A,
                "tunnel_address": "10.250.0.2/32",
                "allowed_addresses": ["10.250.0.2/32", "10.40.0.0/24"],
                "routes": [],
            },
            {
                "name": "branch-b",
                "public_key": PUBLIC_KEY_B,
                "tunnel_address": "10.250.0.3/32",
                "allowed_addresses": ["10.250.0.3/32", "10.40.0.128/25"],
                "routes": [],
            },
        ]
        with self.assertRaisesRegex(RouterOSWireGuardRenderError, "overlap"):
            render_routeros_wireguard(ir=wireguard_ir(peers=peers))

    def test_route_must_be_contained_by_same_peers_allowed_addresses(self):
        peers = [
            {
                "name": "branch-a",
                "public_key": PUBLIC_KEY_A,
                "tunnel_address": "10.250.0.2/32",
                "allowed_addresses": ["10.250.0.2/32", "10.40.0.0/24"],
                "routes": ["10.60.0.0/24"],
            }
        ]
        with self.assertRaisesRegex(RouterOSWireGuardRenderError, "contained"):
            render_routeros_wireguard(ir=wireguard_ir(peers=peers))

    def test_tunnel_address_must_be_remote_host_inside_interface_subnet(self):
        peers = [
            {
                "name": "branch-a",
                "public_key": PUBLIC_KEY_A,
                "tunnel_address": "10.251.0.2/32",
                "allowed_addresses": ["10.251.0.2/32"],
                "routes": [],
            }
        ]
        with self.assertRaisesRegex(RouterOSWireGuardRenderError, "inside a configured WireGuard interface subnet"):
            render_routeros_wireguard(ir=wireguard_ir(peers=peers))

    def test_invalid_public_key_and_tampered_ir_are_rejected(self):
        payload = wireguard_ir()
        payload["operations"][0]["attributes"]["peers"][0]["public_key"] = "not-a-key"
        resign(payload)
        with self.assertRaisesRegex(RouterOSWireGuardRenderError, "base64"):
            render_routeros_wireguard(ir=payload)

        payload = wireguard_ir()
        payload["operations"][0]["attributes"]["listen_port"] = 9999
        with self.assertRaisesRegex(RouterOSWireGuardRenderError, "digest mismatch"):
            render_routeros_wireguard(ir=payload)

    def test_renderer_source_has_no_transport_or_secret_resolver(self):
        source = (ROOT / "src" / "router_configuration" / "routeros_wireguard_renderer.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "urllib.request",
            "requests.",
            "http.client",
            "paramiko",
            "socket.",
            "subprocess",
            "vault.read",
            "keyring.get",
            "def apply(",
            "def execute(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
