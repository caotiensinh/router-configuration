import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from router_configuration.cli import main


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


class ExtendedIRProductPathTests(unittest.TestCase):
    def test_profile_compile_ir_emits_vlan_and_pbr_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = json.loads(PROFILE.read_text(encoding="utf-8"))
            profile["intent"]["segmentation"] = {
                "enabled": True,
                "bridge": "br-lan",
                "vlans": [
                    {"id": 10, "name": "management"},
                    {"id": 20, "name": "users"},
                ],
                "ports": [
                    {
                        "interface": "ether5",
                        "mode": "access",
                        "access_vlan": 20,
                    },
                    {
                        "interface": "sfp-sfpplus2",
                        "mode": "trunk",
                        "allowed_vlans": [10, 20],
                    },
                ],
                "management": {
                    "vlan_id": 10,
                    "port": "sfp-sfpplus2",
                    "address": "10.10.10.1/24",
                },
            }
            profile["intent"]["pbr"] = {
                "enabled": True,
                "strategy": "routing_rules",
                "rules": [
                    {
                        "name": "users-via-wan1g",
                        "source_cidr": "10.20.0.0/24",
                        "destination_cidr": "0.0.0.0/0",
                        "in_interface": "routercfg-users-vlan20",
                        "table": "to-wan1g",
                        "action": "lookup",
                    }
                ],
            }

            profile_path = Path(tmp) / "profile.json"
            output_path = Path(tmp) / "ir.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")

            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = main(
                    [
                        "profile-compile-ir",
                        "--profile",
                        str(profile_path),
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(rc, 0, stdout.getvalue())
            summary = json.loads(stdout.getvalue())
            self.assertTrue(summary["ok"])
            self.assertFalse(summary["vendor_commands_present"])
            self.assertFalse(summary["write_transport_present"])

            artifact = json.loads(output_path.read_text(encoding="utf-8"))
            operations = {
                item["operation_id"]: item for item in artifact["operations"]
            }
            self.assertIn("switching.vlan.segmentation", operations)
            self.assertIn("routing.pbr.rules", operations)
            self.assertEqual(
                operations["switching.vlan.segmentation"]["resource"],
                "vlan_segmentation_policy",
            )
            self.assertEqual(
                operations["routing.pbr.rules"]["resource"],
                "policy_routing_rules",
            )
            rendered = json.dumps(artifact, sort_keys=True)
            self.assertNotIn("/interface/bridge", rendered)
            self.assertNotIn("/routing/rule", rendered)
            self.assertNotIn("POST", rendered)
            self.assertNotIn("PATCH", rendered)
            self.assertNotIn("DELETE", rendered)


if __name__ == "__main__":
    unittest.main()
