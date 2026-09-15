import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ChrRouteLossContractTests(unittest.TestCase):
    def test_evaluator_accepts_default_route_loss_with_links_up(self):
        verifier = _load_module(
            "chr_route_loss_verifier",
            ROOT / "lab/chr/verify_route_loss_acceptance.py",
        )

        normal_rows = [
            {"comment": "routercfg:managed:default:lab-wan10g:a", "active": True},
            {"comment": "routercfg:managed:default:lab-wan10g:b", "active": True},
            {"comment": "routercfg:managed:default:lab-wan1g:a", "active": False},
            {"comment": "routercfg:managed:default:lab-wan1g:b", "active": False},
        ]
        loss_rows = [
            {"comment": "routercfg:managed:default:lab-wan10g:a", "active": False},
            {"comment": "routercfg:managed:default:lab-wan10g:b", "active": False},
            {"comment": "routercfg:managed:default:lab-wan1g:a", "active": True},
            {"comment": "routercfg:managed:default:lab-wan1g:b", "active": True},
        ]

        def flow(tag):
            return {
                "requested_flows": 30,
                "successful_flows": 30,
                "tags": {"WAN10": 30 if tag == "WAN10" else 0, "WAN1": 30 if tag == "WAN1" else 0},
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def dump(name, payload):
                path = root / name
                path.write_text(json.dumps(payload), encoding="utf-8")
                return path

            loss_control = {
                "ok": True,
                "acceptance": "PASS",
                "operation": "disable_preferred_defaults",
                "expected_after": "route_loss",
                "target_route_ids": ["*1", "*2"],
            }
            recovery_control = {
                "ok": True,
                "acceptance": "PASS",
                "operation": "restore_preferred_defaults",
                "expected_after": "recovered",
                "target_route_ids": ["*1", "*2"],
            }

            result = verifier.evaluate(
                flow_normal=dump("flow-normal.json", flow("WAN10")),
                flow_loss=dump("flow-loss.json", flow("WAN1")),
                flow_recovery=dump("flow-recovery.json", flow("WAN10")),
                routes_normal=dump("routes-normal.json", {"ok": True, "expected": "normal", "routes": normal_rows}),
                routes_loss=dump("routes-loss.json", {"ok": True, "expected": "wan10_failed", "routes": loss_rows}),
                routes_recovery=dump("routes-recovery.json", {"ok": True, "expected": "recovered", "routes": normal_rows}),
                loss_control=dump("loss-control.json", loss_control),
                recovery_control=dump("recovery-control.json", recovery_control),
                failure_interfaces=dump("interfaces.json", [{"name": "ether2", "running": "true"}]),
                host_link=dump("host-link.json", [{"ifname": "v-w10-br", "flags": ["UP", "LOWER_UP"]}]),
                namespace_link=dump("namespace-link.json", [{"ifname": "v-w10-ns", "flags": ["UP", "LOWER_UP"]}]),
                host_interface="v-w10-br",
                namespace_interface="v-w10-ns",
                output=root / "acceptance.json",
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["acceptance"], "PASS")
            self.assertTrue(result["semantics"]["preferred_default_routes_lost"])
            self.assertTrue(result["semantics"]["route_loss_flow_on_wan1"])
            self.assertTrue(result["semantics"]["same_routes_restored"])

    def test_control_state_requires_disabled_owned_static_routes(self):
        verifier = _load_module(
            "chr_route_loss_verifier_control",
            ROOT / "lab/chr/verify_route_loss_acceptance.py",
        )
        rows = [
            {"comment": "routercfg:managed:default:lab-wan10g:a", "active": False, "disabled": True, "dynamic": False},
            {"comment": "routercfg:managed:default:lab-wan10g:b", "active": False, "disabled": True, "dynamic": False},
            {"comment": "routercfg:managed:default:lab-wan1g:a", "active": True, "disabled": False, "dynamic": False},
            {"comment": "routercfg:managed:default:lab-wan1g:b", "active": True, "disabled": False, "dynamic": False},
        ]
        self.assertTrue(verifier._control_route_state(rows, "route_loss"))
        rows[0]["dynamic"] = True
        self.assertFalse(verifier._control_route_state(rows, "route_loss"))

    def test_wrapper_changes_only_route_state_not_link_or_upstream_loss(self):
        text = (ROOT / "lab/chr/run_route_loss_acceptance.sh").read_text(encoding="utf-8")
        self.assertIn("--disabled true", text)
        self.assertIn("--disabled false", text)
        self.assertIn("--expected wan10_failed", text)
        self.assertIn("flows-route-loss.json", text)
        self.assertIn("route-loss-routeros-interfaces.json", text)
        self.assertNotIn('ip link set "${V_WAN10_BR}" down', text)
        self.assertNotIn("tc qdisc replace", text)
        self.assertNotIn("dns_probe.py", text)

    def test_verifier_is_lab_only_and_owner_scoped(self):
        text = (ROOT / "lab/chr/verify_route_loss_acceptance.py").read_text(encoding="utf-8")
        self.assertIn("assert_disposable_chr", text)
        self.assertIn('routercfg:managed:default:', text)
        self.assertIn(':lab-wan10g:', text)
        self.assertIn('"PATCH"', text)
        self.assertIn('"production_writer_available": False', text)
        self.assertIn('"write_authorized": False', text)

    def test_workflow_is_opt_in_by_commit_prefix(self):
        text = (ROOT / ".github/workflows/chr-route-loss.yml").read_text(encoding="utf-8")
        self.assertIn("ci(chr-route-loss):", text)
        self.assertIn("run_route_loss_acceptance.sh", text)
        self.assertIn("chr-route-loss-${{ github.sha }}", text)


if __name__ == "__main__":
    unittest.main()
