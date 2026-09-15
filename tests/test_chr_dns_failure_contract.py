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


class ChrDNSFailureContractTests(unittest.TestCase):
    def test_dns_probe_round_trip_is_deterministic(self):
        probe = _load_module("chr_dns_probe", ROOT / "lab/chr/dns_probe.py")
        query = probe.build_query("routercfg.test")
        response = probe.build_response(query, answer_ip="192.0.2.53")
        self.assertEqual(
            probe.parse_response(response, expected_name="routercfg.test"),
            "192.0.2.53",
        )

    def test_evaluator_accepts_dns_only_failure_without_wan_failover(self):
        verifier = _load_module(
            "chr_dns_failure_verifier",
            ROOT / "lab/chr/verify_dns_failure_acceptance.py",
        )
        route_rows = [
            {"comment": "routercfg:managed:default:lab-wan10g:a", "active": True},
            {"comment": "routercfg:managed:default:lab-wan10g:b", "active": False},
            {"comment": "routercfg:managed:default:lab-wan1g:a", "active": False},
            {"comment": "routercfg:managed:default:lab-wan1g:b", "active": False},
        ]
        route = {"ok": True, "expected": "normal", "routes": route_rows}
        connectivity = {
            "requested_flows": 30,
            "successful_flows": 30,
            "tags": {"WAN10": 30, "WAN1": 0},
        }
        dns_ok = {
            "ok": True,
            "acceptance": "PASS",
            "expectation": "success",
            "observed": "success",
            "answer_ip": "192.0.2.53",
        }
        dns_down = {
            "ok": True,
            "acceptance": "PASS",
            "expectation": "failure",
            "observed": "timeout",
            "answer_ip": "",
            "error": "DNS query timed out",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def dump(name, payload):
                path = root / name
                path.write_text(json.dumps(payload), encoding="utf-8")
                return path

            failed_sockets = root / "failed-sockets.txt"
            recovered_sockets = root / "recovered-sockets.txt"
            failed_sockets.write_text("", encoding="utf-8")
            recovered_sockets.write_text(
                "UNCONN 0 0 203.0.113.53:53 0.0.0.0:*\n", encoding="utf-8"
            )

            result = verifier.evaluate(
                dns_normal=dump("dns-normal.json", dns_ok),
                dns_failure=dump("dns-failure.json", dns_down),
                dns_recovery=dump("dns-recovery.json", dns_ok),
                connectivity_normal=dump("c-normal.json", connectivity),
                connectivity_failure=dump("c-failure.json", connectivity),
                connectivity_recovery=dump("c-recovery.json", connectivity),
                routes_normal=dump("r-normal.json", route),
                routes_failure=dump("r-failure.json", route),
                routes_recovery=dump("r-recovery.json", route),
                failure_interfaces=dump(
                    "interfaces.json", [{"name": "ether2", "running": "true"}]
                ),
                failed_sockets=failed_sockets,
                recovered_sockets=recovered_sockets,
                output=root / "acceptance.json",
            )
            self.assertIsNotNone(result)
            self.assertTrue(result["ok"])
            self.assertEqual(result["acceptance"], "PASS")
            self.assertTrue(result["semantics"]["general_connectivity_remained_healthy"])
            self.assertTrue(result["semantics"]["wan10_route_remained_preferred"])

    def test_wrapper_keeps_wan_healthy_and_stops_only_dns_service(self):
        text = (ROOT / "lab/chr/run_dns_failure_acceptance.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('DNS_IP="203.0.113.53"', text)
        self.assertIn("dns_probe.py", text)
        self.assertIn('--expect failure', text)
        self.assertIn('sudo kill "${WAN10_DNS_PID}"', text)
        self.assertIn('--expected normal', text)
        self.assertIn('connectivity-dns-failure.json', text)
        self.assertIn('verify_link_up_recursive_failover.py', text)
        self.assertIn('production_writer_available', (ROOT / "lab/chr/verify_dns_failure_acceptance.py").read_text(encoding="utf-8"))
        self.assertNotIn('tc qdisc replace', text)

    def test_workflow_is_opt_in_by_commit_prefix(self):
        text = (ROOT / ".github/workflows/chr-dns-failure.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("ci(chr-dns):", text)
        self.assertIn("run_dns_failure_acceptance.sh", text)
        self.assertIn("chr-dns-failure-${{ github.sha }}", text)


if __name__ == "__main__":
    unittest.main()
