import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAB_CHR = ROOT / "lab" / "chr"
if str(LAB_CHR) not in sys.path:
    sys.path.insert(0, str(LAB_CHR))

import verify_link_up_recursive_failover as verifier


class FakeAdmin:
    def __init__(self, all_routes, active_routes):
        self.all_routes = all_routes
        self.active_routes = active_routes
        self.calls = []

    def request(self, method, path):
        self.calls.append((method, path))
        if method != "GET":
            raise AssertionError(method)
        if path == "ip/route":
            return 200, self.all_routes
        if path == "ip/route?active=true":
            return 200, self.active_routes
        raise AssertionError(path)


def route(route_id, comment, *, distance, gateway, inactive="false"):
    return {
        ".id": route_id,
        "comment": comment,
        "distance": str(distance),
        "gateway": gateway,
        "routing-table": "main",
        "inactive": inactive,
    }


class ChrLinkUpRouteStatusTests(unittest.TestCase):
    def setUp(self):
        self.routes = [
            route("*A", "routercfg:managed:default:lab-wan10g:1", distance=1, gateway="1.1.1.1"),
            route("*B", "routercfg:managed:default:lab-wan10g:2", distance=1, gateway="8.8.8.8"),
            route("*C", "routercfg:managed:default:lab-wan1g:1", distance=2, gateway="9.9.9.9"),
            route("*D", "routercfg:managed:default:lab-wan1g:2", distance=2, gateway="208.67.222.222"),
        ]

    def test_normal_status_comes_from_routeros_active_filter_not_inactive_false(self):
        admin = FakeAdmin(self.routes, self.routes[:2])
        rows = verifier._managed_defaults(admin)
        active = {row["comment"] for row in rows if row["active"]}
        self.assertEqual(
            active,
            {
                "routercfg:managed:default:lab-wan10g:1",
                "routercfg:managed:default:lab-wan10g:2",
            },
        )
        self.assertTrue(verifier._route_condition(rows, "normal"))
        self.assertIn(("GET", "ip/route?active=true"), admin.calls)

    def test_failover_status_uses_routeros_active_filter_for_backup_routes(self):
        failed_routes = [
            dict(row, inactive="true")
            if ":lab-wan10g:" in row["comment"]
            else row
            for row in self.routes
        ]
        admin = FakeAdmin(failed_routes, failed_routes[2:])
        rows = verifier._managed_defaults(admin)
        self.assertTrue(verifier._route_condition(rows, "wan10_failed"))
        self.assertFalse(
            any(row["active"] for row in rows if ":lab-wan10g:" in row["comment"])
        )
        self.assertTrue(
            any(row["active"] for row in rows if ":lab-wan1g:" in row["comment"])
        )

    def test_missing_route_id_fails_closed_even_when_inactive_is_false(self):
        row = route(
            "",
            "routercfg:managed:default:lab-wan1g:1",
            distance=2,
            gateway="9.9.9.9",
        )
        admin = FakeAdmin([row], [row])
        rows = verifier._managed_defaults(admin)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["active"])

    def test_normal_rejects_simultaneously_active_backup_route(self):
        admin = FakeAdmin(self.routes, self.routes)
        rows = verifier._managed_defaults(admin)
        self.assertFalse(verifier._route_condition(rows, "normal"))


if __name__ == "__main__":
    unittest.main()
