import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAB_CHR = ROOT / "lab" / "chr"
if str(LAB_CHR) not in sys.path:
    sys.path.insert(0, str(LAB_CHR))

import verify_link_up_recursive_failover as verifier


class ChrLinkUpRouteStatusTests(unittest.TestCase):
    def test_explicit_active_property_is_authoritative(self):
        self.assertTrue(verifier._route_is_active({"active": "true", "inactive": "false"}))
        self.assertFalse(verifier._route_is_active({"active": "false", "inactive": "false"}))

    def test_missing_active_falls_back_to_explicit_inactive_property(self):
        self.assertTrue(verifier._route_is_active({"inactive": "false"}))
        self.assertFalse(verifier._route_is_active({"inactive": "true"}))

    def test_missing_route_status_fails_closed(self):
        self.assertFalse(verifier._route_is_active({}))

    def test_observed_failover_shape_satisfies_wan10_failed_condition(self):
        rows = [
            {"comment": "routercfg:managed:default:lab-wan10g:1", "active": False},
            {"comment": "routercfg:managed:default:lab-wan10g:2", "active": False},
            {"comment": "routercfg:managed:default:lab-wan1g:1", "active": True},
            {"comment": "routercfg:managed:default:lab-wan1g:2", "active": True},
        ]
        self.assertTrue(verifier._route_condition(rows, "wan10_failed"))


if __name__ == "__main__":
    unittest.main()
