import unittest

from router_configuration.vendors.cisco.convergence_guard import (
    CiscoConvergenceGuardError,
    CiscoLaneCandidate,
    build_convergence_manifest,
)

BASE = "a" * 40


def lane(lane_id, head, paths, **overrides):
    values = dict(
        lane_id=lane_id,
        base_sha=BASE,
        head_sha=head,
        owned_paths=tuple(paths),
        required_checks_passed=True,
        production_write_authorized=False,
    )
    values.update(overrides)
    return CiscoLaneCandidate(**values)


class CiscoConvergenceGuardTests(unittest.TestCase):
    def test_independent_pass_lanes_build_deterministic_manifest(self):
        a = lane("lane-a", "1" * 40, ["src/a.py", "tests/test_a.py"])
        b = lane("lane-b", "2" * 40, ["src/b.py", "tests/test_b.py"])
        first = build_convergence_manifest([a, b], expected_base_sha=BASE)
        second = build_convergence_manifest([b, a], expected_base_sha=BASE)
        self.assertEqual(first, second)
        self.assertTrue(first.convergence_candidate)
        self.assertFalse(first.repository_merge_performed)
        self.assertFalse(first.parent_ref_updated)
        self.assertFalse(first.production_write_authorized)
        self.assertEqual(first.lane_ids, ("lane-a", "lane-b"))
        self.assertEqual(len(first.manifest_sha256), 64)

    def test_overlapping_paths_fail_closed(self):
        a = lane("lane-a", "1" * 40, ["src/shared.py"])
        b = lane("lane-b", "2" * 40, ["src/shared.py"])
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "owned path conflict"):
            build_convergence_manifest([a, b], expected_base_sha=BASE)

    def test_stale_base_fails_closed(self):
        a = lane("lane-a", "1" * 40, ["src/a.py"])
        b = lane("lane-b", "2" * 40, ["src/b.py"], base_sha="b" * 40)
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "stale or different base"):
            build_convergence_manifest([a, b], expected_base_sha=BASE)

    def test_failed_checks_fail_closed(self):
        a = lane("lane-a", "1" * 40, ["src/a.py"])
        b = lane("lane-b", "2" * 40, ["src/b.py"], required_checks_passed=False)
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "checks are not PASS"):
            build_convergence_manifest([a, b], expected_base_sha=BASE)

    def test_write_authority_fails_closed(self):
        a = lane("lane-a", "1" * 40, ["src/a.py"])
        b = lane("lane-b", "2" * 40, ["src/b.py"], production_write_authorized=True)
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "write authority"):
            build_convergence_manifest([a, b], expected_base_sha=BASE)

    def test_duplicate_lane_or_head_fails_closed(self):
        a = lane("lane-a", "1" * 40, ["src/a.py"])
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "lane id"):
            build_convergence_manifest([a, lane("lane-a", "2" * 40, ["src/b.py"])], expected_base_sha=BASE)
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "head SHA"):
            build_convergence_manifest([a, lane("lane-b", "1" * 40, ["src/b.py"])], expected_base_sha=BASE)

    def test_invalid_path_and_empty_lane_fail_closed(self):
        a = lane("lane-a", "1" * 40, ["../escape"])
        b = lane("lane-b", "2" * 40, ["src/b.py"])
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "invalid owned path"):
            build_convergence_manifest([a, b], expected_base_sha=BASE)
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "no owned paths"):
            build_convergence_manifest([lane("lane-a", "1" * 40, []), b], expected_base_sha=BASE)

    def test_single_lane_is_not_a_convergence_batch(self):
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "at least two"):
            build_convergence_manifest([lane("lane-a", "1" * 40, ["src/a.py"])], expected_base_sha=BASE)

    def test_invalid_base_and_head_fail_closed(self):
        a = lane("lane-a", "1" * 40, ["src/a.py"])
        b = lane("lane-b", "2" * 40, ["src/b.py"])
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "expected base"):
            build_convergence_manifest([a, b], expected_base_sha="bad")
        bad = lane("lane-c", BASE, ["src/c.py"])
        with self.assertRaisesRegex(CiscoConvergenceGuardError, "head SHA"):
            build_convergence_manifest([a, bad], expected_base_sha=BASE)


if __name__ == "__main__":
    unittest.main()
