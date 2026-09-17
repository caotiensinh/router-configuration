import unittest

from router_configuration.test_evidence import TestEvidenceError, build_test_evidence


SHA1 = "a" * 40


def base_kwargs():
    return dict(
        source_main_sha=SHA1,
        test_scope="wave-14-target-tests",
        runner_identity="github-actions/ubuntu-24.04",
        runtime_version="CPython 3.13.15",
        test_command="python -m unittest discover -s tests -v",
        discovered_tests=["suite.test_a", "suite.test_b"],
        passed_tests=["suite.test_a", "suite.test_b"],
        failed_tests=[],
        result="PASS",
        evidence_refs=["run://123/job/456"],
    )


class TestEvidence146Tests(unittest.TestCase):
    def test_pass_record_is_deterministic_and_requires_real_discovery(self):
        a = build_test_evidence(**base_kwargs()).as_dict()
        b = build_test_evidence(**base_kwargs()).as_dict()
        self.assertEqual(a, b)
        self.assertEqual(a["discovered_test_count"], 2)
        self.assertEqual(a["passed_test_count"], 2)
        self.assertEqual(a["failed_test_count"], 0)
        self.assertFalse(a["generic_ci_green_is_sufficient"])
        self.assertFalse(a["production_write_authority"])
        self.assertEqual(len(a["test_evidence_sha256"]), 64)

    def test_pass_without_discovery_or_with_failure_fails_closed(self):
        kwargs = base_kwargs()
        kwargs["discovered_tests"] = []
        kwargs["passed_tests"] = []
        with self.assertRaises(TestEvidenceError):
            build_test_evidence(**kwargs)
        kwargs = base_kwargs()
        kwargs["failed_tests"] = ["suite.test_b"]
        kwargs["passed_tests"] = ["suite.test_a"]
        with self.assertRaises(TestEvidenceError):
            build_test_evidence(**kwargs)

    def test_failed_or_undiscovered_test_relationship_is_validated(self):
        kwargs = base_kwargs()
        kwargs["result"] = "FAIL"
        kwargs["passed_tests"] = ["suite.test_a"]
        kwargs["failed_tests"] = ["suite.test_b"]
        record = build_test_evidence(**kwargs).as_dict()
        self.assertEqual(record["result"], "FAIL")

        kwargs = base_kwargs()
        kwargs["passed_tests"] = ["suite.test_missing"]
        with self.assertRaises(TestEvidenceError):
            build_test_evidence(**kwargs)

    def test_hardware_claim_and_secret_material_are_guarded(self):
        kwargs = base_kwargs()
        kwargs["hardware_claim"] = True
        with self.assertRaises(TestEvidenceError):
            build_test_evidence(**kwargs)
        kwargs["physical_evidence_refs"] = ["evidence://physical/device-1"]
        record = build_test_evidence(**kwargs).as_dict()
        self.assertTrue(record["hardware_claim"])

        kwargs = base_kwargs()
        kwargs["test_command"] = "pytest --token=plaintext"
        with self.assertRaises(TestEvidenceError):
            build_test_evidence(**kwargs)


if __name__ == "__main__":
    unittest.main()
