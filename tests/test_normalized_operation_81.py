import unittest

from router_configuration.normalized_operation import (
    NormalizedOperationError,
    build_normalized_operation,
)


def base_kwargs():
    return dict(
        operation_id="op:vlan:20",
        object_type="network.vlan",
        action="UPDATE",
        selector={"site_id": "site-a", "vlan_id": 20},
        desired_state={"name": "camera"},
        applicability={"model": "exact-required", "firmware": "verified-scope"},
        dependencies=["op:interface:lan"],
        conflicts=[],
        provenance={"source_id": "official-omada", "source_ref": "doc://verified/1"},
        verification={"read_back": True, "negative_control": True},
        rollback={"strategy": "restore_previous_state"},
    )


class NormalizedOperation81Tests(unittest.TestCase):
    def test_operation_is_deterministic_non_executable_and_provenance_bound(self):
        a = build_normalized_operation(**base_kwargs()).as_dict()
        b = build_normalized_operation(**base_kwargs()).as_dict()
        self.assertEqual(a, b)
        self.assertEqual(a["action"], "UPDATE")
        self.assertFalse(a["raw_cli_present"])
        self.assertFalse(a["invented_api_path_present"])
        self.assertFalse(a["production_write_authority"])
        self.assertEqual(len(a["operation_sha256"]), 64)
        self.assertTrue(a["provenance"])

    def test_mutation_requires_rollback_and_unknown_action_fails_closed(self):
        kwargs = base_kwargs()
        kwargs["rollback"] = None
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**kwargs)
        kwargs = base_kwargs()
        kwargs["action"] = "MAGIC_WRITE"
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**kwargs)

    def test_raw_cli_api_path_and_secrets_are_rejected_recursively(self):
        for bad_state in (
            {"command": "set something"},
            {"nested": {"api_path": "/invented"}},
            {"nested": {"password": "plaintext"}},
        ):
            kwargs = base_kwargs()
            kwargs["desired_state"] = bad_state
            with self.subTest(state=bad_state):
                with self.assertRaises(NormalizedOperationError):
                    build_normalized_operation(**kwargs)

    def test_dependency_conflict_invariants_fail_closed(self):
        kwargs = base_kwargs()
        kwargs["conflicts"] = ["op:interface:lan"]
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**kwargs)
        kwargs = base_kwargs()
        kwargs["dependencies"] = [kwargs["operation_id"]]
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**kwargs)


if __name__ == "__main__":
    unittest.main()
