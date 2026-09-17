import unittest

from router_configuration.omada_normalized_operation import NormalizedOperationError, build_normalized_operation


class OmadaNormalizedOperation81Tests(unittest.TestCase):
    def base(self, **overrides):
        kwargs = dict(
            operation_id="op:vlan:10",
            object_type="network.vlan",
            action="UPDATE",
            selector={"site": "lab", "vlan_id": 10},
            desired_state={"name": "camera"},
            applicability={"model": "exact", "firmware": "known", "region": "JP"},
            dependencies=["op:site:lab"],
            conflicts=[],
            provenance={"source_id": "official-doc-1", "source_sha256": "a" * 64},
            verification={"read_back": True, "negative_control": True},
            rollback={"strategy": "restore_previous_normalized_state"},
        )
        kwargs.update(overrides)
        return kwargs

    def test_operation_is_deterministic_non_executable_and_hash_bound(self):
        a = build_normalized_operation(**self.base()).as_dict()
        b = build_normalized_operation(**self.base()).as_dict()
        self.assertEqual(a, b)
        self.assertFalse(a["executable"])
        self.assertFalse(a["production_write_authority"])
        self.assertEqual(len(a["operation_sha256"]), 64)

    def test_raw_cli_or_api_path_is_rejected_recursively(self):
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**self.base(desired_state={"raw_cli": "set x"}))
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**self.base(verification={"api_path": "/invented"}))

    def test_mutation_requires_rollback_metadata(self):
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**self.base(rollback=None))

    def test_self_dependency_and_unknown_action_fail_closed(self):
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**self.base(dependencies=["op:vlan:10"]))
        with self.assertRaises(NormalizedOperationError):
            build_normalized_operation(**self.base(action="EXECUTE"))


if __name__ == "__main__":
    unittest.main()
