import unittest

from router_configuration.dependency_dag import DependencyDAG, DependencyDagError, build_dependency_node


class DependencyDagTests(unittest.TestCase):
    def test_deterministic_topological_order(self):
        dag = DependencyDAG([
            build_dependency_node(operation_id="c", depends_on=["a", "b"]),
            build_dependency_node(operation_id="b", depends_on=["a"]),
            build_dependency_node(operation_id="a"),
        ])
        self.assertEqual(dag.topological_order(), ("a", "b", "c"))
        self.assertFalse(dag.as_dict()["executable"])

    def test_unknown_dependency_fails_closed(self):
        dag = DependencyDAG([build_dependency_node(operation_id="b", depends_on=["missing"])])
        with self.assertRaises(DependencyDagError):
            dag.topological_order()

    def test_cycle_is_rejected(self):
        dag = DependencyDAG([
            build_dependency_node(operation_id="a", depends_on=["b"]),
            build_dependency_node(operation_id="b", depends_on=["a"]),
        ])
        with self.assertRaises(DependencyDagError):
            dag.topological_order()

    def test_self_dependency_is_rejected(self):
        with self.assertRaises(DependencyDagError):
            build_dependency_node(operation_id="a", depends_on=["a"])

    def test_digest_is_stable_for_equivalent_graph(self):
        a = DependencyDAG([
            build_dependency_node(operation_id="b", depends_on=["a"]),
            build_dependency_node(operation_id="a"),
        ]).as_dict()
        b = DependencyDAG([
            build_dependency_node(operation_id="a"),
            build_dependency_node(operation_id="b", depends_on=["a"]),
        ]).as_dict()
        self.assertEqual(a["dag_sha256"], b["dag_sha256"])


if __name__ == "__main__":
    unittest.main()
