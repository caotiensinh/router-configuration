import unittest

from router_configuration.parallel_lanes import (
    MAX_LANES,
    LaneContractError,
    lane_ids,
    plan_document,
    task_from_mapping,
    validate_capacity_manifest,
)


class ParallelLaneContractTests(unittest.TestCase):
    def test_capacity_is_exactly_500_unique_lanes(self) -> None:
        ids = lane_ids()
        self.assertEqual(len(ids), 500)
        self.assertEqual(len(set(ids)), 500)
        self.assertEqual(ids[0], "LANE-0001")
        self.assertEqual(ids[-1], "LANE-0500")

    def test_500_disjoint_tasks_fit_one_wave(self) -> None:
        document = {
            "base_sha": "a" * 40,
            "tasks": [
                {
                    "task_id": f"TASK-{index:04d}",
                    "mode": "write",
                    "write_paths": [f"work/{index:04d}/result.json"],
                }
                for index in range(1, 501)
            ],
        }
        plan = plan_document(document)
        self.assertEqual(len(plan["waves"]), 1)
        assignments = plan["waves"][0]["assignments"]
        self.assertEqual(len(assignments), 500)
        self.assertEqual(assignments[0]["lane_id"], "LANE-0001")
        self.assertEqual(assignments[-1]["lane_id"], "LANE-0500")
        self.assertEqual(plan["worker_processes_started"], 0)
        self.assertTrue(plan["capacity_is_not_worker_count"])

    def test_501_disjoint_tasks_require_second_wave(self) -> None:
        document = {
            "tasks": [
                {
                    "task_id": f"TASK-{index:04d}",
                    "mode": "write",
                    "write_paths": [f"work/{index:04d}.json"],
                }
                for index in range(1, 502)
            ]
        }
        plan = plan_document(document)
        self.assertEqual([len(wave["assignments"]) for wave in plan["waves"]], [500, 1])

    def test_overlapping_write_paths_are_serialized(self) -> None:
        document = {
            "tasks": [
                {"task_id": "A", "mode": "write", "write_paths": ["src/cisco"]},
                {"task_id": "B", "mode": "write", "write_paths": ["src/cisco/parser.py"]},
                {"task_id": "C", "mode": "write", "write_paths": ["docs/cisco.md"]},
            ]
        }
        plan = plan_document(document)
        waves = plan["waves"]
        self.assertEqual(len(waves), 2)
        first = {item["task_id"] for item in waves[0]["assignments"]}
        second = {item["task_id"] for item in waves[1]["assignments"]}
        self.assertEqual(first, {"A", "C"})
        self.assertEqual(second, {"B"})

    def test_conflict_keys_serialize_non_overlapping_paths(self) -> None:
        document = {
            "tasks": [
                {
                    "task_id": "A",
                    "mode": "write",
                    "write_paths": ["a/file.txt"],
                    "conflict_keys": ["ledger:CISCO_PROGRESS"],
                },
                {
                    "task_id": "B",
                    "mode": "write",
                    "write_paths": ["b/file.txt"],
                    "conflict_keys": ["ledger:CISCO_PROGRESS"],
                },
            ]
        }
        plan = plan_document(document)
        self.assertEqual(len(plan["waves"]), 2)

    def test_dependencies_force_later_wave(self) -> None:
        document = {
            "tasks": [
                {"task_id": "A", "mode": "write", "write_paths": ["a.txt"]},
                {
                    "task_id": "B",
                    "mode": "write",
                    "write_paths": ["b.txt"],
                    "dependencies": ["A"],
                },
            ]
        }
        plan = plan_document(document)
        self.assertEqual(
            [[item["task_id"] for item in wave["assignments"]] for wave in plan["waves"]],
            [["A"], ["B"]],
        )

    def test_read_only_tasks_do_not_claim_write_paths(self) -> None:
        with self.assertRaises(LaneContractError):
            task_from_mapping(
                {"task_id": "READ", "mode": "read_only", "write_paths": ["src/file.py"]}
            )

    def test_write_task_requires_declared_paths(self) -> None:
        with self.assertRaises(LaneContractError):
            task_from_mapping({"task_id": "WRITE", "mode": "write", "write_paths": []})

    def test_dependency_cycle_fails_closed(self) -> None:
        document = {
            "tasks": [
                {
                    "task_id": "A",
                    "mode": "write",
                    "write_paths": ["a"],
                    "dependencies": ["B"],
                },
                {
                    "task_id": "B",
                    "mode": "write",
                    "write_paths": ["b"],
                    "dependencies": ["A"],
                },
            ]
        }
        with self.assertRaises(LaneContractError):
            plan_document(document)

    def test_path_traversal_and_absolute_paths_are_rejected(self) -> None:
        for path in ("../secret", "/etc/passwd", "C:\\Windows\\System32"):
            with self.subTest(path=path):
                with self.assertRaises(LaneContractError):
                    task_from_mapping(
                        {"task_id": "BAD", "mode": "write", "write_paths": [path]}
                    )

    def test_invalid_base_sha_fails_closed(self) -> None:
        with self.assertRaises(LaneContractError):
            plan_document(
                {
                    "base_sha": "main",
                    "tasks": [
                        {"task_id": "A", "mode": "write", "write_paths": ["a.txt"]}
                    ],
                }
            )

    def test_manifest_contract(self) -> None:
        manifest = {
            "schema_version": "parallel-lane-capacity/1",
            "lane_capacity": MAX_LANES,
            "lane_ids": list(lane_ids()),
            "capacity_is_not_worker_count": True,
            "direct_main_write": False,
            "vendor_truth_authority": "validated_vendor_knowledge_only",
        }
        validate_capacity_manifest(manifest)
        manifest["lane_ids"][-1] = "LANE-9999"
        with self.assertRaises(LaneContractError):
            validate_capacity_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
