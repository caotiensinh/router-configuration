import unittest

from router_configuration.progress import ProgressTracker


class ProgressTrackerTests(unittest.TestCase):
    def test_summarizes_fixed_100_point_ledger(self):
        summary = ProgressTracker().summarize({
            "scope": "test",
            "items": [
                {"id": "A", "title": "done", "weight": 40, "completed_points": 40, "status": "done"},
                {"id": "B", "title": "partial", "weight": 30, "completed_points": 10, "status": "partial", "next_gate": "finish B"},
                {"id": "C", "title": "todo", "weight": 30, "completed_points": 0, "status": "not_started", "next_gate": "start C"},
            ],
        })
        self.assertEqual(summary.completed_percent, 50)
        self.assertEqual(summary.remaining_percent, 50)
        self.assertEqual(summary.items_done, 1)
        self.assertEqual(summary.items_partial, 1)
        self.assertEqual(summary.items_not_started, 1)

    def test_rejects_weight_total_other_than_100(self):
        with self.assertRaisesRegex(ValueError, "total exactly 100"):
            ProgressTracker().summarize({
                "items": [
                    {"id": "A", "title": "bad", "weight": 99, "completed_points": 0, "status": "not_started"}
                ]
            })

    def test_done_requires_full_weight(self):
        with self.assertRaisesRegex(ValueError, "full weight"):
            ProgressTracker().summarize({
                "items": [
                    {"id": "A", "title": "bad", "weight": 100, "completed_points": 99, "status": "done"}
                ]
            })


if __name__ == "__main__":
    unittest.main()
