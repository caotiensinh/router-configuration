import unittest

from router_configuration.vendors.mikrotik.knowledge_staging import (
    promotion_ready,
    snapshot_changed,
    stage_document,
)


class MikroTikKnowledgeStagingTests(unittest.TestCase):
    def test_staged_snapshot_has_digest_and_never_auto_promotes(self):
        snapshot = stage_document(
            source_url="https://manual.mikrotik.com/docs/llms.txt",
            retrieved_at="2026-09-14T00:00:00Z",
            content=b"manual-index-v1",
        )
        self.assertEqual(snapshot.stage, "staging")
        self.assertEqual(len(snapshot.sha256), 64)

    def test_changed_content_is_detected(self):
        old = stage_document(source_url="https://manual.mikrotik.com/docs/llms.txt", retrieved_at="a", content=b"a")
        new = stage_document(source_url="https://manual.mikrotik.com/docs/llms.txt", retrieved_at="b", content=b"b")
        self.assertTrue(snapshot_changed(old, new))

    def test_promotion_requires_every_gate(self):
        gates = {"parsed": True, "diff_reviewed": True, "validated": True, "tested": True, "reviewed": True}
        self.assertTrue(promotion_ready(gates))
        gates["tested"] = False
        self.assertFalse(promotion_ready(gates))


if __name__ == "__main__":
    unittest.main()
