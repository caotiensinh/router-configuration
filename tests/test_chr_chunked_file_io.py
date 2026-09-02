import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
CHUNKED = CHR_DIR / "verify_render_dry_run_chunked.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-render-dryrun.yml"


def load_chunked():
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location("verify_render_dry_run_chunked_test", CHUNKED)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class FakeAdmin:
    def __init__(self, name: str, contents: str):
        self.name = name
        self.contents = contents
        self.calls = []

    def request(self, method, path, payload=None, *, allow_http_error=False):
        self.calls.append((method, path, payload, allow_http_error))
        if method == "GET" and path == "file":
            return 200, [{".id": "*1", "name": self.name, "size": str(len(self.contents.encode("utf-8")))}]
        if method == "POST" and path == "file/read":
            offset = int(payload["offset"])
            chunk_size = int(payload["chunk-size"])
            raw = self.contents.encode("utf-8")
            data = raw[offset: offset + chunk_size].decode("utf-8")
            return 200, [{"data": data}]
        raise AssertionError((method, path, payload, allow_http_error))


class CHRChunkedFileIOTests(unittest.TestCase):
    def test_reads_file_larger_than_four_kib_in_bounded_chunks(self):
        module = load_chunked()
        contents = "x" * 5536
        admin = FakeAdmin("fixture.rsc", contents)
        observed = module._read_text_file_chunked(admin, "fixture.rsc")
        self.assertEqual(observed, contents)
        reads = [call for call in admin.calls if call[0:2] == ("POST", "file/read")]
        self.assertEqual(len(reads), 2)
        self.assertEqual(reads[0][2]["offset"], 0)
        self.assertEqual(reads[0][2]["chunk-size"], 4096)
        self.assertEqual(reads[1][2]["offset"], 4096)
        self.assertEqual(reads[1][2]["chunk-size"], 1440)

    def test_empty_chunk_before_eof_fails_closed(self):
        module = load_chunked()

        class BrokenAdmin(FakeAdmin):
            def request(self, method, path, payload=None, *, allow_http_error=False):
                if method == "POST" and path == "file/read":
                    return 200, [{"data": ""}]
                return super().request(method, path, payload, allow_http_error=allow_http_error)

        with self.assertRaises(module.base.CHRRenderDryRunError):
            module._read_text_file_chunked(BrokenAdmin("fixture.rsc", "x" * 5000), "fixture.rsc")

    def test_chunked_adapter_keeps_sha_and_byte_equality_checks(self):
        source = CHUNKED.read_text(encoding="utf-8")
        self.assertIn('"file/read"', source)
        self.assertIn("READ_CHUNK_BYTES = 4096", source)
        self.assertIn("expected_sha256", source)
        self.assertIn("observed_sha256", source)
        self.assertIn("observed != contents", source)
        self.assertIn("60_000", source)
        self.assertNotIn("production_writer_available = True", source)

    def test_workflow_uses_chunk_verified_adapter(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("verify_render_dry_run_chunked.py", source)
        self.assertNotIn("python lab/chr/verify_render_dry_run.py \\", source)


if __name__ == "__main__":
    unittest.main()
