import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_reader_write_denied.py"
CLI = ROOT / "src" / "router_configuration" / "cli.py"

spec = importlib.util.spec_from_file_location("verify_reader_write_denied", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class CHRReaderBoundaryTests(unittest.TestCase):
    def test_boundary_probe_requires_loopback_https(self):
        self.assertEqual(
            module._loopback_https("https://127.0.0.1:9443"),
            "https://127.0.0.1:9443",
        )
        for url in (
            "http://127.0.0.1:9180",
            "https://192.0.2.10:9443",
            "https://example.com",
            "https://127.0.0.1:9443/rest/system/resource",
        ):
            with self.assertRaises(module.ReaderBoundaryError):
                module._loopback_https(url)

    def test_probe_is_not_imported_by_product_cli(self):
        source = CLI.read_text(encoding="utf-8")
        self.assertNotIn("verify_reader_write_denied", source)

    def test_direct_403_is_explicit_denial(self):
        self.assertTrue(module._is_explicit_permission_denial(403, {}))

    def test_routeros_500_requires_permission_semantics(self):
        self.assertTrue(
            module._is_explicit_permission_denial(
                500,
                {
                    "error": 500,
                    "message": "Internal Server Error",
                    "detail": "not enough permissions (9)",
                },
            )
        )
        self.assertTrue(
            module._is_explicit_permission_denial(
                500,
                {"detail": "not allowed (9)"},
            )
        )
        self.assertFalse(
            module._is_explicit_permission_denial(
                500,
                {"detail": "database unavailable"},
            )
        )
        self.assertFalse(module._is_explicit_permission_denial(401, {"detail": "forbidden"}))

    def test_probe_marker_detection_is_recursive(self):
        self.assertTrue(
            module._contains_probe_marker(
                [{"comment": "prefix-routercfg-readonly-boundary-probe-suffix"}]
            )
        )
        self.assertFalse(module._contains_probe_marker([{"comment": "other"}]))

    def test_source_requires_denial_semantics_and_readback(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("_is_explicit_permission_denial", source)
        self.assertIn("write_denial_verified_by_readback", source)
        self.assertIn("probe_marker_absent_after_denial", source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertNotIn("routerctl", source)


if __name__ == "__main__":
    unittest.main()
