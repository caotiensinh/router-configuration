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

    def test_source_expects_explicit_write_denial(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("exc.code != 403", source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertNotIn("routerctl", source)


if __name__ == "__main__":
    unittest.main()
