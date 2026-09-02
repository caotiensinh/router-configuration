import ast
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "lab" / "chr" / "bootstrap_secure_acceptance.py"
CLI = ROOT / "src" / "router_configuration" / "cli.py"


class CHRSecureBootstrapContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("chr_secure_bootstrap", BOOTSTRAP)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.module = module

    def test_admin_bootstrap_refuses_non_loopback_and_non_http(self):
        for target in (
            "http://192.0.2.10:80",
            "https://127.0.0.1:9443",
            "http://example.com",
        ):
            with self.assertRaises(self.module.LabBootstrapError):
                self.module.LoopbackRestAdmin(target)

    def test_https_acceptance_target_must_be_loopback(self):
        with self.assertRaises(self.module.LabBootstrapError):
            self.module.bootstrap_secure_acceptance(
                admin_url="http://127.0.0.1:9180",
                https_url="https://192.0.2.10:9443",
                ca_output=Path("unused-ca.crt"),
                credentials_output=Path("unused-creds.json"),
            )

    def test_bootstrap_is_not_imported_by_product_cli(self):
        tree = ast.parse(CLI.read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        self.assertFalse(any("bootstrap_secure_acceptance" in item for item in imported))

    def test_source_declares_minimal_reader_policy(self):
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('"policy": "read,rest-api"', source)
        self.assertNotIn('"policy": "read,write', source)
        self.assertIn('production_writer_available', source)

    def test_service_updates_resolve_routeros_rest_id_by_name(self):
        class FakeAdmin:
            def request(self, method, path, payload=None):
                self.last = (method, path, payload)
                return [
                    {".id": "*1", "name": "www", "port": "80"},
                    {".id": "*2", "name": "www-ssl", "port": "443"},
                ]

        admin = FakeAdmin()
        resolved = self.module._find_rest_id_by_name(admin, "ip/service", "www-ssl")
        self.assertEqual(resolved, "*2")
        self.assertEqual(admin.last[:2], ("GET", "ip/service"))

    def test_missing_service_name_is_blocking(self):
        class FakeAdmin:
            def request(self, method, path, payload=None):
                return [{".id": "*1", "name": "www"}]

        with self.assertRaises(self.module.LabBootstrapError):
            self.module._find_rest_id_by_name(FakeAdmin(), "ip/service", "www-ssl")


if __name__ == "__main__":
    unittest.main()
