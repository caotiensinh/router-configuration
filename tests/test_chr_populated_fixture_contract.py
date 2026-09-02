import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POPULATOR = ROOT / "lab" / "chr" / "populate_acceptance_objects.py"
CLI = ROOT / "src" / "router_configuration" / "cli.py"


class CHRPopulatedFixtureContractTests(unittest.TestCase):
    def test_populator_is_not_imported_by_routerctl(self):
        tree = ast.parse(CLI.read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        self.assertFalse(any("populate_acceptance_objects" in item for item in imported))

    def test_populator_has_only_named_disposable_surfaces(self):
        source = POPULATOR.read_text(encoding="utf-8")
        for path in (
            '"ip/firewall/filter"',
            '"ip/firewall/nat"',
            '"interface/wireguard"',
            '"queue/simple"',
        ):
            self.assertIn(path, source)
        self.assertIn("routercfg-disposable-live-acceptance", source)
        self.assertIn('"production_writer_available": False', source)

    def test_populator_does_not_expose_delete_or_generic_command_runner(self):
        source = POPULATOR.read_text(encoding="utf-8")
        self.assertNotIn('"DELETE"', source)
        self.assertNotIn('"POST"', source)
        self.assertNotIn("routerctl", source)


if __name__ == "__main__":
    unittest.main()
