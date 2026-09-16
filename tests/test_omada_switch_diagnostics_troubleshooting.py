import json
import unittest
from pathlib import Path


class OmadaSwitchDiagnosticsContractTests(unittest.TestCase):
    def test_diagnostics_contract_is_evidence_first_and_fail_closed(self) -> None:
        data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_SWITCH_DIAGNOSTICS_TROUBLESHOOTING_SCHEMA.json").read_text())
        self.assertEqual(data["task"], "4.20")
        self.assertIs(data["safety"]["read_only_evidence_precedes_mutation"], True)
        self.assertIs(data["safety"]["factory_reset_is_not_a_first_line_diagnostic"], True)
        self.assertIs(data["safety"]["firmware_upgrade_is_not_a_first_line_diagnostic"], True)
        self.assertIs(data["safety"]["global_acl_or_security_disable_is_forbidden_as_a_generic_fix"], True)
        self.assertEqual(data["safety"]["unknown_tool_support"], "NOT_SUPPORTED_UNVERIFIED")
        self.assertIs(data["diagnostic_planes"]["physical_link"]["mutation_required"], False)
        self.assertIn("ROOT_CAUSE_UNRESOLVED", data["outcomes"])


if __name__ == "__main__":
    unittest.main()
