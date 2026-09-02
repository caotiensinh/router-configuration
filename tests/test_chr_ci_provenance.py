import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from router_configuration.routeros_evidence import build_routeros_discovery_evidence


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "build_ci_provenance_record.py"
GOLDEN = ROOT / "tests" / "fixtures" / "routeros_normalized_golden.json"

spec = importlib.util.spec_from_file_location("build_ci_provenance_record", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class CHRCIMachineProvenanceTests(unittest.TestCase):
    def _evidence(self):
        state = json.loads(GOLDEN.read_text(encoding="utf-8"))
        return build_routeros_discovery_evidence(state)

    def test_record_is_machine_observation_not_operator_attestation(self):
        record = module.build_record(
            evidence=self._evidence(),
            workflow_sha="a" * 40,
            image_url="https://download.mikrotik.com/routeros/7.24.1/chr-7.24.1.img.zip",
            image_zip_sha256="b" * 64,
        )
        self.assertEqual(record["claim"], "machine_observation_only")
        self.assertFalse(record["operator_attested"])
        self.assertFalse(record["automatic_target_matrix_admission"])
        self.assertEqual(record["routeros_version"], "7.24.1 (stable)")
        self.assertEqual(len(record["record_sha256"]), 64)

    def test_non_official_image_url_is_rejected(self):
        with self.assertRaises(module.MachineProvenanceError):
            module.build_record(
                evidence=self._evidence(),
                workflow_sha="a" * 40,
                image_url="https://example.com/chr.img.zip",
                image_zip_sha256="b" * 64,
            )

    def test_tampered_evidence_is_rejected(self):
        evidence = self._evidence()
        evidence["state_sha256"] = "0" * 64
        with self.assertRaises(module.MachineProvenanceError):
            module.build_record(
                evidence=evidence,
                workflow_sha="a" * 40,
                image_url="https://download.mikrotik.com/routeros/7.24.1/chr-7.24.1.img.zip",
                image_zip_sha256="b" * 64,
            )

    def test_sha256_file_parser_accepts_sha256sum_format(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "download.sha256"
            path.write_text(("c" * 64) + "  /tmp/chr.img.zip\n", encoding="utf-8")
            self.assertEqual(module._parse_sha256_file(path), "c" * 64)


if __name__ == "__main__":
    unittest.main()
