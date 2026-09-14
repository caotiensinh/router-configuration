from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from router_configuration.lab_probes import (
    build_dns_query,
    build_dns_response,
    parse_dns_query,
    parse_dns_response,
)

ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ChrProbeCompatibilityTests(unittest.TestCase):
    def test_chr_dns_api_preserves_common_codec_semantics(self) -> None:
        legacy = _load_module("chr_dns_probe_compat", CHR_DIR / "dns_probe.py")
        query = legacy.build_query("routercfg.test")
        self.assertEqual(query, build_dns_query("routercfg.test"))
        self.assertEqual(legacy.parse_query(query), parse_dns_query(query))

        response = legacy.build_response(query, answer_ip="192.0.2.53")
        self.assertEqual(response, build_dns_response(query, answer_ip="192.0.2.53"))
        self.assertEqual(
            legacy.parse_response(response, expected_name="routercfg.test"),
            parse_dns_response(response, expected_name="routercfg.test"),
        )

    def test_chr_dns_wrapper_preserves_legacy_evidence_schema(self) -> None:
        source = (CHR_DIR / "dns_probe.py").read_text(encoding="utf-8")
        self.assertIn('schema_version="chr-dns-service-probe/1"', source)
        self.assertIn("router_configuration.lab_probes", source)
        self.assertIn("build_query = build_dns_query", source)
        self.assertIn("parse_response = parse_dns_response", source)

    def test_chr_udp_wrappers_preserve_legacy_contract(self) -> None:
        server = (CHR_DIR / "udp_tag_server.py").read_text(encoding="utf-8")
        probe = (CHR_DIR / "udp_flow_probe.py").read_text(encoding="utf-8")
        self.assertIn("router_configuration.lab_probes", server)
        self.assertIn("serve_tagged_udp", server)
        self.assertIn("router_configuration.lab_probes", probe)
        self.assertIn("run_udp_flow_probe", probe)
        self.assertIn('schema_version="chr-udp-flow-probe/1"', probe)

    def test_chr_compatibility_wrappers_bootstrap_repo_source(self) -> None:
        for name in ("dns_probe.py", "udp_tag_server.py", "udp_flow_probe.py"):
            source = (CHR_DIR / name).read_text(encoding="utf-8")
            self.assertIn('Path(__file__).resolve().parents[2]', source)
            self.assertIn('sys.path.insert(0, str(_SRC))', source)


if __name__ == "__main__":
    unittest.main()
