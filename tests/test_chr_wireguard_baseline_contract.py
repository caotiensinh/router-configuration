import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
VALIDATOR = CHR_DIR / "verify_wireguard_baseline.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-wireguard-baseline.yml"


def load_validator():
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location("verify_wireguard_baseline_contract", VALIDATOR)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CHRWireGuardBaselineContractTests(unittest.TestCase):
    def test_fixture_renders_exact_deferred_secret_surface(self):
        module = load_validator()
        remote_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ir = module._build_ir(remote_public_key)
        plan = module.render_routeros_wireguard(ir=ir).as_dict()
        self.assertEqual(plan["template_count"], 4)
        self.assertFalse(plan["secrets_resolved"])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])
        source = "\n".join(item["template"] for item in plan["command_templates"])
        self.assertIn(module.PRIVATE_KEY_PLACEHOLDER, source)
        self.assertNotIn("env://", source)
        self.assertIn('name="wg-routercfg-lab"', source)
        self.assertIn('allowed-address="10.252.0.2/32,10.252.10.0/24"', source)
        self.assertIn('dst-address="10.252.10.0/24" gateway="wg-routercfg-lab"', source)

    def test_private_key_is_ephemeral_and_never_written_to_evidence_contract(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            "os.urandom(32)",
            "raw[0] &= 248",
            "raw[31] &= 127",
            "raw[31] |= 64",
            '"private_key_recorded": False',
            '"private_key_serialized": False',
            '"preshared_key_used": False',
            '"error_code": "wireguard_chr_gate_failed"',
        ):
            self.assertIn(required, source)
        self.assertNotIn('"private_key": private_key', source)
        self.assertNotIn('"private-key": private_key', source)
        self.assertNotIn("print(private_key", source)
        self.assertNotIn("error_detail", source)

    def test_snapshot_explicitly_excludes_sensitive_wireguard_fields(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        snapshot = source[source.index("def _configuration_snapshot"):source.index("def _write_verdict")]
        self.assertIn('"wireguard_interfaces"', snapshot)
        self.assertIn('"wireguard_peers"', snapshot)
        self.assertIn('"public-key"', snapshot)
        self.assertNotIn('"private-key"', snapshot)
        self.assertNotIn('"preshared-key"', snapshot)

    def test_rollback_is_owned_only_and_dependency_ordered(self):
        module = load_validator()
        rollback = module._rollback_script()
        route = rollback.index('/ip/route/remove')
        peer = rollback.index('/interface/wireguard/peers/remove')
        address = rollback.index('/ip/address/remove')
        interface = rollback.index('/interface/wireguard/remove')
        self.assertLess(route, peer)
        self.assertLess(peer, interface)
        self.assertLess(address, interface)
        self.assertIn('comment~"^routercfg:managed:wg:route:"', rollback)
        self.assertIn('comment~"^routercfg:managed:wg:peer:"', rollback)
        self.assertIn('comment~"^routercfg:managed:wg:address:"', rollback)
        self.assertIn('comment="routercfg:managed:wg:interface"', rollback)
        self.assertNotIn("/interface/wireguard/remove [find]\n", rollback)
        self.assertNotIn("/ip/route/remove [find]\n", rollback)

    def test_validator_requires_dry_run_runtime_management_and_exact_rollback(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            "LoopbackCHRAdmin",
            "assert_disposable_chr",
            "_execute_import_dry_run",
            "mutation._execute_import",
            "mutated_digest == baseline_digest",
            "rollback_digest != baseline_digest",
            "management_rest_reachable_after_apply",
            "invalid_managed_objects",
            "disabled_managed_objects",
            "allowed_addresses_exact",
            "managed_objects_removed",
            "rollback_digest_restored",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "paramiko",
            "requests.",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_uses_official_snapshot_and_artifact_excludes_secret_bearing_files(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "ci(chr-wireguard):",
            'CHR_VERSION: "7.24.1"',
            "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip",
            "-snapshot",
            "hostfwd=tcp:127.0.0.1:9580-:80",
            "verify_wireguard_baseline.py",
            "wireguard-baseline.json",
            "actions/upload-artifact@v4",
            "chr-wireguard-baseline-${{ github.sha }}",
        ):
            self.assertIn(required, source)
        artifact_section = source[source.index("- name: Preserve sanitized WireGuard evidence"):source.index("- name: Stop disposable CHR")]
        self.assertNotIn("chr-wireguard-serial.log", artifact_section)
        self.assertNotIn(".rsc", artifact_section)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "secrets.",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
