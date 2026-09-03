from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "lab" / "chr" / "verify_vlan_data_plane.py"
RUNNER = ROOT / "lab" / "chr" / "run_vlan_data_plane_acceptance.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-vlan-data-plane.yml"


def test_vlan_data_plane_gate_uses_production_renderer_and_exact_rollback():
    source = VERIFIER.read_text(encoding="utf-8")
    assert "core.render_routeros_vlan" in source
    assert '"production_renderer_used": True' in source
    assert '"in_band_vlan_data_plane_acceptance": True' in source
    assert '"ingress_filter_negative_control_acceptance": True' in source
    assert '"rollback_digest_restored": True' in source
    assert '"production_writer_available": False' in source
    assert '"write_authorized": False' in source


def test_vlan_runner_proves_tagged_positive_and_untagged_negative():
    source = RUNNER.read_text(encoding="utf-8")
    assert "type vlan id 20" in source
    assert "--tag VLAN20" in source
    assert "flow-tagged.json" in source
    assert "flow-untagged-negative.json" in source
    assert 'if [[ "${negative_rc}" -ne 16 ]]' in source


def test_vlan_workflow_binds_sha_and_preserves_data_plane_evidence():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert 'CHR_VERSION: "7.24.1"' in source
    assert "run_vlan_data_plane_acceptance.sh" in source
    assert 'payload["workflow_sha"] == "${{ github.sha }}"' in source
    assert 'payload["in_band_vlan_data_plane_acceptance"] is True' in source
    assert 'payload["ingress_filter_negative_control_acceptance"] is True' in source
    assert "actions/upload-artifact@v4" in source
