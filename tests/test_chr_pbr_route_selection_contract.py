from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "lab" / "chr" / "verify_pbr_route_selection.py"
RUNNER = ROOT / "lab" / "chr" / "run_pbr_route_selection_acceptance.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-pbr-route-selection.yml"


def test_pbr_route_selection_gate_uses_production_renderer_and_conservative_boundary():
    source = VERIFIER.read_text(encoding="utf-8")
    assert "from router_configuration.routeros_pbr_renderer import render_routeros_pbr" in source
    assert '"route_selection_data_plane_acceptance": True' in source
    assert '"observed_sequence": ["MAIN", "PBR", "MAIN"]' in source
    assert '"production_writer_available": False' in source
    assert '"transport_exposed_to_product": False' in source
    assert '"write_authorized": False' in source
    assert '"physical_router_targeted": False' in source
    assert '"production_route_selection_claimed": False' in source


def test_pbr_runner_probes_baseline_apply_and_rollback_with_distinct_flow_ports():
    source = RUNNER.read_text(encoding="utf-8")
    assert "--tag MAIN" in source
    assert "--tag PBR" in source
    assert 'probe 22000 "${EVIDENCE_DIR}/flow-baseline-main.json"' in source
    assert 'probe 24000 "${EVIDENCE_DIR}/flow-policy-pbr.json"' in source
    assert 'probe 26000 "${EVIDENCE_DIR}/flow-rollback-main.json"' in source
    assert "verify_pbr_route_selection.py" in source
    assert "udp_flow_probe.py" in source


def test_pbr_route_selection_workflow_binds_exact_sha_and_preserves_evidence():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert 'CHR_VERSION: "7.24.1"' in source
    assert "run_pbr_route_selection_acceptance.sh" in source
    assert 'payload["workflow_sha"] == "${{ github.sha }}"' in source
    assert 'payload["packet_flow"]["observed_sequence"] == ["MAIN", "PBR", "MAIN"]' in source
    assert 'payload["route_selection_data_plane_acceptance"] is True' in source
    assert "actions/upload-artifact@v4" in source
