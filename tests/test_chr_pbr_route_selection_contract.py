from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "lab" / "chr" / "verify_pbr_route_selection.py"
RUNNER = ROOT / "lab" / "chr" / "run_pbr_route_selection_acceptance.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-pbr-route-selection.yml"


def test_pbr_route_selection_verifier_requires_real_packet_flow_and_safe_boundary() -> None:
    text = VERIFIER.read_text(encoding="utf-8")
    assert "import verify_pbr_baseline as baseline" in text
    assert "baseline.render_routeros_pbr" in text
    assert '"production_renderer_used": True' in text
    assert '"route_selection_data_plane_acceptance": True' in text
    assert '"negative_control_acceptance": True' in text
    assert "_assert_negative_flow" in text
    assert "_assert_positive_flow" in text
    assert 'normalized != {"PBR": requested}' in text
    assert 'str(row.get("action") or "") != "lookup-only-in-table"' in text
    assert '"rule_rollback_digest_restored": True' in text
    assert '"lab_setup_cleanup_restored": True' in text
    assert '"production_writer_available": False' in text
    assert '"transport_exposed_to_product": False' in text
    assert '"write_authorized": False' in text
    assert '"physical_router_targeted": False' in text


def test_pbr_route_selection_runner_proves_rule_causality_in_isolated_topology() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "rc-pbr-core" in text
    assert "rc-pbr-wan" in text
    assert "198.51.100.2/24" in text
    assert "192.0.2.1/30" in text
    assert "203.0.113.100/32" in text
    assert "--tag PBR" in text
    negative = text.index('flow-without-pbr.json')
    apply_rule = text.index('"${VERIFIER}" apply')
    positive = text.index('flow-with-pbr.json')
    assert negative < apply_rule < positive
    assert 'if [[ "${negative_rc}" -ne 16 ]]' in text
    assert "warming selected routing-table path" in text
    assert '"${VERIFIER}" finalize' in text
    assert "-snapshot" in text


def test_pbr_route_selection_workflow_uses_official_chr_and_sanitized_artifact() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "CHR PBR Route Selection" in text
    assert 'CHR_VERSION: "7.24.1"' in text
    assert "download.mikrotik.com/routeros" in text
    assert "run_pbr_route_selection_acceptance.sh" in text
    assert 'payload["route_selection_data_plane_acceptance"] is True' in text
    assert 'payload["negative_control_acceptance"] is True' in text
    assert 'payload["renderer"]["production_renderer_used"] is True' in text
    assert 'payload["production_writer_available"] is False' in text
    assert 'payload["transport_exposed_to_product"] is False' in text
    assert 'payload["write_authorized"] is False' in text
    assert 'payload["physical_router_targeted"] is False' in text
    assert "actions/upload-artifact@v4" in text
    assert "chr-pbr-route-selection-${{ github.sha }}" in text
    assert "chr-pbr-flow-serial.log" not in text
