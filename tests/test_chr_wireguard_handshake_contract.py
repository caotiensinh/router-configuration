from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "lab" / "chr" / "verify_wireguard_handshake.py"
RUNNER = ROOT / "lab" / "chr" / "run_wireguard_handshake_acceptance.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-wireguard-handshake.yml"


def test_wireguard_handshake_gate_uses_two_chrs_and_production_renderer():
    source = VERIFIER.read_text(encoding="utf-8")
    assert "render_routeros_wireguard" in source
    assert '"production_renderer_used_on_chr_a": True' in source
    assert '"wireguard_handshake_acceptance": True' in source
    assert '"encrypted_packet_transfer_acceptance": True' in source
    assert 'peer.get("last-handshake")' in source
    assert 'peer.get("rx")' in source
    assert 'peer.get("tx")' in source


def test_wireguard_handshake_gate_keeps_private_material_out_of_evidence():
    source = VERIFIER.read_text(encoding="utf-8")
    assert '"private_key_recorded": False' in source
    assert '"private_key_serialized": False' in source
    assert '"preshared_key_used": False' in source
    assert '"chr_b_private_key_read": False' in source
    assert '"production_writer_available": False' in source
    assert '"transport_exposed_to_product": False' in source
    assert '"write_authorized": False' in source
    assert '"physical_router_targeted": False' in source


def test_wireguard_runner_probes_lan_to_lan_through_two_chr_peers():
    source = RUNNER.read_text(encoding="utf-8")
    assert "10.60.1.2" in source
    assert "10.60.2.2" in source
    assert "--tag WG" in source
    assert "verify_wireguard_handshake.py" in source
    assert "udp_flow_probe.py" in source
    assert "10080" in source and "10081" in source


def test_wireguard_workflow_binds_exact_sha_and_checks_handshake_evidence():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert 'CHR_VERSION: "7.24.1"' in source
    assert "run_wireguard_handshake_acceptance.sh" in source
    assert 'acceptance["workflow_sha"] == "${{ github.sha }}"' in source
    assert 'acceptance["wireguard_handshake_acceptance"] is True' in source
    assert 'acceptance["encrypted_packet_transfer_acceptance"] is True' in source
    assert 'cleanup["chr_a_digest_restored"] is True' in source
    assert 'cleanup["chr_b_digest_restored"] is True' in source
    assert "actions/upload-artifact@v4" in source
