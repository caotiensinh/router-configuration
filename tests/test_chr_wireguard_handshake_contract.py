from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "lab" / "chr" / "verify_wireguard_handshake.py"
RUNNER = ROOT / "lab" / "chr" / "run_wireguard_handshake_acceptance.sh"
PROBE = ROOT / "lab" / "chr" / "icmp_probe.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-wireguard-handshake.yml"


def test_wireguard_handshake_verifier_uses_production_renderer_with_lab_only_secret_binding() -> None:
    text = VERIFIER.read_text(encoding="utf-8")
    assert "import verify_wireguard_baseline as baseline" in text
    assert "baseline.render_routeros_wireguard" in text
    assert "PRIVATE_KEY_PLACEHOLDER" in text
    assert '"production_renderer_used": True' in text
    assert '"deferred_secret_binding": True' in text
    assert '"ephemeral_private_key_recorded": False' in text
    assert '"private_key_serialized_to_evidence": False' in text
    assert '"preshared_key_used": False' in text
    assert '"handshake_acceptance": True' in text
    assert '"encrypted_packet_transfer_acceptance": True' in text
    assert '"rollback_digest_restored": True' in text
    assert '"lab_setup_cleanup_restored": True' in text
    assert '"production_writer_available": False' in text
    assert '"transport_exposed_to_product": False' in text
    assert '"write_authorized": False' in text
    assert '"physical_router_targeted": False' in text


def test_wireguard_runner_requires_negative_control_then_measured_transfer_and_two_sided_counters() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "rc-wg-peer" in text
    assert "192.0.2.1/30" in text
    assert "10.252.0.2/24" in text
    assert "wg genkey" in text
    assert "wg pubkey" in text
    assert "private-key /dev/stdin" in text
    negative = text.index("negative-probe.json")
    peer_activation = text.index('wg set "${WG_IF}"')
    positive = text.index("positive-probe.json")
    assert negative < peer_activation < positive
    assert 'if [[ "${negative_rc}" -ne 16 ]]' in text
    assert "--count 20" in text
    assert 'wg show "${WG_IF}" latest-handshakes' in text
    assert 'wg show "${WG_IF}" transfer' in text
    assert "peer_public_key_recorded': False" in text
    assert "private_key_recorded': False" in text
    assert "rm -f \"${EVIDENCE_DIR}/prepared.json\"" in text
    assert "-snapshot" in text


def test_icmp_probe_has_strict_all_or_zero_result_codes() -> None:
    text = PROBE.read_text(encoding="utf-8")
    assert '"schema_version": "chr-icmp-probe/1"' in text
    assert "received == transmitted == args.count" in text
    assert "received == 0" in text
    assert "return 16" in text
    assert "return 17" in text


def test_wireguard_handshake_workflow_uses_official_chr_and_sanitized_evidence() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "CHR WireGuard Handshake" in text
    assert 'CHR_VERSION: "7.24.1"' in text
    assert "download.mikrotik.com/routeros" in text
    assert "wireguard-tools" in text
    assert "run_wireguard_handshake_acceptance.sh" in text
    assert 'payload["handshake_acceptance"] is True' in text
    assert 'payload["encrypted_packet_transfer_acceptance"] is True' in text
    assert 'payload["negative_control"]["received_packets"] == 0' in text
    assert 'payload["encrypted_packet_transfer"]["received_packets"] == 20' in text
    assert 'payload["private_key_recorded"] is False' in text
    assert 'payload["private_key_serialized"] is False' in text
    assert 'payload["preshared_key_used"] is False' in text
    assert 'payload["production_writer_available"] is False' in text
    assert 'payload["transport_exposed_to_product"] is False' in text
    assert 'payload["write_authorized"] is False' in text
    assert 'payload["physical_router_targeted"] is False' in text
    assert "actions/upload-artifact@v4" in text
    assert "prepared.json" not in text
    assert "serial.log" not in text
