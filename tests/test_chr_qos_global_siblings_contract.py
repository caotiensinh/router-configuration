from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "lab" / "chr" / "verify_qos_global_siblings.py"
RUNNER = ROOT / "lab" / "chr" / "run_qos_global_siblings_acceptance.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-global-siblings.yml"
PROBE = ROOT / "lab" / "chr" / "udp_flow_probe.py"


def test_qos_global_sibling_gate_uses_production_renderer_and_conservative_claims():
    source = VERIFIER.read_text(encoding="utf-8")
    assert "from router_configuration.routeros_qos_renderer import render_routeros_qos" in source
    assert "global_sibling_fq_codel_unmarked_default_marked_priority" in source
    assert '"packet_flow_acceptance": True' in source
    assert '"aggregate_shaping_claimed": False' in source
    assert '"bandwidth_guarantee_claimed": False' in source
    assert '"latency_performance_claimed": False' in source
    assert '"production_writer_available": False' in source
    assert '"write_authorized": False' in source
    assert '"physical_router_targeted": False' in source
    assert "parent_queue" not in source


def test_qos_global_sibling_runner_drives_dscp0_and_dscp46_and_exact_rollback():
    source = RUNNER.read_text(encoding="utf-8")
    assert "--dscp 0" not in source  # the probe helper receives the variable argument
    assert "probe 22000 0" in source
    assert "probe 24000 46" in source
    assert "verify_qos_global_siblings.py" in source
    assert "finalize" in source
    assert "diagnose_qos" not in source


def test_qos_global_sibling_workflow_runs_on_production_renderer_changes():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert 'src/router_configuration/routeros_qos_renderer.py' in source
    assert "run_qos_global_siblings_acceptance.sh" in source
    assert "actions/upload-artifact@v4" in source
    assert 'CHR_VERSION: "7.24.1"' in source


def test_udp_probe_supports_explicit_dscp_without_changing_default():
    source = PROBE.read_text(encoding="utf-8")
    assert 'parser.add_argument("--dscp", type=int, default=0)' in source
    assert "socket.IP_TOS" in source
    assert "args.dscp << 2" in source
