from router_configuration.renderer_coverage import (
    RendererCoverageStatus,
    assess_renderer_coverage,
)


def _ir():
    return {
        "schema_version": "config-safe-subset-ir/1",
        "operations": [
            {"operation_id": "topology.wan.wan1", "resource": "wan_role"},
            {"operation_id": "security.baseline", "resource": "firewall_baseline"},
            {"operation_id": "vpn.wireguard", "resource": "wireguard_policy"},
            {"operation_id": "qos.policy", "resource": "traffic_policy"},
        ],
    }


def test_renderer_coverage_separates_execution_boundary_from_renderer_gap():
    plan = {
        "schema_version": "routeros-render-plan/1",
        "commands": [
            {"command_id": "wan.ensure", "operation_id": "topology.wan.wan1"},
        ],
        "blocked_operations": [
            {
                "operation_id": "vpn.wireguard",
                "required_inputs": [
                    "wireguard.private_key_secret_binding",
                    "transaction.authorized_apply_boundary",
                ],
            }
        ],
        "generation_extensions": {
            "enterprise_firewall": {"command_count": 5},
            "qos": {"command_count": 2},
        },
        "deferred_generation_extensions": {"wireguard": {"secrets_resolved": False}},
    }

    report = assess_renderer_coverage(ir=_ir(), render_plan=plan)
    by_id = {item.operation_id: item for item in report.operations}
    assert by_id["topology.wan.wan1"].status is RendererCoverageStatus.RENDERED
    assert by_id["security.baseline"].status is RendererCoverageStatus.RENDERED
    assert by_id["qos.policy"].status is RendererCoverageStatus.RENDERED
    assert by_id["vpn.wireguard"].status is RendererCoverageStatus.DEFERRED_EXECUTION_BOUNDARY
    assert report.renderer_complete is True
    assert report.execution_deferred is True
    assert report.as_dict()["write_authorized"] is False


def test_renderer_coverage_fails_closed_for_unknown_operation():
    ir = {
        "schema_version": "config-safe-subset-ir/1",
        "operations": [{"operation_id": "future.feature", "resource": "future_resource"}],
    }
    plan = {
        "schema_version": "routeros-render-plan/1",
        "commands": [],
        "blocked_operations": [],
        "generation_extensions": {},
        "deferred_generation_extensions": {},
    }
    report = assess_renderer_coverage(ir=ir, render_plan=plan)
    assert report.renderer_complete is False
    assert report.operations[0].status is RendererCoverageStatus.BLOCKED
