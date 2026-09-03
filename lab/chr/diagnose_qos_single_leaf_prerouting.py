from __future__ import annotations

from typing import Any, Mapping

import diagnose_qos_single_leaf as single
import diagnose_qos_flat_global as flat
import verify_qos_packet_flow as flow
import verify_render_dry_run as base


PREROUTING_INGRESS = "ether3"


def install(
    *,
    admin_url: str,
    prepare_payload: Mapping[str, Any],
    mode: str,
    queue: str,
) -> dict[str, Any]:
    """Lab-only timing probe: default mark in prerouting before one global leaf."""
    if mode != "default":
        raise flow.CHRQoSPacketFlowError("prerouting timing probe supports default mode only")
    if queue != "default-small":
        raise flow.CHRQoSPacketFlowError("prerouting timing probe is intentionally bounded to default-small")

    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    target = prepare_payload.get("target")
    if not isinstance(target, Mapping):
        raise flow.CHRQoSPacketFlowError("prerouting timing probe requires production prepare target")
    if str(target.get("interface") or "") != "ether2":
        raise flow.CHRQoSPacketFlowError("prerouting timing probe requires ether2 WAN render target")

    interfaces = {str(row.get("name") or "") for row in flat._rows(admin, "interface")}
    if PREROUTING_INGRESS not in interfaces:
        raise flow.CHRQoSPacketFlowError("prerouting timing probe requires ether3 CORE ingress")

    commands = [
        f"/queue/tree/remove [find where name={flat._quote(name)}]"
        for name in single._remove_queue_names(target)
    ]
    commands.extend(
        (
            f"/ip/firewall/mangle/remove [find where comment={flat._quote(flat.DEFAULT_COMMENT)}]",
            (
                f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(PREROUTING_INGRESS)} "
                f"packet-mark=no-mark action=mark-packet new-packet-mark={flat._quote(flat.DEFAULT_MARK)} "
                f"passthrough=no comment={flat._quote(flat.DEFAULT_COMMENT)} disabled=no"
            ),
            (
                f"/queue/tree/add name={flat._quote(single.SINGLE_DEFAULT_LEAF)} parent=global "
                f"packet-mark={flat._quote(flat.DEFAULT_MARK)} queue=default-small "
                "max-limit=100M disabled=no"
            ),
        )
    )
    execute = flat._execute(admin, "\n".join(commands) + "\n")

    trees = flat._rows(admin, "queue/tree")
    selected = flat._one(
        trees,
        key="name",
        value=single.SINGLE_DEFAULT_LEAF,
        label="prerouting single default leaf",
    )
    if any(str(row.get("name") or "") == single.SINGLE_EF_LEAF for row in trees):
        raise flow.CHRQoSPacketFlowError("prerouting timing probe unexpectedly retained sibling EF leaf")
    if str(selected.get("parent") or "") != "global":
        raise flow.CHRQoSPacketFlowError("prerouting single leaf parent is not global")
    if str(selected.get("packet-mark") or "") != flat.DEFAULT_MARK:
        raise flow.CHRQoSPacketFlowError("prerouting single leaf packet mark mismatch")
    if str(selected.get("queue") or "") != "default-small":
        raise flow.CHRQoSPacketFlowError("prerouting single leaf queue type mismatch")
    if base._is_true(selected.get("invalid")) or base._is_true(selected.get("disabled")):
        raise flow.CHRQoSPacketFlowError("prerouting single leaf is invalid or disabled")

    rule = flat._one(
        flat._rows(admin, "ip/firewall/mangle"),
        key="comment",
        value=flat.DEFAULT_COMMENT,
        label="prerouting default mangle",
    )
    if str(rule.get("chain") or "") != "prerouting":
        raise flow.CHRQoSPacketFlowError("timing probe mangle chain is not prerouting")
    if str(rule.get("in-interface") or "") != PREROUTING_INGRESS:
        raise flow.CHRQoSPacketFlowError("timing probe mangle ingress is not ether3")
    if str(rule.get("new-packet-mark") or "") != flat.DEFAULT_MARK:
        raise flow.CHRQoSPacketFlowError("timing probe mangle mark mismatch")

    return {
        "ok": True,
        "runtime_valid": True,
        "scope": "prerouting_single_mark_to_single_global_leaf_timing_probe",
        "mode": "default",
        "queue": "default-small",
        "interface": "ether2",
        "ingress_interface": PREROUTING_INGRESS,
        "mark_chain": "prerouting",
        "leaf": single.SINGLE_DEFAULT_LEAF,
        "packet_mark": flat.DEFAULT_MARK,
        "mangle_comment": flat.DEFAULT_COMMENT,
        "sibling_leaf_present": False,
        "priority_configured": False,
        "limit_at_configured": False,
        "production_renderer_modified": False,
        "production_packet_flow_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
        "execute": dict(execute),
    }


def main() -> int:
    single.install = install
    return single.main()


if __name__ == "__main__":
    raise SystemExit(main())
