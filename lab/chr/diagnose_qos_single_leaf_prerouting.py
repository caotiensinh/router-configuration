from __future__ import annotations

from typing import Any, Mapping

import diagnose_qos_single_leaf as single
import diagnose_qos_flat_global as flat
import verify_qos_packet_flow as flow
import verify_render_dry_run as base


PREROUTING_INGRESS = "ether3"
LAB_EF_COMMENT = "routercfg:lab:qos-pre:ef"


def install(
    *,
    admin_url: str,
    prepare_payload: Mapping[str, Any],
    mode: str,
    queue: str,
) -> dict[str, Any]:
    """Lab-only timing probe: mark one class in prerouting before one global leaf."""
    if mode not in {"default", "ef"}:
        raise flow.CHRQoSPacketFlowError("prerouting timing probe supports default or ef mode only")
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

    ef_mark = str(target.get("packet_mark") or "")
    production_ef_comment = str(target.get("comment") or "")
    if not ef_mark or not production_ef_comment:
        raise flow.CHRQoSPacketFlowError("prerouting timing probe requires production EF mark facts")

    commands = [
        f"/queue/tree/remove [find where name={flat._quote(name)}]"
        for name in single._remove_queue_names(target)
    ]
    commands.extend(
        (
            f"/ip/firewall/mangle/remove [find where comment={flat._quote(flat.DEFAULT_COMMENT)}]",
            f"/ip/firewall/mangle/remove [find where comment={flat._quote(LAB_EF_COMMENT)}]",
        )
    )

    if mode == "default":
        mark = flat.DEFAULT_MARK
        comment = flat.DEFAULT_COMMENT
        leaf = single.SINGLE_DEFAULT_LEAF
        commands.extend(
            (
                (
                    f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(PREROUTING_INGRESS)} "
                    f"packet-mark=no-mark action=mark-packet new-packet-mark={flat._quote(mark)} "
                    f"passthrough=no comment={flat._quote(comment)} disabled=no"
                ),
                (
                    f"/queue/tree/add name={flat._quote(leaf)} parent=global "
                    f"packet-mark={flat._quote(mark)} queue=default-small "
                    "max-limit=100M disabled=no"
                ),
            )
        )
        production_ef_rule_removed = False
    else:
        mark = ef_mark
        comment = LAB_EF_COMMENT
        leaf = single.SINGLE_EF_LEAF
        commands.extend(
            (
                f"/ip/firewall/mangle/remove [find where comment={flat._quote(production_ef_comment)}]",
                (
                    f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(PREROUTING_INGRESS)} "
                    f"dscp=46 packet-mark=no-mark action=mark-packet new-packet-mark={flat._quote(mark)} "
                    f"passthrough=no comment={flat._quote(comment)} disabled=no"
                ),
                (
                    f"/queue/tree/add name={flat._quote(leaf)} parent=global "
                    f"packet-mark={flat._quote(mark)} queue=default-small "
                    "max-limit=100M disabled=no"
                ),
            )
        )
        production_ef_rule_removed = True

    execute = flat._execute(admin, "\n".join(commands) + "\n")

    trees = flat._rows(admin, "queue/tree")
    selected = flat._one(
        trees,
        key="name",
        value=leaf,
        label=f"prerouting single {mode} leaf",
    )
    sibling = single.SINGLE_EF_LEAF if mode == "default" else single.SINGLE_DEFAULT_LEAF
    if any(str(row.get("name") or "") == sibling for row in trees):
        raise flow.CHRQoSPacketFlowError("prerouting timing probe unexpectedly retained sibling leaf")
    if str(selected.get("parent") or "") != "global":
        raise flow.CHRQoSPacketFlowError("prerouting single leaf parent is not global")
    if str(selected.get("packet-mark") or "") != mark:
        raise flow.CHRQoSPacketFlowError("prerouting single leaf packet mark mismatch")
    if str(selected.get("queue") or "") != "default-small":
        raise flow.CHRQoSPacketFlowError("prerouting single leaf queue type mismatch")
    if base._is_true(selected.get("invalid")) or base._is_true(selected.get("disabled")):
        raise flow.CHRQoSPacketFlowError("prerouting single leaf is invalid or disabled")

    rule = flat._one(
        flat._rows(admin, "ip/firewall/mangle"),
        key="comment",
        value=comment,
        label=f"prerouting {mode} mangle",
    )
    if str(rule.get("chain") or "") != "prerouting":
        raise flow.CHRQoSPacketFlowError("timing probe mangle chain is not prerouting")
    if str(rule.get("in-interface") or "") != PREROUTING_INGRESS:
        raise flow.CHRQoSPacketFlowError("timing probe mangle ingress is not ether3")
    if str(rule.get("new-packet-mark") or "") != mark:
        raise flow.CHRQoSPacketFlowError("timing probe mangle mark mismatch")
    if mode == "ef" and str(rule.get("dscp") or "") != "46":
        raise flow.CHRQoSPacketFlowError("timing probe EF mangle did not retain DSCP 46")

    return {
        "ok": True,
        "runtime_valid": True,
        "scope": "prerouting_single_mark_to_single_global_leaf_timing_probe",
        "mode": mode,
        "queue": "default-small",
        "interface": "ether2",
        "ingress_interface": PREROUTING_INGRESS,
        "mark_chain": "prerouting",
        "leaf": leaf,
        "packet_mark": mark,
        "mangle_comment": comment,
        "sibling_leaf_present": False,
        "priority_configured": False,
        "limit_at_configured": False,
        "same_production_ef_packet_mark": mode == "ef",
        "production_ef_rule_removed_in_disposable_lab": production_ef_rule_removed,
        "production_renderer_modified": False,
        "production_packet_flow_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
        "execute": dict(execute),
    }


def cleanup(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    commands = (
        f"/queue/tree/remove [find where name={flat._quote(single.SINGLE_DEFAULT_LEAF)}]",
        f"/queue/tree/remove [find where name={flat._quote(single.SINGLE_EF_LEAF)}]",
        f"/ip/firewall/mangle/remove [find where comment={flat._quote(flat.DEFAULT_COMMENT)}]",
        f"/ip/firewall/mangle/remove [find where comment={flat._quote(LAB_EF_COMMENT)}]",
    )
    execute = flat._execute(admin, "\n".join(commands) + "\n")
    remaining_tree = [
        row
        for row in flat._rows(admin, "queue/tree")
        if str(row.get("name") or "") in {single.SINGLE_DEFAULT_LEAF, single.SINGLE_EF_LEAF}
    ]
    remaining_lab_rules = [
        row
        for row in flat._rows(admin, "ip/firewall/mangle")
        if str(row.get("comment") or "") in {flat.DEFAULT_COMMENT, LAB_EF_COMMENT}
    ]
    if remaining_tree or remaining_lab_rules:
        raise flow.CHRQoSPacketFlowError("prerouting timing probe cleanup left owned objects")
    return {
        "ok": True,
        "cleanup_complete": True,
        "production_ef_rule_restored": False,
        "disposable_snapshot_required": True,
        "execute": dict(execute),
    }


def main() -> int:
    single.install = install
    single.cleanup = cleanup
    return single.main()


if __name__ == "__main__":
    raise SystemExit(main())
