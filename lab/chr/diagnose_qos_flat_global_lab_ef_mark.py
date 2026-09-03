from __future__ import annotations

from typing import Any, Mapping

import diagnose_qos_flat_global as legacy
import verify_qos_packet_flow as flow
import verify_render_dry_run as base


LAB_EF_MARK = "routercfg-qos-flat-ef-lab"
LAB_EF_COMMENT = "routercfg:lab:qos-flat:ef"


def install(*, admin_url: str, prepare_payload: Mapping[str, Any], queue: str) -> dict[str, Any]:
    """Replace only the production EF mark source inside a disposable CHR lab.

    Queue attachment, queue type, priorities, EF limit-at, default classification,
    traffic topology, and counter/evaluation paths stay aligned with the known
    flat-global experiment. The production renderer itself is not changed.
    """
    if queue not in legacy.SUPPORTED_QUEUES:
        raise flow.CHRQoSPacketFlowError(f"unsupported flat-global queue: {queue}")

    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    target = prepare_payload.get("target")
    if not isinstance(target, Mapping):
        raise flow.CHRQoSPacketFlowError("lab-EF-mark diagnostic requires production prepare target")

    interface = str(target.get("interface") or "")
    production_ef_comment = str(target.get("comment") or "")
    if interface != "ether2" or not production_ef_comment:
        raise flow.CHRQoSPacketFlowError("lab-EF-mark diagnostic requires rendered ether2 EF facts")

    if queue == "routercfg-qos-fq":
        qtypes = [
            row
            for row in legacy._rows(admin, "queue/type")
            if str(row.get("name") or "") == queue
        ]
        if len(qtypes) != 1 or str(qtypes[0].get("kind") or "").lower() != "fq-codel":
            raise flow.CHRQoSPacketFlowError(
                "lab-EF-mark FQ-CoDel queue type is not available from production prepare"
            )

    remove_names = {
        str(target.get("priority_queue") or ""),
        str(target.get("default_queue") or ""),
        str(target.get("parent_queue") or ""),
        "routercfg-qos-diag-interface",
        "routercfg-qos-diag-global",
        "routercfg-qos-diag-global-parent",
        "routercfg-qos-diag-global-default",
        "routercfg-qos-diag-global-ef",
        legacy.DEFAULT_LEAF,
        legacy.EF_LEAF,
    }
    commands = [
        f"/queue/tree/remove [find where name={legacy._quote(name)}]"
        for name in sorted(remove_names)
        if name
    ]
    commands.extend(
        (
            f"/ip/firewall/mangle/remove [find where comment={legacy._quote(production_ef_comment)}]",
            f"/ip/firewall/mangle/remove [find where comment={legacy._quote(LAB_EF_COMMENT)}]",
            f"/ip/firewall/mangle/remove [find where comment={legacy._quote(legacy.DEFAULT_COMMENT)}]",
            (
                f"/ip/firewall/mangle/add chain=forward out-interface={legacy._quote(interface)} "
                "dscp=46 packet-mark=no-mark action=mark-packet "
                f"new-packet-mark={legacy._quote(LAB_EF_MARK)} passthrough=no "
                f"comment={legacy._quote(LAB_EF_COMMENT)} disabled=no"
            ),
            (
                f"/ip/firewall/mangle/add chain=forward out-interface={legacy._quote(interface)} "
                f"packet-mark=no-mark action=mark-packet new-packet-mark={legacy._quote(legacy.DEFAULT_MARK)} "
                f"passthrough=no comment={legacy._quote(legacy.DEFAULT_COMMENT)} disabled=no"
            ),
            (
                f"/queue/tree/add name={legacy._quote(legacy.EF_LEAF)} parent=global "
                f"packet-mark={legacy._quote(LAB_EF_MARK)} queue={legacy._quote(queue)} "
                "priority=1 limit-at=10M max-limit=100M disabled=no"
            ),
            (
                f"/queue/tree/add name={legacy._quote(legacy.DEFAULT_LEAF)} parent=global "
                f"packet-mark={legacy._quote(legacy.DEFAULT_MARK)} queue={legacy._quote(queue)} "
                "priority=8 max-limit=100M disabled=no"
            ),
        )
    )
    execute = legacy._execute(admin, "\n".join(commands) + "\n")

    mangle = legacy._rows(admin, "ip/firewall/mangle")
    ef_rule = legacy._one(
        mangle,
        key="comment",
        value=LAB_EF_COMMENT,
        label="lab EF mangle",
    )
    default_rule = legacy._one(
        mangle,
        key="comment",
        value=legacy.DEFAULT_COMMENT,
        label="flat default mangle",
    )
    trees = legacy._rows(admin, "queue/tree")
    default = legacy._one(
        trees,
        key="name",
        value=legacy.DEFAULT_LEAF,
        label="flat default leaf",
    )
    ef = legacy._one(trees, key="name", value=legacy.EF_LEAF, label="flat EF leaf")

    invalid = sum(1 for row in (default, ef) if base._is_true(row.get("invalid")))
    disabled = sum(1 for row in (default, ef) if base._is_true(row.get("disabled")))
    if invalid or disabled:
        raise flow.CHRQoSPacketFlowError(f"lab-EF-mark leaves invalid={invalid} disabled={disabled}")
    if str(ef_rule.get("new-packet-mark") or "") != LAB_EF_MARK:
        raise flow.CHRQoSPacketFlowError("lab EF mangle did not retain the isolated mark")
    if str(ef_rule.get("dscp") or "") != "46":
        raise flow.CHRQoSPacketFlowError("lab EF mangle did not retain DSCP 46")
    if str(default_rule.get("new-packet-mark") or "") != legacy.DEFAULT_MARK:
        raise flow.CHRQoSPacketFlowError("flat-global default mark was not retained")

    for row, mark, label in (
        (ef, LAB_EF_MARK, "EF"),
        (default, legacy.DEFAULT_MARK, "default"),
    ):
        if str(row.get("parent") or "") != "global":
            raise flow.CHRQoSPacketFlowError(f"lab-EF-mark {label} leaf parent is not global")
        if str(row.get("packet-mark") or "") != mark:
            raise flow.CHRQoSPacketFlowError(f"lab-EF-mark {label} leaf packet mark mismatch")
        if str(row.get("queue") or "") != queue:
            raise flow.CHRQoSPacketFlowError(f"lab-EF-mark {label} leaf queue type mismatch")

    return {
        "ok": True,
        "runtime_valid": True,
        "scope": "single_variable_lab_ef_mark_source_flat_global",
        "interface": interface,
        "queue": queue,
        "default_leaf": legacy.DEFAULT_LEAF,
        "ef_leaf": legacy.EF_LEAF,
        "default_mark": legacy.DEFAULT_MARK,
        "ef_mark": LAB_EF_MARK,
        "default_comment": legacy.DEFAULT_COMMENT,
        "ef_comment": LAB_EF_COMMENT,
        "ef_priority": 1,
        "ef_limit_at": "10M",
        "production_ef_rule_replaced_in_disposable_lab": True,
        "production_renderer_modified": False,
        "execute": dict(execute),
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def cleanup(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    commands = (
        f"/queue/tree/remove [find where name={legacy._quote(legacy.EF_LEAF)}]",
        f"/queue/tree/remove [find where name={legacy._quote(legacy.DEFAULT_LEAF)}]",
        f"/ip/firewall/mangle/remove [find where comment={legacy._quote(LAB_EF_COMMENT)}]",
        f"/ip/firewall/mangle/remove [find where comment={legacy._quote(legacy.DEFAULT_COMMENT)}]",
    )
    execute = legacy._execute(admin, "\n".join(commands) + "\n")
    remaining_tree = [
        row
        for row in legacy._rows(admin, "queue/tree")
        if str(row.get("name") or "") in {legacy.DEFAULT_LEAF, legacy.EF_LEAF}
    ]
    remaining_rule = [
        row
        for row in legacy._rows(admin, "ip/firewall/mangle")
        if str(row.get("comment") or "") in {LAB_EF_COMMENT, legacy.DEFAULT_COMMENT}
    ]
    if remaining_tree or remaining_rule:
        raise flow.CHRQoSPacketFlowError("lab-EF-mark diagnostic cleanup left owned objects")
    return {"ok": True, "cleanup_complete": True, "execute": dict(execute)}


def main() -> int:
    legacy.install = install
    legacy.cleanup = cleanup
    return legacy.main()


if __name__ == "__main__":
    raise SystemExit(main())
