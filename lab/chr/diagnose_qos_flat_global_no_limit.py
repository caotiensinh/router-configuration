from __future__ import annotations

from typing import Any, Mapping

import diagnose_qos_flat_global as legacy
import verify_qos_packet_flow as flow
import verify_render_dry_run as base


def install(*, admin_url: str, prepare_payload: Mapping[str, Any], queue: str) -> dict[str, Any]:
    """Install the flat-global diagnostic with EF limit-at intentionally omitted.

    This is a lab-only single-variable experiment. It reuses the proven flat-global
    counter/evaluation path and changes only the EF direct-global leaf by removing
    limit-at=10M. Production renderer output is not modified.
    """
    if queue not in legacy.SUPPORTED_QUEUES:
        raise flow.CHRQoSPacketFlowError(f"unsupported flat-global queue: {queue}")

    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    target = prepare_payload.get("target")
    if not isinstance(target, Mapping):
        raise flow.CHRQoSPacketFlowError("flat-global no-limit diagnostic requires production prepare target")

    interface = str(target.get("interface") or "")
    ef_mark = str(target.get("packet_mark") or "")
    ef_comment = str(target.get("comment") or "")
    if interface != "ether2" or not ef_mark or not ef_comment:
        raise flow.CHRQoSPacketFlowError("flat-global no-limit diagnostic requires rendered ether2 EF facts")

    if queue == "routercfg-qos-fq":
        qtypes = [
            row
            for row in legacy._rows(admin, "queue/type")
            if str(row.get("name") or "") == queue
        ]
        if len(qtypes) != 1 or str(qtypes[0].get("kind") or "").lower() != "fq-codel":
            raise flow.CHRQoSPacketFlowError(
                "flat-global no-limit FQ-CoDel queue type is not available from production prepare"
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
            f"/ip/firewall/mangle/remove [find where comment={legacy._quote(legacy.DEFAULT_COMMENT)}]",
            (
                f"/ip/firewall/mangle/add chain=forward out-interface={legacy._quote(interface)} "
                f"packet-mark=no-mark action=mark-packet new-packet-mark={legacy._quote(legacy.DEFAULT_MARK)} "
                f"passthrough=no comment={legacy._quote(legacy.DEFAULT_COMMENT)} disabled=no"
            ),
            (
                f"/queue/tree/add name={legacy._quote(legacy.EF_LEAF)} parent=global "
                f"packet-mark={legacy._quote(ef_mark)} queue={legacy._quote(queue)} "
                "priority=1 max-limit=100M disabled=no"
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
    ef_rule = legacy._one(mangle, key="comment", value=ef_comment, label="production EF mangle")
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
        raise flow.CHRQoSPacketFlowError(
            f"flat-global no-limit leaves invalid={invalid} disabled={disabled}"
        )
    if str(ef_rule.get("new-packet-mark") or "") != ef_mark:
        raise flow.CHRQoSPacketFlowError("production EF mark changed during no-limit diagnostic")
    if str(default_rule.get("new-packet-mark") or "") != legacy.DEFAULT_MARK:
        raise flow.CHRQoSPacketFlowError("flat-global default mark was not retained")

    for row, mark, label in (
        (ef, ef_mark, "EF"),
        (default, legacy.DEFAULT_MARK, "default"),
    ):
        if str(row.get("parent") or "") != "global":
            raise flow.CHRQoSPacketFlowError(f"flat-global {label} leaf parent is not global")
        if str(row.get("packet-mark") or "") != mark:
            raise flow.CHRQoSPacketFlowError(f"flat-global {label} leaf packet mark mismatch")
        if str(row.get("queue") or "") != queue:
            raise flow.CHRQoSPacketFlowError(f"flat-global {label} leaf queue type mismatch")

    return {
        "ok": True,
        "runtime_valid": True,
        "scope": "single_wan_flat_global_no_limit_default_and_ef_leaves",
        "interface": interface,
        "queue": queue,
        "default_leaf": legacy.DEFAULT_LEAF,
        "ef_leaf": legacy.EF_LEAF,
        "default_mark": legacy.DEFAULT_MARK,
        "ef_mark": ef_mark,
        "default_comment": legacy.DEFAULT_COMMENT,
        "ef_comment": ef_comment,
        "ef_limit_at_configured": False,
        "execute": dict(execute),
        "production_renderer_modified": False,
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    legacy.install = install
    return legacy.main()


if __name__ == "__main__":
    raise SystemExit(main())
