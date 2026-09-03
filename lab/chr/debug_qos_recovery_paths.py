from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import diagnose_qos_flat_global as flat
import diagnose_qos_single_leaf as single
import verify_qos_packet_flow as flow
import verify_render_dry_run as base


INGRESS = "ether3"
WAN = "ether2"
SPECIAL_MARK = "routercfg-qos-rdbg-special"
DEFAULT_MARK = "routercfg-qos-rdbg-default"
SPECIAL_COMMENT = "routercfg:lab:qos-rdbg:special"
DEFAULT_COMMENT = "routercfg:lab:qos-rdbg:default"
PARENT = "routercfg-qos-rdbg-parent"
DEFAULT_QUEUE = "routercfg-qos-rdbg-default"
SPECIAL_QUEUE = "routercfg-qos-rdbg-special"
LANES = {
    "explicit-default-global-hierarchy",
    "interface-prerouting-dscp-hierarchy",
    "global-siblings-no-mark",
}


def _read(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | Path, payload: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _admin(admin_url: str) -> base.LoopbackCHRAdmin:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    return admin


def _rows(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _stats(admin: base.LoopbackCHRAdmin) -> list[Mapping[str, Any]]:
    _, payload = admin.request("POST", "queue/tree/print", {"stats": ""})
    return list(base._rows(payload))


def _one(rows: list[Mapping[str, Any]], *, key: str, value: str, label: str) -> Mapping[str, Any]:
    matches = [row for row in rows if str(row.get(key) or "") == value]
    if len(matches) != 1:
        raise flow.CHRQoSPacketFlowError(f"expected exactly one {label}, observed {len(matches)}")
    return matches[0]


def _pc(row: Mapping[str, Any], label: str) -> int:
    return flow._int_counter(row, "packets", label)


def _target(prepare: Mapping[str, Any]) -> Mapping[str, Any]:
    target = prepare.get("target")
    if not isinstance(target, Mapping):
        raise flow.CHRQoSPacketFlowError("recovery debug requires production prepare target")
    if str(target.get("interface") or "") != WAN:
        raise flow.CHRQoSPacketFlowError("recovery debug requires rendered ether2 WAN target")
    return target


def _owned_names(target: Mapping[str, Any]) -> set[str]:
    names = set(single._remove_queue_names(target))
    names.update({PARENT, DEFAULT_QUEUE, SPECIAL_QUEUE})
    return {name for name in names if name}


def _remove_commands(target: Mapping[str, Any]) -> list[str]:
    commands = [
        f"/queue/tree/remove [find where name={flat._quote(name)}]"
        for name in sorted(_owned_names(target))
    ]
    for comment in (SPECIAL_COMMENT, DEFAULT_COMMENT):
        commands.append(
            f"/ip/firewall/mangle/remove [find where comment={flat._quote(comment)}]"
        )
    prod_comment = str(target.get("comment") or "")
    if prod_comment:
        commands.append(
            f"/ip/firewall/mangle/remove [find where comment={flat._quote(prod_comment)}]"
        )
    return commands


def _execute(admin: base.LoopbackCHRAdmin, commands: list[str]) -> Mapping[str, Any]:
    return flat._execute(admin, "\n".join(commands) + "\n")


def _special_marker() -> str:
    return (
        f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(INGRESS)} "
        f"protocol=udp dscp=46 packet-mark=no-mark action=mark-packet "
        f"new-packet-mark={flat._quote(SPECIAL_MARK)} passthrough=no "
        f"comment={flat._quote(SPECIAL_COMMENT)} disabled=no"
    )


def _default_marker() -> str:
    return (
        f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(INGRESS)} "
        f"protocol=udp packet-mark=no-mark action=mark-packet "
        f"new-packet-mark={flat._quote(DEFAULT_MARK)} passthrough=no "
        f"comment={flat._quote(DEFAULT_COMMENT)} disabled=no"
    )


def install(*, admin_url: str, prepare: Mapping[str, Any], lane: str) -> dict[str, Any]:
    if lane not in LANES:
        raise flow.CHRQoSPacketFlowError(f"unsupported recovery lane: {lane}")
    admin = _admin(admin_url)
    target = _target(prepare)
    commands = _remove_commands(target)
    commands.append(_special_marker())

    if lane == "explicit-default-global-hierarchy":
        commands.append(_default_marker())
        commands.extend(
            (
                f"/queue/tree/add name={flat._quote(PARENT)} parent=global queue=default-small max-limit=100M disabled=no",
                (
                    f"/queue/tree/add name={flat._quote(DEFAULT_QUEUE)} parent={flat._quote(PARENT)} "
                    f"packet-mark={flat._quote(DEFAULT_MARK)} queue=default-small priority=8 max-limit=100M disabled=no"
                ),
                (
                    f"/queue/tree/add name={flat._quote(SPECIAL_QUEUE)} parent={flat._quote(PARENT)} "
                    f"packet-mark={flat._quote(SPECIAL_MARK)} queue=default-small priority=1 "
                    "limit-at=10M max-limit=100M disabled=no"
                ),
            )
        )
        aggregate_parent = True
        default_is_explicitly_marked = True
    elif lane == "interface-prerouting-dscp-hierarchy":
        commands.extend(
            (
                f"/queue/tree/add name={flat._quote(PARENT)} parent={flat._quote(WAN)} queue=default-small max-limit=100M disabled=no",
                (
                    f"/queue/tree/add name={flat._quote(DEFAULT_QUEUE)} parent={flat._quote(PARENT)} "
                    "packet-mark=no-mark queue=default-small priority=8 max-limit=100M disabled=no"
                ),
                (
                    f"/queue/tree/add name={flat._quote(SPECIAL_QUEUE)} parent={flat._quote(PARENT)} "
                    f"packet-mark={flat._quote(SPECIAL_MARK)} queue=default-small priority=1 "
                    "limit-at=10M max-limit=100M disabled=no"
                ),
            )
        )
        aggregate_parent = True
        default_is_explicitly_marked = False
    else:
        commands.extend(
            (
                (
                    f"/queue/tree/add name={flat._quote(DEFAULT_QUEUE)} parent=global packet-mark=no-mark "
                    "queue=default-small priority=8 max-limit=100M disabled=no"
                ),
                (
                    f"/queue/tree/add name={flat._quote(SPECIAL_QUEUE)} parent=global "
                    f"packet-mark={flat._quote(SPECIAL_MARK)} queue=default-small priority=1 "
                    "limit-at=10M max-limit=100M disabled=no"
                ),
            )
        )
        aggregate_parent = False
        default_is_explicitly_marked = False

    execute = _execute(admin, commands)
    trees = _rows(admin, "queue/tree")
    default = _one(trees, key="name", value=DEFAULT_QUEUE, label=f"{lane} default queue")
    special = _one(trees, key="name", value=SPECIAL_QUEUE, label=f"{lane} special queue")
    if base._is_true(default.get("invalid")) or base._is_true(special.get("invalid")):
        raise flow.CHRQoSPacketFlowError(f"{lane} child queue is invalid")
    if aggregate_parent:
        parent = _one(trees, key="name", value=PARENT, label=f"{lane} parent")
        if base._is_true(parent.get("invalid")):
            raise flow.CHRQoSPacketFlowError(f"{lane} parent is invalid")
    return {
        "ok": True,
        "runtime_valid": True,
        "lane": lane,
        "aggregate_parent": aggregate_parent,
        "default_is_explicitly_marked": default_is_explicitly_marked,
        "special_mark_chain": "prerouting",
        "production_classifier_retained": False,
        "production_packet_flow_acceptance": False,
        "production_renderer_modified": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
        "execute": dict(execute),
    }


def counters(*, admin_url: str, lane: str) -> dict[str, Any]:
    admin = _admin(admin_url)
    stats = _stats(admin)
    mangles = _rows(admin, "ip/firewall/mangle")
    default = _one(stats, key="name", value=DEFAULT_QUEUE, label=f"{lane} default stats")
    special = _one(stats, key="name", value=SPECIAL_QUEUE, label=f"{lane} special stats")
    special_rule = _one(mangles, key="comment", value=SPECIAL_COMMENT, label="recovery special marker")
    result: dict[str, Any] = {
        "ok": True,
        "lane": lane,
        "counter_source": "queue_tree_print_stats",
        "default_packets": _pc(default, "recovery_default"),
        "special_packets": _pc(special, "recovery_special"),
        "special_classifier_packets": _pc(special_rule, "recovery_special_classifier"),
    }
    if lane == "explicit-default-global-hierarchy":
        default_rule = _one(mangles, key="comment", value=DEFAULT_COMMENT, label="recovery default marker")
        result["default_classifier_packets"] = _pc(default_rule, "recovery_default_classifier")
    if lane != "global-siblings-no-mark":
        parent = _one(stats, key="name", value=PARENT, label=f"{lane} parent stats")
        result["parent_packets"] = _pc(parent, "recovery_parent")
    return result


def evaluate(
    *,
    lane: str,
    before: Mapping[str, Any],
    after_default: Mapping[str, Any],
    after_special: Mapping[str, Any],
    default_flow: Mapping[str, Any],
    special_flow: Mapping[str, Any],
) -> dict[str, Any]:
    if not flow._flow_ok(default_flow, expected_dscp=0):
        raise flow.CHRQoSPacketFlowError(f"{lane} default flow was not reliable")
    if not flow._flow_ok(special_flow, expected_dscp=46):
        raise flow.CHRQoSPacketFlowError(f"{lane} special flow was not reliable")

    def phase_delta(after: Mapping[str, Any], first: Mapping[str, Any], key: str) -> int:
        return int(after.get(key, 0)) - int(first.get(key, 0))

    default_default = phase_delta(after_default, before, "default_packets")
    default_special = phase_delta(after_default, before, "special_packets")
    default_special_classifier = phase_delta(after_default, before, "special_classifier_packets")
    special_default = phase_delta(after_special, after_default, "default_packets")
    special_special = phase_delta(after_special, after_default, "special_packets")
    special_classifier = phase_delta(after_special, after_default, "special_classifier_packets")

    if default_default <= 0 or default_special != 0 or default_special_classifier != 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} default traffic did not isolate into default queue")
    if special_special <= 0 or special_default != 0 or special_classifier <= 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} EF traffic did not isolate into special queue")

    evidence: dict[str, Any] = {
        "default_queue_packet_delta": default_default,
        "default_to_special_queue_delta": default_special,
        "special_queue_packet_delta": special_special,
        "special_to_default_queue_delta": special_default,
        "special_classifier_packet_delta": special_classifier,
    }
    if lane == "explicit-default-global-hierarchy":
        default_classifier = phase_delta(after_default, before, "default_classifier_packets")
        special_default_classifier = phase_delta(after_special, after_default, "default_classifier_packets")
        if default_classifier <= 0 or special_default_classifier != 0:
            raise flow.CHRQoSPacketFlowError("explicit default marking was not isolated")
        evidence["default_classifier_packet_delta"] = default_classifier
    if lane != "global-siblings-no-mark":
        default_parent = phase_delta(after_default, before, "parent_packets")
        special_parent = phase_delta(after_special, after_default, "parent_packets")
        if default_parent <= 0 or special_parent <= 0:
            raise flow.CHRQoSPacketFlowError(f"{lane} aggregate parent did not observe both classes")
        evidence["default_parent_packet_delta"] = default_parent
        evidence["special_parent_packet_delta"] = special_parent

    return {
        "ok": True,
        "acceptance": "PASS",
        "lane": lane,
        "scope": "disposable_chr_qos_recovery_formulation",
        "evidence": evidence,
        "default_isolated": True,
        "special_isolated": True,
        "aggregate_parent_verified": lane != "global-siblings-no-mark",
        "production_packet_flow_acceptance": False,
        "production_renderer_modified": False,
        "aggregate_shaping_claimed": False,
        "latency_performance_claimed": False,
        "bandwidth_guarantee_claimed": False,
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def cleanup(*, admin_url: str, prepare: Mapping[str, Any]) -> dict[str, Any]:
    admin = _admin(admin_url)
    target = _target(prepare)
    execute = _execute(admin, _remove_commands(target))
    return {
        "ok": True,
        "cleanup_complete": True,
        "production_packet_flow_acceptance": False,
        "execute": dict(execute),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Disposable CHR fallback QoS recovery formulations")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("install")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
    p.add_argument("--lane", choices=sorted(LANES), required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("counters")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--lane", choices=sorted(LANES), required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("evaluate")
    p.add_argument("--lane", choices=sorted(LANES), required=True)
    for flag in ("before", "after-default", "after-special", "default-flow", "special-flow"):
        p.add_argument(f"--{flag}", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("cleanup")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
    p.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.command == "install":
        result = install(admin_url=args.admin_url, prepare=_read(args.prepare), lane=args.lane)
    elif args.command == "counters":
        result = counters(admin_url=args.admin_url, lane=args.lane)
    elif args.command == "evaluate":
        result = evaluate(
            lane=args.lane,
            before=_read(args.before),
            after_default=_read(args.after_default),
            after_special=_read(args.after_special),
            default_flow=_read(args.default_flow),
            special_flow=_read(args.special_flow),
        )
    else:
        result = cleanup(admin_url=args.admin_url, prepare=_read(args.prepare))
    _write(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
