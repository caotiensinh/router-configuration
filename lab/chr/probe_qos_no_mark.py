from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


class CHRQoSNoMarkProbeError(RuntimeError):
    pass


APPLY_FILE = "routercfg-qos-probe-a-apply.rsc"
ROLLBACK_FILE = "routercfg-qos-probe-a-rollback.rsc"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, mutation.VERDICT_FILE)
QUEUE_TYPE = "routercfg-qos-probe-fq"
PARENT = "routercfg-qos-probe-parent"
VOICE = "routercfg-qos-probe-voice"
DEFAULT = "routercfg-qos-probe-default"
COMMENT = "routercfg:managed:qos-probe-a:voice"


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _norm(admin: base.LoopbackCHRAdmin, path: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _records(admin, path):
        if base._is_true(row.get("dynamic")):
            continue
        rows.append({field: row[field] for field in fields if field in row})
    rows.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return rows


def _snapshot(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "mangle": _norm(
            admin,
            "ip/firewall/mangle",
            ("chain", "out-interface", "dscp", "packet-mark", "action", "new-packet-mark", "passthrough", "comment", "disabled"),
        ),
        "queue_tree": _norm(
            admin,
            "queue/tree",
            ("name", "parent", "packet-mark", "queue", "priority", "limit-at", "max-limit", "disabled"),
        ),
        "queue_type": _norm(admin, "queue/type", ("name", "kind")),
    }


def _apply_script() -> str:
    return "\n".join(
        (
            f"/queue/type/add name={QUEUE_TYPE} kind=fq-codel",
            f"/ip/firewall/mangle/add chain=forward out-interface=ether2 dscp=46 packet-mark=no-mark action=mark-packet new-packet-mark={VOICE} passthrough=no comment={COMMENT} disabled=no",
            f"/queue/tree/add name={PARENT} parent=ether2 max-limit=100M disabled=no",
            f"/queue/tree/add name={VOICE} parent={PARENT} packet-mark={VOICE} queue={QUEUE_TYPE} priority=1 limit-at=10M max-limit=100M disabled=no",
            f"/queue/tree/add name={DEFAULT} parent={PARENT} packet-mark=no-mark queue={QUEUE_TYPE} priority=8 limit-at=1M max-limit=100M disabled=no",
        )
    ) + "\n"


def _rollback_script() -> str:
    return "\n".join(
        (
            f'/queue/tree/remove [find where name="{DEFAULT}"]',
            f'/queue/tree/remove [find where name="{VOICE}"]',
            f'/queue/tree/remove [find where name="{PARENT}"]',
            f'/ip/firewall/mangle/remove [find where comment="{COMMENT}"]',
            f'/queue/type/remove [find where name="{QUEUE_TYPE}"]',
        )
    ) + "\n"


def _one(rows: list[Mapping[str, Any]], *, label: str, predicate) -> Mapping[str, Any]:
    matches = [row for row in rows if predicate(row)]
    if len(matches) != 1:
        raise CHRQoSNoMarkProbeError(f"expected exactly one {label}, observed {len(matches)}")
    return matches[0]


def probe(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = {str(row.get("name") or "") for row in _records(admin, "interface")}
    if not {"ether1", "ether2"}.issubset(interfaces):
        raise CHRQoSNoMarkProbeError("QoS probe requires disposable CHR ether1 management and ether2 test WAN")

    baseline = _snapshot(admin)
    baseline_sha = base._canonical_digest(baseline)
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

    mutated_sha = None
    rollback_sha = None
    try:
        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, _apply_script())
        apply_result = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)

        mangle = _one(
            _records(admin, "ip/firewall/mangle"),
            label="managed voice mangle",
            predicate=lambda row: str(row.get("comment") or "") == COMMENT,
        )
        trees = _records(admin, "queue/tree")
        parent = _one(trees, label="parent queue", predicate=lambda row: str(row.get("name") or "") == PARENT)
        voice = _one(trees, label="voice queue", predicate=lambda row: str(row.get("name") or "") == VOICE)
        default = _one(trees, label="default no-mark queue", predicate=lambda row: str(row.get("name") or "") == DEFAULT)
        qtype = _one(
            _records(admin, "queue/type"),
            label="FQ-CoDel queue type",
            predicate=lambda row: str(row.get("name") or "") == QUEUE_TYPE,
        )
        managed = (mangle, parent, voice, default)
        invalid = sum(1 for row in managed if base._is_true(row.get("invalid")))
        disabled = sum(1 for row in managed if base._is_true(row.get("disabled")))
        if invalid or disabled:
            raise CHRQoSNoMarkProbeError(
                f"QoS no-mark formulation is not runtime-valid: invalid={invalid} disabled={disabled}"
            )
        if str(default.get("packet-mark") or "") != "no-mark":
            raise CHRQoSNoMarkProbeError("default Queue Tree child did not preserve packet-mark=no-mark")
        if str(qtype.get("kind") or "").lower() != "fq-codel":
            raise CHRQoSNoMarkProbeError("managed queue type is not fq-codel")

        mutated_sha = base._canonical_digest(_snapshot(admin))
        if mutated_sha == baseline_sha:
            raise CHRQoSNoMarkProbeError("QoS probe apply did not change configuration digest")

        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, _rollback_script())
        rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
        rollback_sha = base._canonical_digest(_snapshot(admin))
        if rollback_sha != baseline_sha:
            raise CHRQoSNoMarkProbeError("QoS probe rollback did not restore exact baseline digest")
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)

    return {
        "ok": True,
        "acceptance": "PASS",
        "strategy": "default_child_packet_mark_no_mark",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "runtime": {
            "managed_mangle_count": 1,
            "managed_queue_tree_count": 3,
            "invalid_managed_objects": 0,
            "disabled_managed_objects": 0,
            "default_packet_mark": "no-mark",
            "queue_kind": "fq-codel",
        },
        "apply": apply_result,
        "rollback": rollback_result,
        "configuration_baseline_sha256": baseline_sha,
        "configuration_mutated_sha256": mutated_sha,
        "configuration_rollback_sha256": rollback_sha,
        "rollback_digest_restored": rollback_sha == baseline_sha,
        "packet_flow_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe RouterOS Queue Tree no-mark default child on disposable CHR")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9680")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = probe(admin_url=args.admin_url)
        rc = 0
    except Exception as exc:
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "strategy": "default_child_packet_mark_no_mark",
            "error": str(exc),
            "packet_flow_acceptance": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "physical_router_targeted": False,
        }
        rc = 15
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
