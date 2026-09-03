from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import verify_wireguard_baseline as baseline
from router_configuration.routeros_wireguard_renderer import PRIVATE_KEY_PLACEHOLDER


class CHRWireGuardHandshakeError(RuntimeError):
    pass


UNDERLAY_ADDRESS = "192.0.2.2/30"
UNDERLAY_INTERFACE = "ether2"
UNDERLAY_COMMENT = "routercfg:lab:wg-handshake:underlay"
APPLY_FILE = "routercfg-wg-handshake-apply.rsc"
ROLLBACK_FILE = "routercfg-wg-handshake-rollback.rsc"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, baseline.mutation.VERDICT_FILE)


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _records(admin: baseline.base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(baseline.base._rows(payload))


def _digest(admin: baseline.base.LoopbackCHRAdmin) -> str:
    return baseline.base._canonical_digest(baseline._configuration_snapshot(admin))


def _find_underlay(admin: baseline.base.LoopbackCHRAdmin) -> Mapping[str, Any] | None:
    return next(
        (
            row
            for row in _records(admin, "ip/address")
            if str(row.get("comment") or "") == UNDERLAY_COMMENT
        ),
        None,
    )


def _create_underlay(admin: baseline.base.LoopbackCHRAdmin) -> None:
    if _find_underlay(admin) is not None:
        raise CHRWireGuardHandshakeError("disposable CHR already contains the WireGuard lab underlay address")
    admin.request(
        "PUT",
        "ip/address",
        {
            "address": UNDERLAY_ADDRESS,
            "interface": UNDERLAY_INTERFACE,
            "comment": UNDERLAY_COMMENT,
            "disabled": False,
        },
    )
    row = _find_underlay(admin)
    if row is None:
        raise CHRWireGuardHandshakeError("CHR did not expose the WireGuard lab underlay address")
    if (
        str(row.get("address") or "") != UNDERLAY_ADDRESS
        or str(row.get("interface") or "") != UNDERLAY_INTERFACE
    ):
        raise CHRWireGuardHandshakeError("WireGuard lab underlay address does not match the requested topology")


def _remove_underlay(admin: baseline.base.LoopbackCHRAdmin) -> None:
    row = _find_underlay(admin)
    if row is None:
        return
    row_id = str(row.get(".id") or "").strip()
    if not row_id:
        raise CHRWireGuardHandshakeError("WireGuard lab underlay address has no RouterOS id")
    admin.request("DELETE", f"ip/address/{row_id}")
    if _find_underlay(admin) is not None:
        raise CHRWireGuardHandshakeError("WireGuard lab underlay address remains after cleanup")


def _managed_interface(admin: baseline.base.LoopbackCHRAdmin) -> Mapping[str, Any]:
    rows = [
        row
        for row in _records(admin, "interface/wireguard")
        if str(row.get("comment") or "") == baseline.COMMENT_PREFIX + "interface"
    ]
    if len(rows) != 1:
        raise CHRWireGuardHandshakeError(f"expected one managed WireGuard interface, observed {len(rows)}")
    return rows[0]


def _managed_peer(admin: baseline.base.LoopbackCHRAdmin) -> Mapping[str, Any]:
    rows = [
        row
        for row in _records(admin, "interface/wireguard/peers")
        if str(row.get("comment") or "").startswith(baseline.COMMENT_PREFIX + "peer:")
    ]
    if len(rows) != 1:
        raise CHRWireGuardHandshakeError(f"expected one managed WireGuard peer, observed {len(rows)}")
    return rows[0]


def _integer_field(row: Mapping[str, Any], field: str) -> int:
    raw = row.get(field)
    if isinstance(raw, bool):
        raise CHRWireGuardHandshakeError(f"WireGuard peer field {field!r} is not numeric")
    try:
        value = int(str(raw or "0").strip())
    except ValueError as exc:
        raise CHRWireGuardHandshakeError(f"WireGuard peer field {field!r} is not numeric: {raw!r}") from exc
    return value


def _peer_observation(admin: baseline.base.LoopbackCHRAdmin) -> dict[str, Any]:
    peer = _managed_peer(admin)
    handshake = str(peer.get("last-handshake") or "").strip()
    rx = _integer_field(peer, "rx")
    tx = _integer_field(peer, "tx")
    return {
        "last_handshake_present": bool(handshake) and handshake.lower() not in {"never", "none"},
        "rx_bytes": rx,
        "tx_bytes": tx,
        "current_endpoint_present": bool(str(peer.get("current-endpoint-address") or "").strip()),
    }


def _build_apply_script(*, remote_public_key: str) -> tuple[str, dict[str, Any], str]:
    ir = baseline._build_ir(remote_public_key)
    plan = baseline.render_routeros_wireguard(ir=ir).as_dict()
    templates = plan.get("command_templates")
    if not isinstance(templates, list) or len(templates) != 4:
        raise CHRWireGuardHandshakeError("WireGuard handshake gate requires exactly four production templates")
    private_key = baseline._ephemeral_private_key()
    lines: list[str] = []
    placeholder_count = 0
    for item in templates:
        if not isinstance(item, Mapping):
            raise CHRWireGuardHandshakeError("WireGuard production template plan contains a non-object")
        template = str(item.get("template") or "")
        if PRIVATE_KEY_PLACEHOLDER in template:
            placeholder_count += template.count(PRIVATE_KEY_PLACEHOLDER)
        lines.append(template.replace(PRIVATE_KEY_PLACEHOLDER, private_key))
    if placeholder_count != 1:
        raise CHRWireGuardHandshakeError(
            f"expected exactly one private-key placeholder binding, observed {placeholder_count}"
        )
    return "\n".join(lines) + "\n", plan, private_key


def _assert_negative_probe(payload: Mapping[str, Any]) -> dict[str, Any]:
    requested = int(payload.get("requested_packets") or 0)
    received = int(payload.get("received_packets") or 0)
    parse_ok = payload.get("parse_ok") is True
    if requested <= 0 or not parse_ok or received != 0:
        raise CHRWireGuardHandshakeError(
            f"WireGuard negative control unexpectedly transferred traffic: requested={requested} received={received} parse_ok={parse_ok}"
        )
    return {
        "requested_packets": requested,
        "received_packets": 0,
        "blocked_before_peer_activation": True,
    }


def _assert_positive_probe(payload: Mapping[str, Any]) -> dict[str, Any]:
    requested = int(payload.get("requested_packets") or 0)
    received = int(payload.get("received_packets") or 0)
    parse_ok = payload.get("parse_ok") is True
    if requested <= 0 or not parse_ok or received != requested:
        raise CHRWireGuardHandshakeError(
            f"WireGuard measured tunnel transfer failed: requested={requested} received={received} parse_ok={parse_ok}"
        )
    return {
        "requested_packets": requested,
        "received_packets": received,
        "success_ratio": 1.0,
    }


def _assert_linux_stats(payload: Mapping[str, Any]) -> dict[str, Any]:
    handshake = int(payload.get("latest_handshake_epoch") or 0)
    rx = int(payload.get("rx_bytes") or 0)
    tx = int(payload.get("tx_bytes") or 0)
    if handshake <= 0 or rx <= 0 or tx <= 0:
        raise CHRWireGuardHandshakeError(
            f"Linux WireGuard peer did not expose handshake/transfer counters: handshake={handshake} rx={rx} tx={tx}"
        )
    return {
        "latest_handshake_present": True,
        "rx_bytes_positive": True,
        "tx_bytes_positive": True,
    }


def prepare(*, admin_url: str, workflow_sha: str, remote_public_key: str) -> dict[str, Any]:
    admin = baseline.base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = {str(row.get("name") or "") for row in _records(admin, "interface")}
    missing = sorted({"ether1", UNDERLAY_INTERFACE} - interfaces)
    if missing:
        raise CHRWireGuardHandshakeError(f"disposable CHR is missing WireGuard handshake interfaces: {missing}")
    if not baseline._owned_objects_absent(admin):
        raise CHRWireGuardHandshakeError("disposable CHR baseline already contains routercfg-owned WireGuard objects")
    if _find_underlay(admin) is not None:
        raise CHRWireGuardHandshakeError("disposable CHR baseline already contains WireGuard lab underlay")

    for name in TEMP_FILES:
        baseline.base._delete_file_if_present(admin, name)
    original_digest = _digest(admin)
    _create_underlay(admin)
    setup_digest = _digest(admin)
    if setup_digest == original_digest:
        raise CHRWireGuardHandshakeError("WireGuard underlay setup did not change configuration digest")

    apply_script, plan, private_key = _build_apply_script(remote_public_key=remote_public_key)
    try:
        baseline.chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
        apply_result = baseline.mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)
    finally:
        private_key = ""
        apply_script = ""
        baseline.base._delete_file_if_present(admin, APPLY_FILE)
        baseline.base._delete_file_if_present(admin, baseline.mutation.VERDICT_FILE)

    mutated_digest = _digest(admin)
    if mutated_digest == setup_digest:
        raise CHRWireGuardHandshakeError("WireGuard production-template apply did not change configuration digest")
    runtime = baseline._runtime_state(admin)
    interface = _managed_interface(admin)
    chr_public_key = str(interface.get("public-key") or "").strip()
    if not chr_public_key:
        raise CHRWireGuardHandshakeError("managed WireGuard interface did not expose its public key")
    before = _peer_observation(admin)
    if before["last_handshake_present"] or before["rx_bytes"] > 0 or before["tx_bytes"] > 0:
        raise CHRWireGuardHandshakeError("WireGuard peer already shows handshake/transfer before remote peer activation")

    return {
        "ok": True,
        "acceptance": "PREPARED",
        "workflow_sha": workflow_sha,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "renderer": {
            "production_renderer_used": True,
            "template_count": int(plan.get("template_count") or 0),
            "deferred_secret_binding": True,
            "secrets_resolved_by_product": bool(plan.get("secrets_resolved")),
            "transport_present": bool(plan.get("transport_present")),
            "apply_available": bool(plan.get("apply_available")),
            "write_authorized": bool(plan.get("write_authorized")),
        },
        "lab_secret_binding": {
            "ephemeral_private_key_used": True,
            "ephemeral_private_key_recorded": False,
            "private_key_serialized_to_evidence": False,
            "preshared_key_used": False,
            "remote_public_key_sha256": _sha256_text(remote_public_key),
            "chr_public_key_sha256": _sha256_text(chr_public_key),
        },
        "chr_public_key": chr_public_key,
        "runtime": runtime,
        "peer_before_activation": before,
        "apply": {"verdict": str(apply_result.get("verdict") or "")},
        "configuration_original_sha256": original_digest,
        "configuration_setup_sha256": setup_digest,
        "configuration_mutated_sha256": mutated_digest,
        "handshake_acceptance": False,
        "encrypted_packet_transfer_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def finalize(
    *,
    admin_url: str,
    prepared: Mapping[str, Any],
    negative_probe: Mapping[str, Any],
    positive_probe: Mapping[str, Any],
    linux_stats: Mapping[str, Any],
) -> dict[str, Any]:
    admin = baseline.base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    negative = _assert_negative_probe(negative_probe)
    positive = _assert_positive_probe(positive_probe)
    linux = _assert_linux_stats(linux_stats)
    after = _peer_observation(admin)
    if not after["last_handshake_present"] or after["rx_bytes"] <= 0 or after["tx_bytes"] <= 0:
        raise CHRWireGuardHandshakeError(
            "RouterOS WireGuard peer did not expose a completed handshake with positive transfer counters"
        )
    if not after["current_endpoint_present"]:
        raise CHRWireGuardHandshakeError("RouterOS WireGuard peer did not learn a current endpoint")
    admin.request("GET", "system/resource")

    rollback_script = baseline._rollback_script()
    baseline.chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
    rollback_result = baseline.mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
    if not baseline._owned_objects_absent(admin):
        raise CHRWireGuardHandshakeError("routercfg-owned WireGuard objects remain after handshake rollback")
    setup_digest = str(prepared.get("configuration_setup_sha256") or "")
    rollback_digest = _digest(admin)
    if rollback_digest != setup_digest:
        raise CHRWireGuardHandshakeError("WireGuard rollback did not restore exact underlay setup digest")

    _remove_underlay(admin)
    cleanup_digest = _digest(admin)
    original_digest = str(prepared.get("configuration_original_sha256") or "")
    if cleanup_digest != original_digest:
        raise CHRWireGuardHandshakeError("WireGuard lab underlay cleanup did not restore original digest")
    for name in TEMP_FILES:
        baseline.base._delete_file_if_present(admin, name)
    baseline.base._assert_files_absent(admin, TEMP_FILES)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_wireguard_handshake_and_encrypted_icmp_transfer",
        "workflow_sha": str(prepared.get("workflow_sha") or ""),
        "platform": dict(prepared.get("platform") or {}),
        "renderer": dict(prepared.get("renderer") or {}),
        "lab_secret_binding": dict(prepared.get("lab_secret_binding") or {}),
        "negative_control": negative,
        "encrypted_packet_transfer": positive,
        "routeros_peer_after_transfer": {
            "last_handshake_present": True,
            "rx_bytes_positive": True,
            "tx_bytes_positive": True,
            "current_endpoint_present": True,
        },
        "linux_peer_after_transfer": linux,
        "handshake_acceptance": True,
        "encrypted_packet_transfer_acceptance": True,
        "rollback": {"verdict": str(rollback_result.get("verdict") or "")},
        "configuration_original_sha256": original_digest,
        "configuration_setup_sha256": setup_digest,
        "configuration_mutated_sha256": str(prepared.get("configuration_mutated_sha256") or ""),
        "configuration_rollback_sha256": rollback_digest,
        "configuration_cleanup_sha256": cleanup_digest,
        "rollback_digest_restored": True,
        "lab_setup_cleanup_restored": True,
        "temporary_files_removed": True,
        "management_rest_reachable_after_transfer": True,
        "private_key_recorded": False,
        "private_key_serialized": False,
        "preshared_key_used": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove WireGuard handshake and encrypted packet transfer on disposable CHR")
    sub = parser.add_subparsers(dest="command", required=True)

    p_prepare = sub.add_parser("prepare")
    p_prepare.add_argument("--admin-url", default="http://127.0.0.1:10380")
    p_prepare.add_argument("--workflow-sha", required=True)
    p_prepare.add_argument("--remote-public-key", required=True)
    p_prepare.add_argument("--output", required=True)

    p_final = sub.add_parser("finalize")
    p_final.add_argument("--admin-url", default="http://127.0.0.1:10380")
    p_final.add_argument("--prepared", required=True)
    p_final.add_argument("--negative-probe", required=True)
    p_final.add_argument("--positive-probe", required=True)
    p_final.add_argument("--linux-stats", required=True)
    p_final.add_argument("--output", required=True)

    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        if args.command == "prepare":
            result = prepare(
                admin_url=args.admin_url,
                workflow_sha=args.workflow_sha,
                remote_public_key=args.remote_public_key,
            )
        else:
            result = finalize(
                admin_url=args.admin_url,
                prepared=_load(args.prepared),
                negative_probe=_load(args.negative_probe),
                positive_probe=_load(args.positive_probe),
                linux_stats=_load(args.linux_stats),
            )
        rc = 0
    except (
        OSError,
        ValueError,
        KeyError,
        baseline.base.CHRRenderDryRunError,
        baseline.mutation.CHRMutationRollbackError,
        baseline.CHRWireGuardBaselineError,
        CHRWireGuardHandshakeError,
    ) as exc:
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "handshake_acceptance": False,
            "encrypted_packet_transfer_acceptance": False,
            "private_key_recorded": False,
            "private_key_serialized": False,
            "preshared_key_used": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "physical_router_targeted": False,
        }
        rc = 1
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
