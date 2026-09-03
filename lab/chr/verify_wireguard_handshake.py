from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
import verify_wireguard_baseline as wgbase
from router_configuration.routeros_wireguard_renderer import (
    PRIVATE_KEY_PLACEHOLDER,
    render_routeros_wireguard,
)
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


class CHRWireGuardHandshakeError(RuntimeError):
    pass


A_INTERFACE = "wg-routercfg-lab"
B_INTERFACE = "wg-remote-lab"
A_LISTEN_PORT = 51820
B_LISTEN_PORT = 51821
A_UNDERLAY = "192.0.2.1/30"
B_UNDERLAY = "192.0.2.2/30"
A_UNDERLAY_IP = "192.0.2.1"
B_UNDERLAY_IP = "192.0.2.2"
A_LAN = "10.60.1.1/24"
B_LAN = "10.60.2.1/24"
A_LAN_NETWORK = "10.60.1.0/24"
B_LAN_NETWORK = "10.60.2.0/24"
A_TUNNEL = "10.252.0.1/24"
B_TUNNEL = "10.252.0.2/24"
A_TUNNEL_HOST = "10.252.0.1/32"
B_TUNNEL_HOST = "10.252.0.2/32"
A_PREFIX = "routercfg:lab:wg-dp:a:"
B_PREFIX = "routercfg:lab:wg-dp:b:"
A_PEER_COMMENT = "routercfg:managed:wg:peer:001"
B_PEER_COMMENT = B_PREFIX + "peer"
B_WG_COMMENT = B_PREFIX + "interface"
A_APPLY_FILE = "routercfg-wg-handshake-a-apply.rsc"
A_ROLLBACK_FILE = "routercfg-wg-handshake-a-rollback.rsc"
TEMP_FILES = (A_APPLY_FILE, A_ROLLBACK_FILE, mutation.VERDICT_FILE)


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _normalized_rows(
    admin: base.LoopbackCHRAdmin,
    path: str,
    fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _records(admin, path):
        if base._is_true(row.get("dynamic")):
            continue
        rows.append({field: row[field] for field in fields if field in row})
    rows.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return rows


def _snapshot(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "ip_addresses": _normalized_rows(
            admin,
            "ip/address",
            ("address", "interface", "comment", "disabled"),
        ),
        "ip_routes": _normalized_rows(
            admin,
            "ip/route",
            ("dst-address", "gateway", "routing-table", "comment", "disabled"),
        ),
        "wireguard_interfaces": _normalized_rows(
            admin,
            "interface/wireguard",
            ("name", "listen-port", "mtu", "public-key", "comment", "disabled"),
        ),
        "wireguard_peers": _normalized_rows(
            admin,
            "interface/wireguard/peers",
            (
                "interface",
                "name",
                "public-key",
                "allowed-address",
                "endpoint-address",
                "endpoint-port",
                "persistent-keepalive",
                "responder",
                "comment",
                "disabled",
            ),
        ),
    }


def _digest(admin: base.LoopbackCHRAdmin) -> str:
    return base._canonical_digest(_snapshot(admin))


def _public_key_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("ascii", "strict")).hexdigest()


def _create(admin: base.LoopbackCHRAdmin, path: str, payload: Mapping[str, Any]) -> str:
    _, created = admin.request("PUT", path, dict(payload))
    if not isinstance(created, Mapping):
        raise CHRWireGuardHandshakeError(f"RouterOS did not return an object while creating {path}")
    row_id = str(created.get(".id") or "").strip()
    if not row_id:
        raise CHRWireGuardHandshakeError(f"RouterOS did not return an id while creating {path}")
    return row_id


def _delete_if_id(admin: base.LoopbackCHRAdmin, path: str, row_id: str | None) -> None:
    if row_id:
        admin.request("DELETE", f"{path}/{row_id}")


def _find_one(admin: base.LoopbackCHRAdmin, path: str, *, field: str, value: str) -> Mapping[str, Any]:
    rows = [row for row in _records(admin, path) if str(row.get(field) or "") == value]
    if len(rows) != 1:
        raise CHRWireGuardHandshakeError(
            f"expected one {path} row with {field}={value!r}, observed {len(rows)}"
        )
    return rows[0]


def _build_a_ir(remote_public_key: str) -> dict[str, Any]:
    return SafeSubsetIR(
        device_id="chr-wireguard-handshake-a",
        operations=(
            IntentOperation(
                operation_id="vpn.wireguard",
                feature="vpn",
                resource="wireguard_policy",
                attributes={
                    "enabled": True,
                    "name": A_INTERFACE,
                    "addresses": [A_TUNNEL],
                    "listen_port": A_LISTEN_PORT,
                    "mtu": 1420,
                    "peers": [
                        {
                            "name": "chr-b",
                            "public_key": remote_public_key,
                            "tunnel_address": B_TUNNEL_HOST,
                            "allowed_addresses": [B_TUNNEL_HOST, B_LAN_NETWORK],
                            "routes": [B_LAN_NETWORK],
                            "endpoint_address": B_UNDERLAY_IP,
                            "endpoint_port": B_LISTEN_PORT,
                            "persistent_keepalive": 5,
                            "responder": False,
                        }
                    ],
                },
                risk=IntentRisk.HIGH,
                requires=("wireguard", "firewall", "management_path"),
                secret_references=("env://ROUTERCFG_CHR_SYNTHETIC_WG_PRIVATE_KEY",),
            ),
        ),
    ).as_dict()


def _execute_script(admin: base.LoopbackCHRAdmin, *, file_name: str, script: str) -> dict[str, Any]:
    base._delete_file_if_present(admin, file_name)
    base._delete_file_if_present(admin, mutation.VERDICT_FILE)
    chunked._create_text_file_chunk_verified(admin, file_name, script)
    try:
        return mutation._execute_import(admin, file_name=file_name, expect_success=True)
    finally:
        base._delete_file_if_present(admin, file_name)
        base._delete_file_if_present(admin, mutation.VERDICT_FILE)


def _a_rollback_script() -> str:
    prefix = "routercfg:managed:wg:"
    return "\n".join(
        (
            f'/ip/route/remove [find where comment~"^{prefix}route:"]',
            f'/interface/wireguard/peers/remove [find where comment~"^{prefix}peer:"]',
            f'/ip/address/remove [find where comment~"^{prefix}address:"]',
            f'/interface/wireguard/remove [find where comment="{prefix}interface"]',
        )
    ) + "\n"


def _peer_stats(admin: base.LoopbackCHRAdmin, *, comment: str) -> dict[str, Any]:
    peer = _find_one(admin, "interface/wireguard/peers", field="comment", value=comment)
    if base._is_true(peer.get("invalid")) or base._is_true(peer.get("disabled")):
        raise CHRWireGuardHandshakeError(f"WireGuard peer {comment!r} is invalid or disabled")
    handshake = str(peer.get("last-handshake") or "").strip()
    if not handshake or handshake.lower() in {"never", "0", "0s"}:
        raise CHRWireGuardHandshakeError(f"WireGuard peer {comment!r} has no successful handshake")
    try:
        rx = int(str(peer.get("rx") or "0"))
        tx = int(str(peer.get("tx") or "0"))
    except ValueError as exc:
        raise CHRWireGuardHandshakeError(f"WireGuard peer {comment!r} has non-integer rx/tx counters") from exc
    if rx <= 0 or tx <= 0:
        raise CHRWireGuardHandshakeError(
            f"WireGuard peer {comment!r} counters did not prove bidirectional encrypted traffic: rx={rx} tx={tx}"
        )
    return {
        "last_handshake_present": True,
        "rx_bytes": rx,
        "tx_bytes": tx,
        "current_endpoint_address": str(peer.get("current-endpoint-address") or ""),
        "current_endpoint_port": str(peer.get("current-endpoint-port") or ""),
        "invalid": False,
        "disabled": False,
    }


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def configure(*, admin_a_url: str, admin_b_url: str, workflow_sha: str) -> dict[str, Any]:
    admin_a = base.LoopbackCHRAdmin(admin_a_url)
    admin_b = base.LoopbackCHRAdmin(admin_b_url)
    platform_a = admin_a.assert_disposable_chr()
    platform_b = admin_b.assert_disposable_chr()
    baseline_a = _digest(admin_a)
    baseline_b = _digest(admin_b)

    ids: dict[str, str] = {}
    private_key = ""
    apply_script = ""
    try:
        ids["a_underlay"] = _create(
            admin_a,
            "ip/address",
            {"address": A_UNDERLAY, "interface": "ether2", "comment": A_PREFIX + "underlay"},
        )
        ids["a_lan"] = _create(
            admin_a,
            "ip/address",
            {"address": A_LAN, "interface": "ether3", "comment": A_PREFIX + "lan"},
        )
        ids["b_underlay"] = _create(
            admin_b,
            "ip/address",
            {"address": B_UNDERLAY, "interface": "ether2", "comment": B_PREFIX + "underlay"},
        )
        ids["b_lan"] = _create(
            admin_b,
            "ip/address",
            {"address": B_LAN, "interface": "ether3", "comment": B_PREFIX + "lan"},
        )
        ids["b_wg"] = _create(
            admin_b,
            "interface/wireguard",
            {"name": B_INTERFACE, "listen-port": B_LISTEN_PORT, "mtu": 1420, "comment": B_WG_COMMENT},
        )
        b_interface = _find_one(admin_b, "interface/wireguard", field="name", value=B_INTERFACE)
        b_public_key = str(b_interface.get("public-key") or "").strip()
        if not b_public_key:
            raise CHRWireGuardHandshakeError("CHR-B did not expose its auto-generated public key")
        ids["b_tunnel"] = _create(
            admin_b,
            "ip/address",
            {"address": B_TUNNEL, "interface": B_INTERFACE, "comment": B_PREFIX + "tunnel"},
        )

        plan = render_routeros_wireguard(ir=_build_a_ir(b_public_key)).as_dict()
        templates = plan.get("command_templates")
        if not isinstance(templates, list) or len(templates) != 4:
            raise CHRWireGuardHandshakeError("production WireGuard renderer did not emit the expected four templates")
        private_key = wgbase._ephemeral_private_key()
        lines: list[str] = []
        for item in templates:
            if not isinstance(item, Mapping):
                raise CHRWireGuardHandshakeError("production WireGuard template plan contains a non-object")
            template = str(item.get("template") or "")
            lines.append(template.replace(PRIVATE_KEY_PLACEHOLDER, private_key))
        apply_script = "\n".join(lines) + "\n"
        apply_result = _execute_script(admin_a, file_name=A_APPLY_FILE, script=apply_script)
        private_key = ""
        apply_script = ""

        a_interface = _find_one(admin_a, "interface/wireguard", field="name", value=A_INTERFACE)
        a_public_key = str(a_interface.get("public-key") or "").strip()
        if not a_public_key:
            raise CHRWireGuardHandshakeError("CHR-A did not expose the public key derived from its ephemeral private key")

        ids["b_peer"] = _create(
            admin_b,
            "interface/wireguard/peers",
            {
                "interface": B_INTERFACE,
                "name": "chr-a",
                "public-key": a_public_key,
                "allowed-address": f"{A_TUNNEL_HOST},{A_LAN_NETWORK}",
                "endpoint-address": A_UNDERLAY_IP,
                "endpoint-port": A_LISTEN_PORT,
                "persistent-keepalive": 5,
                "responder": False,
                "comment": B_PEER_COMMENT,
            },
        )
        ids["b_route"] = _create(
            admin_b,
            "ip/route",
            {"dst-address": A_LAN_NETWORK, "gateway": B_INTERFACE, "comment": B_PREFIX + "route"},
        )

        a_peer = _find_one(admin_a, "interface/wireguard/peers", field="comment", value=A_PEER_COMMENT)
        if str(a_peer.get("endpoint-address") or "") != B_UNDERLAY_IP:
            raise CHRWireGuardHandshakeError("production-rendered CHR-A peer endpoint is not CHR-B underlay IP")
        if str(a_peer.get("endpoint-port") or "") != str(B_LISTEN_PORT):
            raise CHRWireGuardHandshakeError("production-rendered CHR-A peer endpoint port is not CHR-B listen port")

        return {
            "ok": True,
            "acceptance": "CONFIGURED",
            "workflow_sha": workflow_sha,
            "platform_a": {
                "version": str(platform_a.get("version") or ""),
                "architecture": str(platform_a.get("architecture-name") or ""),
                "board_name": str(platform_a.get("board-name") or ""),
            },
            "platform_b": {
                "version": str(platform_b.get("version") or ""),
                "architecture": str(platform_b.get("architecture-name") or ""),
                "board_name": str(platform_b.get("board-name") or ""),
            },
            "baseline_a_sha256": baseline_a,
            "baseline_b_sha256": baseline_b,
            "configured_a_sha256": _digest(admin_a),
            "configured_b_sha256": _digest(admin_b),
            "renderer": {
                "production_renderer_used_on_chr_a": True,
                "schema_version": str(plan.get("schema_version") or ""),
                "template_count": len(templates),
                "secrets_resolved_in_plan": bool(plan.get("secrets_resolved")),
                "transport_present": bool(plan.get("transport_present")),
                "apply_available": bool(plan.get("apply_available")),
                "write_authorized": bool(plan.get("write_authorized")),
            },
            "key_boundary": {
                "chr_a_public_key_sha256": _public_key_fingerprint(a_public_key),
                "chr_b_public_key_sha256": _public_key_fingerprint(b_public_key),
                "private_key_recorded": False,
                "private_key_serialized": False,
                "preshared_key_used": False,
                "chr_b_private_key_read": False,
            },
            "lab_ids": ids,
            "apply": {"verdict": str(apply_result.get("verdict") or "")},
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "physical_router_targeted": False,
        }
    except Exception:
        private_key = ""
        apply_script = ""
        raise


def evaluate(
    *,
    admin_a_url: str,
    admin_b_url: str,
    configured: Mapping[str, Any],
    flow: Mapping[str, Any],
) -> dict[str, Any]:
    admin_a = base.LoopbackCHRAdmin(admin_a_url)
    admin_b = base.LoopbackCHRAdmin(admin_b_url)
    admin_a.assert_disposable_chr()
    admin_b.assert_disposable_chr()
    requested = int(flow.get("requested_flows") or 0)
    successful = int(flow.get("successful_flows") or 0)
    tags = flow.get("tags")
    normalized_tags = {str(key): int(value) for key, value in tags.items()} if isinstance(tags, Mapping) else {}
    if requested <= 0 or successful != requested or normalized_tags != {"WG": requested}:
        raise CHRWireGuardHandshakeError(
            f"end-to-end WireGuard packet flow failed: requested={requested} successful={successful} tags={normalized_tags}"
        )
    a_stats = _peer_stats(admin_a, comment=A_PEER_COMMENT)
    b_stats = _peer_stats(admin_b, comment=B_PEER_COMMENT)
    if a_stats["current_endpoint_address"] != B_UNDERLAY_IP:
        raise CHRWireGuardHandshakeError("CHR-A authenticated endpoint is not CHR-B underlay IP")
    if b_stats["current_endpoint_address"] != A_UNDERLAY_IP:
        raise CHRWireGuardHandshakeError("CHR-B authenticated endpoint is not CHR-A underlay IP")
    return {
        "ok": True,
        "acceptance": "PASS",
        "workflow_sha": str(configured.get("workflow_sha") or ""),
        "packet_flow": {
            "requested_flows": requested,
            "successful_flows": successful,
            "success_ratio": 1.0,
            "observed_tags": normalized_tags,
            "source_lan": "10.60.1.2",
            "destination_lan": "10.60.2.2",
        },
        "chr_a_peer": a_stats,
        "chr_b_peer": b_stats,
        "wireguard_handshake_acceptance": True,
        "encrypted_packet_transfer_acceptance": True,
        "production_renderer_used_on_chr_a": True,
        "private_key_recorded": False,
        "private_key_serialized": False,
        "preshared_key_used": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def cleanup(*, admin_a_url: str, admin_b_url: str, configured: Mapping[str, Any]) -> dict[str, Any]:
    admin_a = base.LoopbackCHRAdmin(admin_a_url)
    admin_b = base.LoopbackCHRAdmin(admin_b_url)
    admin_a.assert_disposable_chr()
    admin_b.assert_disposable_chr()
    ids = configured.get("lab_ids")
    if not isinstance(ids, Mapping):
        raise CHRWireGuardHandshakeError("configured evidence does not contain lab ids")

    _execute_script(admin_a, file_name=A_ROLLBACK_FILE, script=_a_rollback_script())
    _delete_if_id(admin_b, "ip/route", str(ids.get("b_route") or "") or None)
    _delete_if_id(admin_b, "interface/wireguard/peers", str(ids.get("b_peer") or "") or None)
    _delete_if_id(admin_b, "ip/address", str(ids.get("b_tunnel") or "") or None)
    _delete_if_id(admin_b, "interface/wireguard", str(ids.get("b_wg") or "") or None)
    _delete_if_id(admin_b, "ip/address", str(ids.get("b_lan") or "") or None)
    _delete_if_id(admin_b, "ip/address", str(ids.get("b_underlay") or "") or None)
    _delete_if_id(admin_a, "ip/address", str(ids.get("a_lan") or "") or None)
    _delete_if_id(admin_a, "ip/address", str(ids.get("a_underlay") or "") or None)
    for name in TEMP_FILES:
        base._delete_file_if_present(admin_a, name)
    base._assert_files_absent(admin_a, TEMP_FILES)

    final_a = _digest(admin_a)
    final_b = _digest(admin_b)
    baseline_a = str(configured.get("baseline_a_sha256") or "")
    baseline_b = str(configured.get("baseline_b_sha256") or "")
    if final_a != baseline_a:
        raise CHRWireGuardHandshakeError("CHR-A cleanup did not restore exact baseline digest")
    if final_b != baseline_b:
        raise CHRWireGuardHandshakeError("CHR-B cleanup did not restore exact baseline digest")
    return {
        "ok": True,
        "acceptance": "CLEAN",
        "workflow_sha": str(configured.get("workflow_sha") or ""),
        "chr_a_baseline_sha256": baseline_a,
        "chr_a_cleanup_sha256": final_a,
        "chr_b_baseline_sha256": baseline_b,
        "chr_b_cleanup_sha256": final_b,
        "chr_a_digest_restored": True,
        "chr_b_digest_restored": True,
        "temporary_files_removed": True,
        "private_key_recorded": False,
        "private_key_serialized": False,
        "preshared_key_used": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove RouterOS-to-RouterOS WireGuard handshake and encrypted packet transfer")
    sub = parser.add_subparsers(dest="command", required=True)

    p_config = sub.add_parser("configure")
    p_config.add_argument("--admin-a-url", default="http://127.0.0.1:10080")
    p_config.add_argument("--admin-b-url", default="http://127.0.0.1:10081")
    p_config.add_argument("--workflow-sha", required=True)
    p_config.add_argument("--output", required=True)

    p_eval = sub.add_parser("evaluate")
    p_eval.add_argument("--admin-a-url", default="http://127.0.0.1:10080")
    p_eval.add_argument("--admin-b-url", default="http://127.0.0.1:10081")
    p_eval.add_argument("--configured", required=True)
    p_eval.add_argument("--flow", required=True)
    p_eval.add_argument("--output", required=True)

    p_cleanup = sub.add_parser("cleanup")
    p_cleanup.add_argument("--admin-a-url", default="http://127.0.0.1:10080")
    p_cleanup.add_argument("--admin-b-url", default="http://127.0.0.1:10081")
    p_cleanup.add_argument("--configured", required=True)
    p_cleanup.add_argument("--output", required=True)

    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        if args.command == "configure":
            result = configure(
                admin_a_url=args.admin_a_url,
                admin_b_url=args.admin_b_url,
                workflow_sha=args.workflow_sha,
            )
        elif args.command == "evaluate":
            result = evaluate(
                admin_a_url=args.admin_a_url,
                admin_b_url=args.admin_b_url,
                configured=_load(args.configured),
                flow=_load(args.flow),
            )
        else:
            result = cleanup(
                admin_a_url=args.admin_a_url,
                admin_b_url=args.admin_b_url,
                configured=_load(args.configured),
            )
        rc = 0
    except (OSError, ValueError, base.CHRRenderDryRunError, mutation.CHRMutationRollbackError, CHRWireGuardHandshakeError) as exc:
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "wireguard_handshake_acceptance": False,
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
