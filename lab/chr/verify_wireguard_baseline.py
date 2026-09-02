from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
from router_configuration.routeros_wireguard_renderer import (
    PRIVATE_KEY_PLACEHOLDER,
    render_routeros_wireguard,
)
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


class CHRWireGuardBaselineError(RuntimeError):
    pass


INTERFACE_NAME = "wg-routercfg-lab"
KEYGEN_INTERFACE = "routercfg-wg-keygen"
APPLY_FILE = "routercfg-wireguard-apply.rsc"
NEGATIVE_FILE = "routercfg-wireguard-negative.rsc"
ROLLBACK_FILE = "routercfg-wireguard-rollback.rsc"
VERDICT_FILE = "routercfg-wireguard-verdict.txt"
TEMP_FILES = (
    APPLY_FILE,
    NEGATIVE_FILE,
    ROLLBACK_FILE,
    VERDICT_FILE,
    mutation.VERDICT_FILE,
)
COMMENT_PREFIX = "routercfg:managed:wg:"


def _ephemeral_private_key() -> str:
    """Generate one X25519-compatible private key in memory only."""

    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return base64.b64encode(bytes(raw)).decode("ascii")


def _remote_public_key(admin: base.LoopbackCHRAdmin) -> str:
    """Ask disposable CHR for a valid public key without ever reading its private key."""

    _, created = admin.request(
        "PUT",
        "interface/wireguard",
        {"name": KEYGEN_INTERFACE, "comment": "routercfg:lab-only:keygen"},
    )
    keygen_id = None
    if isinstance(created, Mapping):
        keygen_id = str(created.get(".id") or "").strip() or None
    try:
        _, payload = admin.request("GET", "interface/wireguard")
        row = next(
            (
                item
                for item in base._rows(payload)
                if str(item.get("name") or "") == KEYGEN_INTERFACE
            ),
            None,
        )
        if row is None:
            raise CHRWireGuardBaselineError("disposable CHR did not expose the keygen WireGuard interface")
        keygen_id = keygen_id or str(row.get(".id") or "").strip() or None
        public_key = str(row.get("public-key") or "").strip()
        if not public_key:
            raise CHRWireGuardBaselineError("disposable CHR did not expose a generated WireGuard public key")
        try:
            decoded = base64.b64decode(public_key, validate=True)
        except ValueError as exc:
            raise CHRWireGuardBaselineError("disposable CHR generated a non-base64 WireGuard public key") from exc
        if len(decoded) != 32:
            raise CHRWireGuardBaselineError("disposable CHR WireGuard public key is not 32 bytes")
        return public_key
    finally:
        if keygen_id:
            admin.request("DELETE", f"interface/wireguard/{keygen_id}")
        _, remaining = admin.request("GET", "interface/wireguard")
        if any(str(row.get("name") or "") == KEYGEN_INTERFACE for row in base._rows(remaining)):
            raise CHRWireGuardBaselineError("temporary WireGuard keygen interface was not removed")


def _build_ir(remote_public_key: str) -> dict[str, Any]:
    return SafeSubsetIR(
        device_id="chr-wireguard-baseline-lab",
        operations=(
            IntentOperation(
                operation_id="vpn.wireguard",
                feature="vpn",
                resource="wireguard_policy",
                attributes={
                    "enabled": True,
                    "name": INTERFACE_NAME,
                    "addresses": ["10.252.0.1/24"],
                    "listen_port": 51820,
                    "mtu": 1420,
                    "peers": [
                        {
                            "name": "synthetic-remote",
                            "public_key": remote_public_key,
                            "tunnel_address": "10.252.0.2/32",
                            "allowed_addresses": ["10.252.0.2/32", "10.252.10.0/24"],
                            "routes": ["10.252.10.0/24"],
                            "persistent_keepalive": 0,
                            "responder": True,
                        }
                    ],
                },
                risk=IntentRisk.HIGH,
                requires=("wireguard", "firewall", "management_path"),
                secret_references=("env://ROUTERCFG_CHR_SYNTHETIC_WG_PRIVATE_KEY",),
            ),
        ),
    ).as_dict()


def _normalized_rows(
    admin: base.LoopbackCHRAdmin,
    path: str,
    fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", path)
    rows: list[dict[str, Any]] = []
    for row in base._rows(payload):
        if base._is_true(row.get("dynamic")):
            continue
        rows.append({field: row[field] for field in fields if field in row})
    rows.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return rows


def _configuration_snapshot(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    """Snapshot WG mutation surfaces without private/preshared key fields."""

    snapshot = base._configuration_snapshot(admin)
    snapshot["wireguard_interfaces"] = _normalized_rows(
        admin,
        "interface/wireguard",
        ("name", "mtu", "listen-port", "public-key", "comment", "disabled"),
    )
    snapshot["wireguard_peers"] = _normalized_rows(
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
    )
    return snapshot


def _write_verdict(admin: base.LoopbackCHRAdmin, value: str = "PENDING") -> None:
    chunked._create_text_file_chunk_verified(admin, VERDICT_FILE, value)


def _reset_verdict(admin: base.LoopbackCHRAdmin) -> None:
    verdict_id = base._find_file_id(admin, VERDICT_FILE)
    if not verdict_id:
        raise CHRWireGuardBaselineError("WireGuard CHR verdict file disappeared")
    admin.request("PATCH", f"file/{verdict_id}", {"contents": "PENDING"})


def _dry_run(
    admin: base.LoopbackCHRAdmin,
    *,
    apply_script: str,
    rollback_script: str,
) -> dict[str, Any]:
    before = _configuration_snapshot(admin)
    before_digest = base._canonical_digest(before)

    chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
    _write_verdict(admin)
    valid = base._execute_import_dry_run(
        admin,
        file_name=APPLY_FILE,
        verdict_name=VERDICT_FILE,
        expect_success=True,
    )

    chunked._create_text_file_chunk_verified(admin, NEGATIVE_FILE, "this\n")
    _reset_verdict(admin)
    negative = base._execute_import_dry_run(
        admin,
        file_name=NEGATIVE_FILE,
        verdict_name=VERDICT_FILE,
        expect_success=False,
    )

    chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
    _reset_verdict(admin)
    rollback = base._execute_import_dry_run(
        admin,
        file_name=ROLLBACK_FILE,
        verdict_name=VERDICT_FILE,
        expect_success=True,
    )

    after_digest = base._canonical_digest(_configuration_snapshot(admin))
    if after_digest != before_digest:
        raise CHRWireGuardBaselineError("WireGuard import dry-run changed RouterOS configuration")
    return {
        "apply_verdict": str(valid.get("verdict") or ""),
        "negative_control_rejected": str(negative.get("verdict") or "") == "ERROR",
        "rollback_verdict": str(rollback.get("verdict") or ""),
        "configuration_changed": False,
        "configuration_sha256": before_digest,
    }


def _runtime_state(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    _, interface_payload = admin.request("GET", "interface/wireguard")
    interfaces = [
        row
        for row in base._rows(interface_payload)
        if str(row.get("comment") or "") == COMMENT_PREFIX + "interface"
    ]
    if len(interfaces) != 1:
        raise CHRWireGuardBaselineError(f"expected one managed WireGuard interface, observed {len(interfaces)}")
    interface = interfaces[0]
    if base._is_true(interface.get("invalid")) or base._is_true(interface.get("disabled")):
        raise CHRWireGuardBaselineError("managed WireGuard interface is invalid or disabled")
    if (
        str(interface.get("name") or "") != INTERFACE_NAME
        or str(interface.get("listen-port") or "") != "51820"
        or str(interface.get("mtu") or "") != "1420"
    ):
        raise CHRWireGuardBaselineError("managed WireGuard interface fields do not match the rendered fixture")

    _, peer_payload = admin.request("GET", "interface/wireguard/peers")
    peers = [
        row
        for row in base._rows(peer_payload)
        if str(row.get("comment") or "").startswith(COMMENT_PREFIX + "peer:")
    ]
    if len(peers) != 1:
        raise CHRWireGuardBaselineError(f"expected one managed WireGuard peer, observed {len(peers)}")
    peer = peers[0]
    if base._is_true(peer.get("invalid")) or base._is_true(peer.get("disabled")):
        raise CHRWireGuardBaselineError("managed WireGuard peer is invalid or disabled")
    allowed = {value.strip() for value in str(peer.get("allowed-address") or "").split(",") if value.strip()}
    if allowed != {"10.252.0.2/32", "10.252.10.0/24"}:
        raise CHRWireGuardBaselineError(f"managed WireGuard peer allowed-address mismatch: {sorted(allowed)}")
    if str(peer.get("responder") or "").lower() not in {"true", "yes"}:
        raise CHRWireGuardBaselineError("managed WireGuard peer responder flag is not enabled")

    _, address_payload = admin.request("GET", "ip/address")
    addresses = [
        row
        for row in base._rows(address_payload)
        if str(row.get("comment") or "").startswith(COMMENT_PREFIX + "address:")
    ]
    if len(addresses) != 1:
        raise CHRWireGuardBaselineError(f"expected one managed WireGuard address, observed {len(addresses)}")
    address = addresses[0]
    if str(address.get("interface") or "") != INTERFACE_NAME or str(address.get("address") or "") != "10.252.0.1/24":
        raise CHRWireGuardBaselineError("managed WireGuard interface address is incorrect")

    _, route_payload = admin.request("GET", "ip/route")
    routes = [
        row
        for row in base._rows(route_payload)
        if str(row.get("comment") or "").startswith(COMMENT_PREFIX + "route:")
    ]
    if len(routes) != 1:
        raise CHRWireGuardBaselineError(f"expected one managed WireGuard route, observed {len(routes)}")
    route = routes[0]
    if str(route.get("dst-address") or "") != "10.252.10.0/24" or str(route.get("gateway") or "") != INTERFACE_NAME:
        raise CHRWireGuardBaselineError("managed WireGuard route does not match the explicit peer route")

    admin.request("GET", "system/resource")
    return {
        "managed_interface_count": 1,
        "managed_peer_count": 1,
        "managed_address_count": 1,
        "managed_route_count": 1,
        "invalid_managed_objects": 0,
        "disabled_managed_objects": 0,
        "allowed_addresses_exact": True,
        "management_rest_reachable_after_apply": True,
    }


def _rollback_script() -> str:
    return "\n".join(
        (
            f'/ip/route/remove [find where comment~"^{COMMENT_PREFIX}route:"]',
            f'/interface/wireguard/peers/remove [find where comment~"^{COMMENT_PREFIX}peer:"]',
            f'/ip/address/remove [find where comment~"^{COMMENT_PREFIX}address:"]',
            f'/interface/wireguard/remove [find where comment="{COMMENT_PREFIX}interface"]',
        )
    ) + "\n"


def _owned_objects_absent(admin: base.LoopbackCHRAdmin) -> bool:
    checks = (
        ("interface/wireguard", "comment"),
        ("interface/wireguard/peers", "comment"),
        ("ip/address", "comment"),
        ("ip/route", "comment"),
    )
    for path, field in checks:
        _, payload = admin.request("GET", path)
        if any(str(row.get(field) or "").startswith(COMMENT_PREFIX) for row in base._rows(payload)):
            return False
    return True


def verify_wireguard_baseline(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    remote_public_key = _remote_public_key(admin)
    private_key = _ephemeral_private_key()
    ir = _build_ir(remote_public_key)
    plan = render_routeros_wireguard(ir=ir).as_dict()
    templates = plan.get("command_templates", [])
    if not isinstance(templates, list) or len(templates) != 4:
        raise CHRWireGuardBaselineError(
            f"WireGuard CHR fixture requires exactly four templates, observed {len(templates) if isinstance(templates, list) else 'invalid'}"
        )
    script_lines = []
    for item in templates:
        if not isinstance(item, Mapping):
            raise CHRWireGuardBaselineError("WireGuard template fixture contains a non-object")
        template = str(item.get("template") or "")
        if PRIVATE_KEY_PLACEHOLDER not in template and item.get("secret_placeholders"):
            raise CHRWireGuardBaselineError("WireGuard template secret metadata does not match its placeholder")
        script_lines.append(template.replace(PRIVATE_KEY_PLACEHOLDER, private_key))
    apply_script = "\n".join(script_lines) + "\n"
    rollback_script = _rollback_script()

    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)
    if not _owned_objects_absent(admin):
        raise CHRWireGuardBaselineError("disposable CHR baseline already contains routercfg-owned WireGuard objects")

    baseline = _configuration_snapshot(admin)
    baseline_digest = base._canonical_digest(baseline)
    dry_run_result: dict[str, Any] | None = None
    apply_result: dict[str, Any] | None = None
    rollback_result: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None
    mutated_digest: str | None = None
    rollback_digest: str | None = None

    try:
        dry_run_result = _dry_run(admin, apply_script=apply_script, rollback_script=rollback_script)

        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
        apply_result = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)
        mutated_digest = base._canonical_digest(_configuration_snapshot(admin))
        if mutated_digest == baseline_digest:
            raise CHRWireGuardBaselineError("WireGuard apply did not change the configuration digest")
        runtime = _runtime_state(admin)

        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
        rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
        if not _owned_objects_absent(admin):
            raise CHRWireGuardBaselineError("routercfg-owned WireGuard objects remain after rollback")
        rollback_digest = base._canonical_digest(_configuration_snapshot(admin))
        if rollback_digest != baseline_digest:
            raise CHRWireGuardBaselineError("WireGuard rollback did not restore the exact baseline digest")
    finally:
        private_key = ""
        apply_script = ""
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_wireguard_deferred_secret_runtime",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "fixture": {
            "template_count": len(templates),
            "interface_name": INTERFACE_NAME,
            "listen_port": 51820,
            "address_count": 1,
            "peer_count": 1,
            "route_count": 1,
            "synthetic_remote_public_key_source": "disposable_chr_autogenerated_public_key",
            "synthetic_private_key_source": "ephemeral_in_memory_x25519_compatible_random",
        },
        "dry_run": dry_run_result,
        "apply": {"verdict": str((apply_result or {}).get("verdict") or "")},
        "runtime": runtime,
        "rollback": {"verdict": str((rollback_result or {}).get("verdict") or "")},
        "configuration_baseline_sha256": baseline_digest,
        "configuration_mutated_sha256": mutated_digest,
        "configuration_rollback_sha256": rollback_digest,
        "rollback_digest_restored": rollback_digest == baseline_digest,
        "managed_objects_removed": _owned_objects_absent(admin),
        "temporary_files_removed": True,
        "private_key_recorded": False,
        "private_key_serialized": False,
        "preshared_key_used": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate deferred-secret WireGuard templates on disposable RouterOS CHR"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9580")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_wireguard_baseline(admin_url=args.admin_url)
        rc = 0
    except (OSError, ValueError, base.CHRRenderDryRunError, CHRWireGuardBaselineError):
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "error_code": "wireguard_chr_gate_failed",
            "private_key_recorded": False,
            "private_key_serialized": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
        }
        rc = 18

    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
