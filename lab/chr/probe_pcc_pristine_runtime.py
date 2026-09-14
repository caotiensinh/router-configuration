from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


class PCCPristineProbeError(RuntimeError):
    pass


PREFIX = "routercfg:diagnostic:pcc-pristine:"
SCRIPT_FILE = "routercfg-pcc-pristine-probe.rsc"
VERDICT_FILE = "routercfg-pcc-pristine-probe-verdict.txt"
TEMP_FILES = (SCRIPT_FILE, VERDICT_FILE)
DEVICE_MODE_FEATURES = (
    "bandwidth-test",
    "container",
    "email",
    "fetch",
    "hotspot",
    "install-any-version",
    "ipsec",
    "l2tp",
    "partitions",
    "pptp",
    "proxy",
    "romon",
    "routerboard",
    "scheduler",
    "smb",
    "sniffer",
    "socks",
    "traffic-gen",
    "zerotier",
)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _first_mapping(payload: Any) -> Mapping[str, Any]:
    rows = base._rows(payload)
    return rows[0] if rows else {}


def _optional_get(admin: base.LoopbackCHRAdmin, path: str) -> tuple[int, Mapping[str, Any]]:
    status, payload = admin.request("GET", path, allow_http_error=True)
    return status, _first_mapping(payload)


def _sanitize_license(payload: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "level": str(payload.get("level") or ""),
        "limited_upgrades": base._is_true(payload.get("limited-upgrades")),
    }
    system_id = str(payload.get("system-id") or "").strip()
    if system_id:
        result["system_id_sha256"] = _sha256_text(system_id)
    return result


def _sanitize_device_mode(payload: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "mode": str(payload.get("mode") or ""),
        "flagged": base._is_true(payload.get("flagged")),
        "flagging_enabled": base._is_true(payload.get("flagging-enabled")),
    }
    features: dict[str, bool] = {}
    for name in DEVICE_MODE_FEATURES:
        if name in payload:
            features[name] = base._is_true(payload.get(name))
    result["features"] = features
    return result


def _sanitize_connection_tracking(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "enabled": str(payload.get("enabled") or ""),
        "active_ipv4": base._is_true(payload.get("active-ipv4")),
        "active_ipv6": base._is_true(payload.get("active-ipv6")),
        "total_entries": str(payload.get("total-entries") or ""),
        "total_ipv4_entries": str(payload.get("total-ip4-entries") or ""),
        "total_ipv6_entries": str(payload.get("total-ip6-entries") or ""),
        "max_entries": str(payload.get("max-entries") or ""),
    }


def _routing_table_fingerprint(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    status, payload = admin.request("GET", "routing/table", allow_http_error=True)
    if status != 200:
        return [{"http_status": status}]
    rows: list[dict[str, Any]] = []
    for raw in base._rows(payload):
        row = dict(raw)
        rows.append(
            {
                "name": str(row.get("name") or ""),
                "dynamic": base._is_true(row.get("dynamic")),
                "disabled": base._is_true(row.get("disabled")),
                "invalid": base._is_true(row.get("invalid")),
                "fib_key_present": "fib" in row,
                "fib_raw": str(row.get("fib") or ""),
                "keys": sorted(str(key) for key in row),
            }
        )
    rows.sort(key=lambda row: row.get("name", ""))
    return rows


def _runtime_fingerprint(
    admin: base.LoopbackCHRAdmin,
    platform: Mapping[str, Any],
) -> dict[str, Any]:
    license_status, license_payload = _optional_get(admin, "system/license")
    mode_status, mode_payload = _optional_get(admin, "system/device-mode")
    tracking_status, tracking_payload = _optional_get(admin, "ip/firewall/connection/tracking")
    initial_mangle = _rows(admin)
    return {
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
            "build_time": str(platform.get("build-time") or ""),
            "cpu_count": str(platform.get("cpu-count") or ""),
            "total_memory": str(platform.get("total-memory") or ""),
        },
        "license": {
            "http_status": license_status,
            **(_sanitize_license(license_payload) if license_status == 200 else {}),
        },
        "device_mode": {
            "http_status": mode_status,
            **(_sanitize_device_mode(mode_payload) if mode_status == 200 else {}),
        },
        "connection_tracking": {
            "http_status": tracking_status,
            **(
                _sanitize_connection_tracking(tracking_payload)
                if tracking_status == 200
                else {}
            ),
        },
        "routing_tables": _routing_table_fingerprint(admin),
        "initial_mangle_rule_count": len(initial_mangle),
        "initial_mangle_dynamic_count": sum(
            1 for row in initial_mangle if base._is_true(row.get("dynamic"))
        ),
    }


def _rows(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", "ip/firewall/mangle")
    return [dict(row) for row in base._rows(payload)]


def _delete_probe_rows(admin: base.LoopbackCHRAdmin) -> None:
    for row in _rows(admin):
        if not str(row.get("comment") or "").startswith(PREFIX):
            continue
        row_id = str(row.get(".id") or "").strip()
        if row_id:
            admin.request("DELETE", f"ip/firewall/mangle/{row_id}")


def _summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "comment": str(row.get("comment") or ""),
        "action": str(row.get("action") or ""),
        "invalid": base._is_true(row.get("invalid")),
        "disabled": base._is_true(row.get("disabled")),
        "new_connection_mark": str(row.get("new-connection-mark") or ""),
        "pcc": str(row.get("per-connection-classifier") or ""),
    }


def _import_one(admin: base.LoopbackCHRAdmin, command: str) -> None:
    chunked._create_text_file_chunk_verified(admin, SCRIPT_FILE, command + "\n")
    mutation._execute_import(admin, file_name=SCRIPT_FILE, expect_success=True)


def _find_probe_rows(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    result = [
        _summary(row)
        for row in _rows(admin)
        if str(row.get("comment") or "").startswith(PREFIX)
    ]
    result.sort(key=lambda row: row["comment"])
    return result


def _isolated_case(
    admin: base.LoopbackCHRAdmin,
    *,
    name: str,
    command: str,
) -> dict[str, Any]:
    _delete_probe_rows(admin)
    _import_one(admin, command)
    observed = _find_probe_rows(admin)
    if len(observed) != 1:
        raise PCCPristineProbeError(
            f"isolated probe {name!r} expected one rule, observed {len(observed)}"
        )
    result = {
        "name": name,
        "command_sha256": _sha256_text(command + "\n"),
        "rows": observed,
    }
    _delete_probe_rows(admin)
    return result


def _cumulative_case(
    admin: base.LoopbackCHRAdmin,
    *,
    name: str,
    commands: tuple[str, ...],
) -> dict[str, Any]:
    _delete_probe_rows(admin)
    for command in commands:
        _import_one(admin, command)
    observed = _find_probe_rows(admin)
    if len(observed) != len(commands):
        raise PCCPristineProbeError(
            f"cumulative probe {name!r} expected {len(commands)} rules, observed {len(observed)}"
        )
    result = {
        "name": name,
        "command_sha256": [_sha256_text(command + "\n") for command in commands],
        "rows": observed,
    }
    _delete_probe_rows(admin)
    return result


def probe(*, admin_url: str, output: Path) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    for temp in TEMP_FILES:
        base._delete_file_if_present(admin, temp)
    _delete_probe_rows(admin)
    runtime_fingerprint = _runtime_fingerprint(admin, platform)

    pcc0 = (
        f'/ip/firewall/mangle/add chain=prerouting action=accept '
        f'per-connection-classifier="both-addresses-and-ports:2/0" '
        f'comment="{PREFIX}accept-pcc-2-0"'
    )
    pcc1 = (
        f'/ip/firewall/mangle/add chain=prerouting action=accept '
        f'per-connection-classifier="both-addresses-and-ports:2/1" '
        f'comment="{PREFIX}accept-pcc-2-1"'
    )
    mark_a = (
        f'/ip/firewall/mangle/add chain=prerouting action=mark-connection '
        f'new-connection-mark="routercfg-diag-a" passthrough=yes '
        f'comment="{PREFIX}mark-a"'
    )
    mark_b = (
        f'/ip/firewall/mangle/add chain=prerouting action=mark-connection '
        f'new-connection-mark="routercfg-diag-b" passthrough=yes '
        f'comment="{PREFIX}mark-b"'
    )

    cases: list[dict[str, Any]] = []
    try:
        cases.append(_isolated_case(admin, name="pcc_2_0_isolated", command=pcc0))
        cases.append(_isolated_case(admin, name="pcc_2_1_isolated", command=pcc1))
        cases.append(
            _cumulative_case(
                admin,
                name="pcc_2_0_then_2_1",
                commands=(pcc0, pcc1),
            )
        )
        cases.append(_isolated_case(admin, name="mark_a_isolated", command=mark_a))
        cases.append(
            _cumulative_case(
                admin,
                name="mark_a_then_mark_b",
                commands=(mark_a, mark_b),
            )
        )
    finally:
        _delete_probe_rows(admin)
        for temp in TEMP_FILES:
            base._delete_file_if_present(admin, temp)
        base._assert_files_absent(admin, TEMP_FILES)

    all_rows = [row for case in cases for row in case["rows"]]
    result = {
        "schema_version": "chr-pcc-pristine-runtime-probe/2",
        "ok": True,
        "scope": "disposable_chr_pristine_runtime_diagnostic_only",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "runtime_fingerprint": runtime_fingerprint,
        "cases": cases,
        "invalid_observed": any(bool(row["invalid"]) for row in all_rows),
        "probe_rules_removed": True,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe PCC and connection-mark validity on pristine disposable CHR"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9380")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = probe(admin_url=args.admin_url, output=Path(args.output))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, base.CHRRenderDryRunError, PCCPristineProbeError) as exc:
        failure = {
            "schema_version": "chr-pcc-pristine-runtime-probe/2",
            "ok": False,
            "error": str(exc),
            "production_writer_available": False,
            "write_authorized": False,
        }
        Path(args.output).write_text(json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 18


if __name__ == "__main__":
    raise SystemExit(main())
