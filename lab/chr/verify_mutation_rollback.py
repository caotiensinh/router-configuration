from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import build_renderer_syntax_fixture as fixture_builder
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


class CHRMutationRollbackError(RuntimeError):
    pass


APPLY_FILE = "routercfg-mutation-apply.rsc"
FAIL_FILE = "routercfg-mutation-failure.rsc"
ROLLBACK_FILE = "routercfg-mutation-rollback.rsc"
VERDICT_FILE = "routercfg-mutation-verdict.txt"
TEMP_FILES = (APPLY_FILE, FAIL_FILE, ROLLBACK_FILE, VERDICT_FILE)


def _managed_rows(
    admin: base.LoopbackCHRAdmin,
    path: str,
    *,
    comment_prefix: str,
) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return [
        row
        for row in base._rows(payload)
        if str(row.get("comment") or "").startswith(comment_prefix)
    ]


def _named_rows(
    admin: base.LoopbackCHRAdmin,
    path: str,
    *,
    names: set[str],
) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return [
        row
        for row in base._rows(payload)
        if str(row.get("name") or "") in names
    ]


def _write_verdict_file(admin: base.LoopbackCHRAdmin) -> None:
    chunked._create_text_file_chunk_verified(admin, VERDICT_FILE, "PENDING")


def _execute_import(
    admin: base.LoopbackCHRAdmin,
    *,
    file_name: str,
    expect_success: bool,
) -> dict[str, Any]:
    _write_verdict_file(admin)
    verdict_q = VERDICT_FILE.replace('"', '\\"')
    script = (
        f':onerror e in={{ import {file_name} verbose=yes }} do={{'
        f'/file set [find where name="{verdict_q}"] contents=("ERROR|" . [:tostr $e]);'
        ':return};'
        f'/file set [find where name="{verdict_q}"] contents="OK"'
    )
    status, response = admin.request(
        "POST",
        "execute",
        {"script": script},
        allow_http_error=True,
    )
    if status >= 400:
        raise CHRMutationRollbackError(
            f"RouterOS import wrapper failed to start with HTTP {status}: {str(response)[:400]}"
        )
    contents = base._wait_for_verdict(admin, VERDICT_FILE, timeout_seconds=20.0)
    captured_error, detail = base._parse_verdict_contents(contents)
    if expect_success and captured_error:
        raise CHRMutationRollbackError(
            f"RouterOS mutation import failed: {detail[:400]}"
        )
    if not expect_success and not captured_error:
        raise CHRMutationRollbackError(
            "RouterOS failure injection unexpectedly succeeded"
        )
    opaque_ret = None
    if isinstance(response, Mapping):
        opaque_ret = str(response.get("ret") or "").strip() or None
    return {
        "http_status": status,
        "verdict": "ERROR" if captured_error else "OK",
        "error_detail": detail,
        "execute_ret_observed": opaque_ret,
    }


def _rollback_script() -> str:
    """Delete only objects owned by the CHR syntax fixture, in dependency order."""

    commands = (
        '/ip/firewall/mangle/remove [find where comment~"^routercfg:managed:pcc-"]',
        '/ip/route/remove [find where comment~"^routercfg:managed:pcc-route:"]',
        '/ip/route/remove [find where comment~"^routercfg:managed:default:"]',
        '/ip/route/remove [find where comment~"^routercfg:managed:probe:"]',
        '/ip/address/remove [find where comment~"^routercfg:managed:wan-address:"]',
        '/interface/list/member/remove [find where comment~"^routercfg:managed:wan:"]',
        '/interface/list/member/remove [find where comment="routercfg:managed:core-uplink"]',
        '/interface/list/remove [find where name="routercfg-WAN"]',
        '/interface/list/remove [find where name="routercfg-CORE"]',
        '/routing/table/remove [find where name="to-lab-wan10g"]',
        '/routing/table/remove [find where name="to-lab-wan1g"]',
    )
    return "\n".join(commands) + "\n"


def _assert_mutated_state(admin: base.LoopbackCHRAdmin) -> dict[str, int]:
    pcc_mangle = _managed_rows(
        admin,
        "ip/firewall/mangle",
        comment_prefix="routercfg:managed:pcc-",
    )
    pcc_routes = _managed_rows(
        admin,
        "ip/route",
        comment_prefix="routercfg:managed:pcc-route:",
    )
    recursive_probes = _managed_rows(
        admin,
        "ip/route",
        comment_prefix="routercfg:managed:probe:",
    )
    recursive_defaults = _managed_rows(
        admin,
        "ip/route",
        comment_prefix="routercfg:managed:default:",
    )
    tables = _named_rows(
        admin,
        "routing/table",
        names={"to-lab-wan10g", "to-lab-wan1g"},
    )
    addresses = _managed_rows(
        admin,
        "ip/address",
        comment_prefix="routercfg:managed:wan-address:",
    )

    counts = {
        "pcc_mangle": len(pcc_mangle),
        "pcc_policy_routes": len(pcc_routes),
        "recursive_probe_routes": len(recursive_probes),
        "recursive_default_routes": len(recursive_defaults),
        "routing_tables": len(tables),
        "wan_addresses": len(addresses),
    }
    expected = {
        "pcc_mangle": 13,
        "pcc_policy_routes": 8,
        "recursive_probe_routes": 4,
        "recursive_default_routes": 4,
        "routing_tables": 2,
        "wan_addresses": 2,
    }
    if counts != expected:
        raise CHRMutationRollbackError(
            f"mutated RouterOS state does not match the generated fixture: expected={expected} observed={counts}"
        )
    return counts


def _assert_managed_state_absent(admin: base.LoopbackCHRAdmin) -> None:
    remaining: dict[str, int] = {}
    checks = (
        ("pcc_mangle", "ip/firewall/mangle", "routercfg:managed:pcc-"),
        ("pcc_routes", "ip/route", "routercfg:managed:pcc-route:"),
        ("recursive_defaults", "ip/route", "routercfg:managed:default:"),
        ("recursive_probes", "ip/route", "routercfg:managed:probe:"),
        ("wan_addresses", "ip/address", "routercfg:managed:wan-address:"),
        ("wan_members", "interface/list/member", "routercfg:managed:wan:"),
        ("core_members", "interface/list/member", "routercfg:managed:core-uplink"),
    )
    for key, path, prefix in checks:
        count = len(_managed_rows(admin, path, comment_prefix=prefix))
        if count:
            remaining[key] = count
    tables = _named_rows(
        admin,
        "routing/table",
        names={"to-lab-wan10g", "to-lab-wan1g"},
    )
    if tables:
        remaining["routing_tables"] = len(tables)
    lists = _named_rows(
        admin,
        "interface/list",
        names={"routercfg-WAN", "routercfg-CORE"},
    )
    if lists:
        remaining["interface_lists"] = len(lists)
    if remaining:
        raise CHRMutationRollbackError(
            f"managed RouterOS objects remain after rollback: {remaining}"
        )


def verify_mutation_rollback(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    fixture = fixture_builder.build_syntax_fixture()
    commands = fixture.get("commands", [])
    if len(commands) != 38:
        raise CHRMutationRollbackError(
            f"mutation lab requires the accepted 38-command fixture, observed {len(commands)}"
        )
    apply_script = "\n".join(str(item["command"]) for item in commands) + "\n"

    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

    baseline = chunked._configuration_snapshot_with_pcc(admin)
    baseline_digest = base._canonical_digest(baseline)
    mutated_digest = None
    rollback_digest = None
    apply_result: dict[str, Any] | None = None
    failure_result: dict[str, Any] | None = None
    rollback_result: dict[str, Any] | None = None
    mutated_counts: dict[str, int] | None = None
    rollback_verified = False

    try:
        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
        apply_result = _execute_import(
            admin,
            file_name=APPLY_FILE,
            expect_success=True,
        )
        mutated = chunked._configuration_snapshot_with_pcc(admin)
        mutated_digest = base._canonical_digest(mutated)
        if mutated_digest == baseline_digest:
            raise CHRMutationRollbackError(
                "mutation apply did not change the RouterOS configuration digest"
            )
        mutated_counts = _assert_mutated_state(admin)

        chunked._create_text_file_chunk_verified(admin, FAIL_FILE, "this\n")
        failure_result = _execute_import(
            admin,
            file_name=FAIL_FILE,
            expect_success=False,
        )

        rollback_script = _rollback_script()
        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
        rollback_result = _execute_import(
            admin,
            file_name=ROLLBACK_FILE,
            expect_success=True,
        )
        _assert_managed_state_absent(admin)
        rolled_back = chunked._configuration_snapshot_with_pcc(admin)
        rollback_digest = base._canonical_digest(rolled_back)
        if rollback_digest != baseline_digest:
            raise CHRMutationRollbackError(
                "rollback completed but RouterOS configuration digest did not return to baseline"
            )
        rollback_verified = True
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)

    return {
        "ok": rollback_verified,
        "scope": "disposable_chr_mutation_failure_rollback",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "fixture": {
            "command_count": len(commands),
            "recursive_command_count": int(fixture.get("base_command_count") or 0),
            "pcc_command_count": int(fixture.get("pcc_command_count") or 0),
        },
        "apply": apply_result,
        "mutated_counts": mutated_counts,
        "failure_injection": failure_result,
        "rollback": rollback_result,
        "configuration_baseline_sha256": baseline_digest,
        "configuration_mutated_sha256": mutated_digest,
        "configuration_rollback_sha256": rollback_digest,
        "mutation_observed": mutated_digest is not None and mutated_digest != baseline_digest,
        "failure_observed": bool(failure_result and failure_result.get("verdict") == "ERROR"),
        "rollback_digest_restored": rollback_digest == baseline_digest,
        "managed_objects_removed": rollback_verified,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "acceptance": "PASS" if rollback_verified else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply, fail and rollback the RouterOS CHR combined fixture"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9280")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_mutation_rollback(admin_url=args.admin_url)
        rc = 0 if result.get("ok") else 15
    except (OSError, base.CHRRenderDryRunError, CHRMutationRollbackError) as exc:
        result = {
            "ok": False,
            "error": str(exc),
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "acceptance": "FAIL",
        }
        rc = 15

    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
