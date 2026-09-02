from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from router_configuration.routeros_state_contract import verify_routeros_discovery_evidence


COMMENT = "routercfg-disposable-live-acceptance"


def _records_with_comment(records: Any, comment: str) -> list[Mapping[str, Any]]:
    if not isinstance(records, list):
        return []
    return [
        item
        for item in records
        if isinstance(item, Mapping) and item.get("comment") == comment
    ]


def verify_populated_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    integrity = verify_routeros_discovery_evidence(evidence)
    errors: list[str] = list(integrity.errors)

    collection = evidence.get("collection", {})
    if collection.get("failed_surfaces"):
        errors.append("live discovery contains failed surfaces")
    if collection.get("missing_surfaces"):
        errors.append("live discovery contains missing surfaces")

    state = evidence.get("normalized_state", {})
    firewall = state.get("firewall", {}) if isinstance(state, Mapping) else {}
    wireguard = state.get("wireguard", {}) if isinstance(state, Mapping) else {}
    qos = state.get("qos", {}) if isinstance(state, Mapping) else {}

    populated = {
        "firewall_filter": _records_with_comment(firewall.get("filter"), COMMENT),
        "firewall_nat": _records_with_comment(firewall.get("nat"), COMMENT),
        "wireguard_interfaces": _records_with_comment(wireguard.get("interfaces"), COMMENT),
        "qos_simple_queues": _records_with_comment(qos.get("simple_queues"), COMMENT),
    }

    for surface, records in populated.items():
        if not records:
            errors.append(f"expected populated acceptance object missing: {surface}")

    for item in populated["wireguard_interfaces"]:
        if "private-key" in item and item.get("private-key") != "<redacted>":
            errors.append("wireguard private-key was not redacted")

    return {
        "ok": not errors,
        "errors": errors,
        "state_sha256": evidence.get("state_sha256"),
        "platform": evidence.get("platform"),
        "populated_counts": {key: len(value) for key, value in populated.items()},
        "secret_boundary_verified": not any("private-key" in error for error in errors),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify populated disposable CHR evidence after read-only collection"
    )
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()

    payload = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    result = verify_populated_evidence(payload)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 8


if __name__ == "__main__":
    raise SystemExit(main())
