from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from .routeros_capabilities import assess_routeros_capabilities

_SECRET_KEY_TOKENS = (
    "password",
    "private-key",
    "private_key",
    "preshared-key",
    "preshared_key",
    "psk",
    "secret",
    "token",
)


def _contains_unredacted_secret(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(token in lowered for token in _SECRET_KEY_TOKENS):
                if item != "<redacted>":
                    return True
            if _contains_unredacted_secret(item):
                return True
    elif isinstance(value, list):
        return any(_contains_unredacted_secret(item) for item in value)
    return False


def _state_digest(state: Mapping[str, Any]) -> str:
    payload = json.dumps(
        state,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_routeros_discovery_evidence(
    state: Mapping[str, Any],
    *,
    surface_errors: Mapping[str, str] | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a sanitized evidence artifact from normalized RouterOS state.

    Raw RouterOS responses and credentials are intentionally not part of this
    artifact. The normalized state may be persisted because the normalizer
    redacts secret-bearing keys before this boundary.
    """

    if _contains_unredacted_secret(state):
        raise ValueError("normalized state contains an unredacted secret-bearing field")

    timestamp = observed_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("observed_at must be timezone-aware")

    errors = dict(sorted((surface_errors or {}).items()))
    capabilities = assess_routeros_capabilities(state)

    counts = {
        "interfaces": len(state.get("interfaces", [])),
        "ip_addresses": len(state.get("ip_addresses", [])),
        "ip_routes": len(state.get("ip_routes", [])),
        "routing_tables": len(state.get("routing_tables", [])),
        "firewall_filter": len(state.get("firewall", {}).get("filter", [])),
        "firewall_nat": len(state.get("firewall", {}).get("nat", [])),
        "wireguard_interfaces": len(state.get("wireguard", {}).get("interfaces", [])),
        "wireguard_peers": len(state.get("wireguard", {}).get("peers", [])),
        "qos_simple_queues": len(state.get("qos", {}).get("simple_queues", [])),
        "qos_queue_tree": len(state.get("qos", {}).get("queue_tree", [])),
    }

    return {
        "schema_version": "routeros-discovery-evidence/1",
        "observed_at": timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "state_sha256": _state_digest(state),
        "platform": dict(state.get("platform", {})),
        "collection": {
            "failed_surfaces": sorted(errors),
            "surface_errors": errors,
            "missing_surfaces": list(state.get("missing_surfaces", [])),
            "record_counts": counts,
        },
        "capabilities": capabilities.as_dict(),
        "normalized_state": dict(state),
    }
