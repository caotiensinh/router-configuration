from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

from router_configuration.routeros_discovery import (
    RouterOSDiscoveryCollector,
    RouterOSRestClient,
    normalize_routeros_snapshot,
)
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.routeros_state_contract import verify_routeros_discovery_evidence


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Isolated CI-only live CHR REST GET smoke runner"
    )
    parser.add_argument("--url", default="http://127.0.0.1:9180")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise SystemExit("CI CHR smoke permits only loopback HTTP")

    client = RouterOSRestClient(
        base_url=args.url,
        username="admin",
        password="",
        verify_tls=False,
        allow_insecure_transport=True,
        timeout_seconds=5.0,
    )
    report = RouterOSDiscoveryCollector(client).collect_report()
    state = normalize_routeros_snapshot(report.data)
    evidence = build_routeros_discovery_evidence(
        state,
        surface_errors=report.errors,
    )
    verification = verify_routeros_discovery_evidence(evidence)
    if not verification.ok:
        raise SystemExit("live CHR evidence integrity verification failed")

    platform = evidence.get("platform", {})
    if not platform.get("version"):
        raise SystemExit("live CHR did not report RouterOS version")
    if not platform.get("architecture"):
        raise SystemExit("live CHR did not report architecture")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "ok": True,
                "routeros_version": platform.get("version"),
                "architecture": platform.get("architecture"),
                "failed_surfaces": evidence["collection"]["failed_surfaces"],
                "state_sha256": evidence["state_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
