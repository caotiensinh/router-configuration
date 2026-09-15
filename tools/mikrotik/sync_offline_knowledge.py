#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


SOURCES = {
    "llms.txt": "https://manual.mikrotik.com/llms.txt",
    "llms-full.txt": "https://manual.mikrotik.com/llms-full.txt",
    "sitemap.xml": "https://manual.mikrotik.com/sitemap.xml",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, destination: Path, *, timeout: float) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "router-configuration-mikrotik-knowledge-sync/1"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read()
    if not data:
        raise RuntimeError(f"empty documentation response: {url}")
    destination.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Synchronize official MikroTik machine-readable docs into a local offline snapshot."
    )
    parser.add_argument("--output", required=True, help="Snapshot directory")
    parser.add_argument("--timeout", type=float, default=180.0)
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, object]] = []
    for name, url in SOURCES.items():
        destination = output / name
        download(url, destination, timeout=args.timeout)
        artifacts.append(
            {
                "name": name,
                "source_url": url,
                "bytes": destination.stat().st_size,
                "sha256": sha256(destination),
            }
        )

    manifest = {
        "schema_version": "mikrotik-offline-snapshot/1",
        "vendor": "mikrotik",
        "authority": "official-current-manual",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "runtime_network_required": False,
        "artifacts": artifacts,
    }
    (output / "snapshot-manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
