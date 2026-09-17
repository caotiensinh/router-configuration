from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


class VerifiedCliRegistryError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_OFFICIAL_HOST_SUFFIXES = ("omadanetworks.com", "tp-link.com")
_FORBIDDEN_SCOPE = frozenset({"*", "ANY", "ALL", "UNKNOWN", "UNSPECIFIED", "N/A"})


def _safe_text(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise VerifiedCliRegistryError(f"{label} must be a non-empty single-line value")
    return text


def _exact_scope(value: object, label: str) -> str:
    text = _safe_text(value, label)
    if text.upper() in _FORBIDDEN_SCOPE or "*" in text:
        raise VerifiedCliRegistryError(f"{label} must identify an exact verified applicability value")
    return text


def _official_url(value: object) -> str:
    text = _safe_text(value, "source_url")
    parsed = urlparse(text)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not any(host == suffix or host.endswith(f".{suffix}") for suffix in _OFFICIAL_HOST_SUFFIXES):
        raise VerifiedCliRegistryError("source_url must be an official TP-Link/Omada HTTPS URL")
    return text


@dataclass(frozen=True)
class VerifiedCliEntry:
    command_id: str
    command: str
    operation: str
    mode: str
    model: str
    hardware_version: str
    firmware: str
    region: str
    source_url: str
    source_sha256: str
    source_locator: str

    def applicability_key(self) -> tuple[str, str, str, str]:
        return (self.model, self.hardware_version, self.firmware, self.region)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "omada-verified-cli-entry/1",
            "command_id": self.command_id,
            "command": self.command,
            "operation": self.operation,
            "mode": self.mode,
            "model": self.model,
            "hardware_version": self.hardware_version,
            "firmware": self.firmware,
            "region": self.region,
            "source_url": self.source_url,
            "source_sha256": self.source_sha256,
            "source_locator": self.source_locator,
            "verification_state": "VENDOR_DOCUMENT_VERIFIED",
            "executable": False,
            "production_write_authority": False,
        }


def build_verified_cli_entry(
    *,
    command_id: str,
    command: str,
    operation: str,
    mode: str,
    model: str,
    hardware_version: str,
    firmware: str,
    region: str,
    source_url: str,
    source_sha256: str,
    source_locator: str,
    verification_state: str,
) -> VerifiedCliEntry:
    identifier = _safe_text(command_id, "command_id")
    if not _SAFE_ID.fullmatch(identifier):
        raise VerifiedCliRegistryError("command_id format is invalid")
    if _safe_text(verification_state, "verification_state").upper() != "VENDOR_DOCUMENT_VERIFIED":
        raise VerifiedCliRegistryError("CLI entries require VENDOR_DOCUMENT_VERIFIED evidence")
    digest = str(source_sha256 or "").strip().lower()
    if not _SHA256.fullmatch(digest):
        raise VerifiedCliRegistryError("source_sha256 must be a lowercase SHA-256")
    return VerifiedCliEntry(
        command_id=identifier,
        command=_safe_text(command, "command"),
        operation=_safe_text(operation, "operation"),
        mode=_safe_text(mode, "mode"),
        model=_exact_scope(model, "model"),
        hardware_version=_exact_scope(hardware_version, "hardware_version"),
        firmware=_exact_scope(firmware, "firmware"),
        region=_exact_scope(region, "region"),
        source_url=_official_url(source_url),
        source_sha256=digest,
        source_locator=_safe_text(source_locator, "source_locator"),
    )


class VerifiedCliRegistry:
    def __init__(self, entries: Iterable[VerifiedCliEntry] = ()) -> None:
        self._entries: dict[str, VerifiedCliEntry] = {}
        for entry in entries:
            self.add(entry)

    def add(self, entry: VerifiedCliEntry) -> None:
        if not isinstance(entry, VerifiedCliEntry):
            raise VerifiedCliRegistryError("registry accepts only VerifiedCliEntry objects")
        if entry.command_id in self._entries:
            raise VerifiedCliRegistryError(f"duplicate command_id: {entry.command_id}")
        self._entries[entry.command_id] = entry

    def exact_lookup(
        self,
        command_id: str,
        *,
        model: str,
        hardware_version: str,
        firmware: str,
        region: str,
    ) -> VerifiedCliEntry:
        identifier = _safe_text(command_id, "command_id")
        try:
            entry = self._entries[identifier]
        except KeyError as exc:
            raise VerifiedCliRegistryError("verified CLI entry not found") from exc
        requested = (
            _exact_scope(model, "model"),
            _exact_scope(hardware_version, "hardware_version"),
            _exact_scope(firmware, "firmware"),
            _exact_scope(region, "region"),
        )
        if entry.applicability_key() != requested:
            raise VerifiedCliRegistryError("no exact verified applicability match; fallback is forbidden")
        return entry

    def as_dict(self) -> dict[str, object]:
        rows = [self._entries[key].as_dict() for key in sorted(self._entries)]
        return {
            "schema_version": "omada-verified-cli-registry/1",
            "entries": rows,
            "entry_count": len(rows),
            "fallback_matching": False,
            "production_write_authority": False,
        }
