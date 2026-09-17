"""Yamaha RTX3510 exact model/firmware read-only admission primitives."""

from __future__ import annotations

from dataclasses import dataclass
import re


_DOCUMENTATION_SOURCE_IDS = (
    "YAMAHA-RTX3510-TECHDOCS",
    "YAMAHA-RTX3510-SPEC",
    "YAMAHA-RTX3510-SUPPORT",
    "YAMAHA-RTX3510-FIRMWARE",
    "YAMAHA-RTX3510-RELNOTE-23.01.03",
    "YAMAHA-RTX-MANUAL-INDEX",
    "YAMAHA-RTX-CMDREF",
    "YAMAHA-RTX3510-USERGUIDE",
)
_ADMITTED_MODEL = "RTX3510"
_ADMITTED_FIRMWARE = "23.01.03"


@dataclass(frozen=True)
class YamahaPlatformDecision:
    status: str
    model: str
    firmware_version: str
    normalized_model: str | None
    normalized_firmware: str | None
    documentation_source_ids: tuple[str, ...]
    read_only_candidate: bool
    write_authorized: bool = False
    physical_device_verified: bool = False


def normalize_model(model: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", model.upper())


def normalize_firmware(firmware_version: str) -> str | None:
    match = re.fullmatch(
        r"\s*(?:Rev\.)?(\d{2}\.\d{2}\.\d{2})\s*",
        firmware_version,
        flags=re.IGNORECASE,
    )
    return match.group(1) if match else None


def assess_read_only_candidate(
    model: str,
    firmware_version: str,
) -> YamahaPlatformDecision:
    normalized_model = normalize_model(model)
    normalized_firmware = normalize_firmware(firmware_version)

    if normalized_model != _ADMITTED_MODEL:
        return YamahaPlatformDecision(
            status="UNVERIFIED_PLATFORM",
            model=model,
            firmware_version=firmware_version,
            normalized_model=normalized_model or None,
            normalized_firmware=normalized_firmware,
            documentation_source_ids=(),
            read_only_candidate=False,
        )

    if normalized_firmware != _ADMITTED_FIRMWARE:
        return YamahaPlatformDecision(
            status="UNVERIFIED_VERSION",
            model=model,
            firmware_version=firmware_version,
            normalized_model=normalized_model,
            normalized_firmware=normalized_firmware,
            documentation_source_ids=_DOCUMENTATION_SOURCE_IDS,
            read_only_candidate=False,
        )

    return YamahaPlatformDecision(
        status="DOCUMENTED_READ_ONLY_CANDIDATE",
        model=model,
        firmware_version=firmware_version,
        normalized_model=normalized_model,
        normalized_firmware=normalized_firmware,
        documentation_source_ids=_DOCUMENTATION_SOURCE_IDS,
        read_only_candidate=True,
    )
