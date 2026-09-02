from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .deployment_profile import DeploymentProfileValidator
from .preflight import RouterOSPreflightEvaluator
from .routeros_state_contract import verify_routeros_discovery_evidence


@dataclass(frozen=True)
class AcceptanceBundleResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    platform: Mapping[str, Any] | None = None
    routeros_version: str | None = None
    normalized_state_sha256: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "claim": "ready_for_provenance_review" if self.ok else "invalid_candidate_bundle",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "platform": dict(self.platform or {}),
            "routeros_version": self.routeros_version,
            "normalized_state_sha256": self.normalized_state_sha256,
            "provenance_verified": False,
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path, label: str, errors: list[str]) -> Mapping[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label} could not be read as JSON: {exc.__class__.__name__}")
        return None
    if not isinstance(payload, Mapping):
        errors.append(f"{label} must contain a JSON object")
        return None
    return payload


def validate_readonly_acceptance_bundle(
    *,
    profile_path: str | Path,
    evidence_path: str | Path,
    manifest_path: str | Path,
) -> AcceptanceBundleResult:
    """Validate a candidate read-only acceptance bundle.

    Passing this function proves internal consistency only. It intentionally does
    not prove that the evidence originated from CHR or from a physical router.
    That provenance remains an explicit human/lab acceptance step.
    """

    errors: list[str] = []
    warnings: list[str] = []
    profile_file = Path(profile_path)
    evidence_file = Path(evidence_path)
    manifest_file = Path(manifest_path)

    profile = _load_object(profile_file, "profile", errors)
    evidence = _load_object(evidence_file, "evidence", errors)
    manifest = _load_object(manifest_file, "manifest", errors)
    if profile is None or evidence is None or manifest is None:
        return AcceptanceBundleResult(tuple(errors), tuple(warnings))

    if manifest.get("schema_version") != "routeros-readonly-acceptance-manifest/1":
        errors.append("unsupported acceptance manifest schema")
    if manifest.get("claim_scope") != "read_only_candidate_evidence":
        errors.append("manifest claim_scope must remain read_only_candidate_evidence")

    try:
        profile_hash = _sha256_file(profile_file)
        evidence_hash = _sha256_file(evidence_file)
    except OSError as exc:
        errors.append(f"bundle file hashing failed: {exc.__class__.__name__}")
        return AcceptanceBundleResult(tuple(errors), tuple(warnings))

    if manifest.get("profile_sha256") != profile_hash:
        errors.append("manifest profile_sha256 does not match profile file")
    if manifest.get("evidence_file_sha256") != evidence_hash:
        errors.append("manifest evidence_file_sha256 does not match evidence file")

    evidence_verification = verify_routeros_discovery_evidence(evidence)
    errors.extend(f"evidence: {item}" for item in evidence_verification.errors)
    warnings.extend(f"evidence: {item}" for item in evidence_verification.warnings)

    state_sha = evidence.get("state_sha256")
    if manifest.get("normalized_state_sha256") != state_sha:
        errors.append("manifest normalized_state_sha256 does not match evidence")

    evidence_platform = evidence.get("platform")
    if manifest.get("platform") != evidence_platform:
        errors.append("manifest platform does not match evidence platform")

    profile_validation = DeploymentProfileValidator().validate(profile)
    errors.extend(f"profile: {item}" for item in profile_validation.errors)
    warnings.extend(f"profile: {item}" for item in profile_validation.warnings)

    if evidence_verification.ok and profile_validation.ok:
        preflight = RouterOSPreflightEvaluator().evaluate(profile, evidence)
        for finding in preflight.findings:
            if finding.severity.value == "blocking":
                errors.append(f"preflight[{finding.code}]: {finding.message}")
            elif finding.severity.value == "warning":
                warnings.append(f"preflight[{finding.code}]: {finding.message}")

    platform = evidence_platform if isinstance(evidence_platform, Mapping) else None
    version = None
    if platform is not None and platform.get("version") is not None:
        version = str(platform.get("version"))

    return AcceptanceBundleResult(
        errors=tuple(errors),
        warnings=tuple(warnings),
        platform=platform,
        routeros_version=version,
        normalized_state_sha256=str(state_sha) if state_sha is not None else None,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m router_configuration.acceptance_bundle",
        description="Validate a RouterOS read-only candidate acceptance bundle",
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--manifest", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = validate_readonly_acceptance_bundle(
        profile_path=args.profile,
        evidence_path=args.evidence,
        manifest_path=args.manifest,
    )
    print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    return 0 if result.ok else 7


if __name__ == "__main__":
    raise SystemExit(main())
