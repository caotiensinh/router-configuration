from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from .postdeploy import BackupArtifact, HandoverBundleResult, build_handover_bundle
from .reference_measure import MikroTikReferenceComparison


_REQUIRED_POST_CHANGE_BACKUPS = {"sanitized_export", "binary_system_backup"}


def finalize_verified_deployment(
    *,
    output_dir: str | Path,
    deployment_record: Mapping[str, Any],
    backup_artifacts: Iterable[BackupArtifact],
    reference_comparison: MikroTikReferenceComparison,
) -> HandoverBundleResult:
    """Finalize only after recovery artifacts and vendor-reference conformance exist.

    Script execution success is deliberately insufficient. Production-style
    finalization requires a PASS post-state comparison against the MikroTik
    reference rules plus both reviewable and recovery-grade backup artifacts.
    """

    if not reference_comparison.post_ready:
        raise ValueError(
            "MikroTik deployment cannot be finalized while official-reference post-state is not ready"
        )
    if reference_comparison.regressed:
        raise ValueError("MikroTik deployment cannot be finalized with reference regressions")

    artifacts = tuple(backup_artifacts)
    kinds = {str(item.kind).strip() for item in artifacts}
    missing = sorted(_REQUIRED_POST_CHANGE_BACKUPS - kinds)
    if missing:
        raise ValueError(
            "MikroTik deployment cannot be finalized without post-change backup artifacts: "
            + ", ".join(missing)
        )

    binary = [item for item in artifacts if item.kind == "binary_system_backup"]
    if len(binary) != 1:
        raise ValueError("MikroTik finalization requires exactly one binary_system_backup")
    if not binary[0].contains_sensitive_data:
        raise ValueError("binary_system_backup must be classified as sensitive")

    export = [item for item in artifacts if item.kind == "sanitized_export"]
    if len(export) != 1:
        raise ValueError("MikroTik finalization requires exactly one sanitized_export")

    post_state = str(deployment_record.get("post_state_sha256") or "").strip()
    if not post_state:
        raise ValueError("MikroTik finalization requires post_state_sha256")

    enriched_record = dict(deployment_record)
    enriched_record["reference_comparison"] = reference_comparison.as_dict()
    return build_handover_bundle(
        output_dir=output_dir,
        deployment_record=enriched_record,
        backup_artifacts=artifacts,
    )
