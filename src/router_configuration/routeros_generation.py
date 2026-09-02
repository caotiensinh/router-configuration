from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .render_readiness import assess_render_readiness
from .routeros_renderer import RouterOSRenderError, RouterOSSafeSubsetRenderer


@dataclass(frozen=True)
class RouterOSGenerationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    readiness: Mapping[str, Any]
    render_plan: Mapping[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return not self.errors and self.render_plan is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "claim": "routeros_generation_complete" if self.ok else "routeros_generation_blocked",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "readiness": dict(self.readiness),
            "render_plan": dict(self.render_plan) if self.render_plan is not None else None,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }


def generate_routeros_plan(
    *,
    profile: Mapping[str, Any],
    ir: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> RouterOSGenerationResult:
    """Gate pure RouterOS generation behind verified profile/IR/live-state readiness.

    This boundary deliberately does not accept credentials, URLs or a transport.
    A partial render plan is still a successful generation artifact when the
    renderer explicitly records missing operator/environment facts as blockers;
    such a plan remains non-applicable and cannot authorize writes.
    """

    readiness_result = assess_render_readiness(
        profile=profile,
        ir=ir,
        evidence=evidence,
    )
    readiness = readiness_result.as_dict()
    if not readiness_result.ok:
        return RouterOSGenerationResult(
            errors=readiness_result.errors,
            warnings=readiness_result.warnings,
            readiness=readiness,
        )

    try:
        plan = RouterOSSafeSubsetRenderer().render(ir).as_dict()
    except RouterOSRenderError as exc:
        return RouterOSGenerationResult(
            errors=(f"renderer: {exc}",),
            warnings=readiness_result.warnings,
            readiness=readiness,
        )

    if plan.get("source_ir_sha256") != readiness_result.ir_sha256:
        return RouterOSGenerationResult(
            errors=("renderer source IR digest does not match readiness binding",),
            warnings=readiness_result.warnings,
            readiness=readiness,
        )
    if any(
        plan.get(field) is not expected
        for field, expected in (
            ("secrets_resolved", False),
            ("transport_present", False),
            ("apply_available", False),
            ("write_authorized", False),
        )
    ):
        return RouterOSGenerationResult(
            errors=("renderer plan violated the generation-only safety boundary",),
            warnings=readiness_result.warnings,
            readiness=readiness,
        )

    return RouterOSGenerationResult(
        errors=(),
        warnings=readiness_result.warnings,
        readiness=readiness,
        render_plan=plan,
    )
