from __future__ import annotations

from typing import Any, Mapping

from .routeros_generation import RouterOSGenerationResult, generate_routeros_plan
from .routeros_generation_extensions import apply_state_bound_vlan_pbr_extensions
from .routeros_pbr_renderer import RouterOSPbrRenderError
from .routeros_vlan_renderer import RouterOSVlanRenderError


def generate_routeros_plan_v1(
    *,
    profile: Mapping[str, Any],
    ir: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> RouterOSGenerationResult:
    """Generate the RouterOS v1 plan including state-bound VLAN/PBR extensions.

    The existing generation core remains authoritative for readiness, base
    topology, firewall, WireGuard, QoS and PCC. VLAN/PBR are attached only
    after that boundary succeeds. No credentials, secret resolution, transport
    or apply capability are introduced here.
    """

    base = generate_routeros_plan(profile=profile, ir=ir, evidence=evidence)
    if not base.ok or base.render_plan is None:
        return base

    try:
        plan = apply_state_bound_vlan_pbr_extensions(
            base_plan=base.render_plan,
            ir=ir,
            evidence=evidence,
        )
    except RouterOSVlanRenderError as exc:
        return RouterOSGenerationResult(
            errors=(f"vlan renderer: {exc}",),
            warnings=base.warnings,
            readiness=base.readiness,
        )
    except RouterOSPbrRenderError as exc:
        return RouterOSGenerationResult(
            errors=(f"pbr renderer: {exc}",),
            warnings=base.warnings,
            readiness=base.readiness,
        )
    except ValueError as exc:
        return RouterOSGenerationResult(
            errors=(f"generation extension: {exc}",),
            warnings=base.warnings,
            readiness=base.readiness,
        )

    return RouterOSGenerationResult(
        errors=(),
        warnings=base.warnings,
        readiness=base.readiness,
        render_plan=plan,
    )
