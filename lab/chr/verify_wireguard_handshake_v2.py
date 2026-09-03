from __future__ import annotations

from typing import Any, Mapping

import verify_wireguard_handshake as core
from router_configuration.routeros_wireguard_renderer import PRIVATE_KEY_PLACEHOLDER


def _build_apply_script(*, remote_public_key: str) -> tuple[str, dict[str, Any], str]:
    """Bind one logical deferred secret even when an idempotent template references it twice."""

    ir = core.baseline._build_ir(remote_public_key)
    plan = core.baseline.render_routeros_wireguard(ir=ir).as_dict()
    templates = plan.get("command_templates")
    if not isinstance(templates, list) or len(templates) != 4:
        raise core.CHRWireGuardHandshakeError(
            "WireGuard handshake gate requires exactly four production templates"
        )

    private_key = core.baseline._ephemeral_private_key()
    lines: list[str] = []
    secret_template_count = 0
    for item in templates:
        if not isinstance(item, Mapping):
            raise core.CHRWireGuardHandshakeError(
                "WireGuard production template plan contains a non-object"
            )
        template = str(item.get("template") or "")
        placeholders = item.get("secret_placeholders")
        if PRIVATE_KEY_PLACEHOLDER in template:
            secret_template_count += 1
            if placeholders != [PRIVATE_KEY_PLACEHOLDER]:
                raise core.CHRWireGuardHandshakeError(
                    "WireGuard secret-bearing template metadata does not match its private-key placeholder"
                )
        elif placeholders:
            raise core.CHRWireGuardHandshakeError(
                "WireGuard template declares secret metadata without a private-key placeholder"
            )
        lines.append(template.replace(PRIVATE_KEY_PLACEHOLDER, private_key))

    bindings = plan.get("secret_bindings")
    if not isinstance(bindings, Mapping) or set(bindings) != {PRIVATE_KEY_PLACEHOLDER}:
        raise core.CHRWireGuardHandshakeError(
            "WireGuard production plan must expose exactly one logical private-key secret binding"
        )
    binding = bindings[PRIVATE_KEY_PLACEHOLDER]
    if not isinstance(binding, Mapping) or binding.get("resolved") is not False:
        raise core.CHRWireGuardHandshakeError(
            "WireGuard production private-key binding must remain unresolved"
        )
    if secret_template_count != 1:
        raise core.CHRWireGuardHandshakeError(
            f"expected exactly one secret-bearing template, observed {secret_template_count}"
        )
    return "\n".join(lines) + "\n", plan, private_key


core._build_apply_script = _build_apply_script


if __name__ == "__main__":
    raise SystemExit(core.main())
