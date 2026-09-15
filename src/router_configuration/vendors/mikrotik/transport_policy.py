from __future__ import annotations

from dataclasses import dataclass

from .tool_registry import MikroTikToolSpec, MikroTikTransport


@dataclass(frozen=True)
class TransportRequirement:
    continuous: bool = False
    interactive_session: bool = False
    bulk_script: bool = False


def select_transport(tool: MikroTikToolSpec, requirement: TransportRequirement | None = None) -> MikroTikTransport:
    """Select a transport without exposing a transport implementation or writer.

    Interactive sessions are routed to SSH/CLI, continuous operations to the
    native API, and ordinary one-shot operations retain the tool's validated
    preferred transport. This function never executes a request.
    """

    req = requirement or TransportRequirement(continuous=tool.continuous)
    if req.interactive_session or req.bulk_script:
        return MikroTikTransport.SSH_CLI
    if req.continuous or tool.continuous:
        return MikroTikTransport.API
    return tool.preferred_transport
