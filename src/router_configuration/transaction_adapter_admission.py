from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

from .transaction_lifecycle import TransactionLifecycleError, _verify_lifecycle


class TransactionAdapterAdmissionError(ValueError):
    pass


@dataclass(frozen=True)
class TransactionAdapterAdmission:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def admit_disposable_chr_candidate(
    *,
    render_plan: Mapping[str, Any],
    envelope: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    target: Mapping[str, Any],
) -> TransactionAdapterAdmission:
    """Admit only an exact, authorized candidate to a disposable-CHR adapter.

    This function exposes no network transport and performs no mutation. It is a
    fail-closed boundary that a future lab runtime adapter must pass before it can
    consume an approved plan. Production and physical-router admission remain
    deliberately impossible here.
    """

    try:
        _verify_lifecycle(lifecycle)
    except TransactionLifecycleError as exc:
        raise TransactionAdapterAdmissionError("transaction lifecycle verification failed") from exc

    if lifecycle.get("phase") != "authorized":
        raise TransactionAdapterAdmissionError("adapter candidate requires authorized lifecycle phase")
    for field in (
        "transport_present",
        "apply_available",
        "rollback_available",
        "production_writer_available",
        "write_authorized",
        "secret_values_present",
    ):
        if lifecycle.get(field) is not False:
            raise TransactionAdapterAdmissionError(f"lifecycle must keep {field}=false")

    if envelope.get("schema_version") != "routeros-transaction-envelope/1":
        raise TransactionAdapterAdmissionError("unsupported transaction envelope schema")
    for field in (
        "transport_present",
        "apply_available",
        "production_writer_available",
        "write_authorized",
        "secret_values_present",
    ):
        if envelope.get(field) is not False:
            raise TransactionAdapterAdmissionError(f"envelope must keep {field}=false")

    transaction_id = str(envelope.get("transaction_id") or "")
    envelope_sha = str(envelope.get("envelope_sha256") or "")
    if not hmac.compare_digest(
        str(lifecycle.get("transaction_id") or ""), transaction_id
    ):
        raise TransactionAdapterAdmissionError("lifecycle is bound to a different transaction")
    if not hmac.compare_digest(
        str(lifecycle.get("envelope_sha256") or ""), envelope_sha
    ):
        raise TransactionAdapterAdmissionError("lifecycle is bound to a different envelope")

    bindings = envelope.get("bindings")
    if not isinstance(bindings, Mapping):
        raise TransactionAdapterAdmissionError("transaction envelope bindings are missing")
    expected_render_sha = str(bindings.get("render_plan_sha256") or "")
    supplied_render_sha = str(render_plan.get("render_sha256") or "")
    if not expected_render_sha or not hmac.compare_digest(
        supplied_render_sha, expected_render_sha
    ):
        raise TransactionAdapterAdmissionError("render plan does not match the approved envelope")
    if render_plan.get("transport_present") is not False:
        raise TransactionAdapterAdmissionError("render plan must not contain transport")
    if render_plan.get("apply_available") is not False:
        raise TransactionAdapterAdmissionError("render plan must keep apply unavailable")
    if render_plan.get("write_authorized") is not False:
        raise TransactionAdapterAdmissionError("render plan must keep write_authorized=false")

    if target.get("target_kind") != "disposable_chr":
        raise TransactionAdapterAdmissionError("only disposable CHR is admitted by this boundary")
    if target.get("disposable") is not True or target.get("snapshot_mode") is not True:
        raise TransactionAdapterAdmissionError("CHR adapter target must be disposable snapshot mode")
    if target.get("physical_router_targeted") is not False:
        raise TransactionAdapterAdmissionError("physical router target is forbidden")
    if target.get("production") is not False:
        raise TransactionAdapterAdmissionError("production target is forbidden")
    forbidden_target_fields = {
        "password",
        "token",
        "secret",
        "private_key",
        "credential",
        "credential_ref",
        "command",
        "commands",
    }
    present = sorted(
        str(key) for key in target if str(key).lower() in forbidden_target_fields
    )
    if present:
        raise TransactionAdapterAdmissionError(
            "target metadata contains runtime-capability or secret fields: "
            + ", ".join(present)
        )

    payload = {
        "schema_version": "routeros-adapter-admission/1",
        "claim": "eligible_for_disposable_chr_adapter_only",
        "transaction_id": transaction_id,
        "envelope_sha256": envelope_sha,
        "render_sha256": expected_render_sha,
        "pre_state_sha256": str(bindings.get("pre_state_sha256") or ""),
        "target_kind": "disposable_chr",
        "disposable": True,
        "snapshot_mode": True,
        "transport_present": False,
        "credentials_present": False,
        "secret_values_present": False,
        "production_writer_available": False,
        "physical_router_targeted": False,
        "production_allowed": False,
        "write_authorized": False,
    }
    return TransactionAdapterAdmission(payload)
