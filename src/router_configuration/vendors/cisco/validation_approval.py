"""Deterministic Cisco IOS XE validation and approval-fingerprint binding.

This module is deliberately pre-write. It validates a source-bound desired-state
artifact and builds an immutable fingerprint that a later human approval record
may reference. It never approves, applies, connects to, or mutates a device.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
import xml.etree.ElementTree as ET

from .desired_state import DesiredStateRender, desired_state_catalog_digest

_IOSXE_NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CHANGE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
_SUPPORTED_FEATURE_LEAVES = {
    "interface.description.set": "description",
    "interface.mtu.set": "mtu",
}
_MIN_INTERFACE_MTU = 64
_MAX_INTERFACE_MTU = 18000


class CiscoValidationApprovalError(ValueError):
    """Raised when validation or approval binding fails closed."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise CiscoValidationApprovalError(
            f"{label} must be a 64-character lowercase SHA-256 digest"
        )
    return normalized


def _require_ref(value: object, label: str, pattern: re.Pattern[str]) -> str:
    text = str(value or "").strip()
    if not pattern.fullmatch(text):
        raise CiscoValidationApprovalError(f"{label} contains unsupported characters")
    return text


@dataclass(frozen=True)
class CiscoValidationAttestation:
    target_id: str
    pre_state_sha256: str
    payload_digest_sha256: str
    schema_inventory_digest_sha256: str
    catalog_digest_sha256: str
    model: str
    iosxe_version: str
    documentation_train: str
    platform_family: str
    role: str
    feature_id: str
    validation_sha256: str
    passed: bool = True
    findings: tuple[str, ...] = ()
    c08_complete: bool = False
    write_authorized: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["schema_version"] = "cisco-validation-attestation/1"
        return payload


@dataclass(frozen=True)
class CiscoApprovalBinding:
    change_id: str
    target_id: str
    pre_state_sha256: str
    payload_digest_sha256: str
    schema_inventory_digest_sha256: str
    catalog_digest_sha256: str
    validation_sha256: str
    model: str
    iosxe_version: str
    documentation_train: str
    platform_family: str
    role: str
    feature_id: str
    target_datastore: str
    approval_sha256: str
    approval_bound: bool = False
    human_approved: bool = False
    c08_complete: bool = False
    apply_authorized: bool = False
    write_authorized: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["schema_version"] = "cisco-approval-binding/1"
        return payload


def _validate_exact_native_payload(render: DesiredStateRender) -> None:
    calculated = hashlib.sha256(render.payload_xml.encode("utf-8")).hexdigest()
    if calculated != _require_sha256(
        render.payload_digest_sha256,
        "render.payload_digest_sha256",
    ):
        raise CiscoValidationApprovalError("desired-state payload digest mismatch")

    leaf_name = _SUPPORTED_FEATURE_LEAVES.get(render.feature_id)
    if leaf_name is None:
        raise CiscoValidationApprovalError(
            f"unsupported desired-state feature for C08 validation: {render.feature_id}"
        )

    try:
        root = ET.fromstring(render.payload_xml)
    except ET.ParseError as exc:
        raise CiscoValidationApprovalError("desired-state payload is not valid XML") from exc

    native = f"{{{_IOSXE_NATIVE_NS}}}native"
    interface = f"{{{_IOSXE_NATIVE_NS}}}interface"
    gigabit = f"{{{_IOSXE_NATIVE_NS}}}GigabitEthernet"
    name = f"{{{_IOSXE_NATIVE_NS}}}name"
    feature_leaf = f"{{{_IOSXE_NATIVE_NS}}}{leaf_name}"

    if root.tag != native or root.attrib:
        raise CiscoValidationApprovalError("payload root is outside the bounded Cisco Native schema")
    root_children = list(root)
    if (
        len(root_children) != 1
        or root_children[0].tag != interface
        or root_children[0].attrib
    ):
        raise CiscoValidationApprovalError("payload must contain exactly one native interface container")
    interface_children = list(root_children[0])
    if (
        len(interface_children) != 1
        or interface_children[0].tag != gigabit
        or interface_children[0].attrib
    ):
        raise CiscoValidationApprovalError("payload must contain exactly one GigabitEthernet entry")
    leaves = list(interface_children[0])
    if [leaf.tag for leaf in leaves] != [name, feature_leaf] or any(leaf.attrib for leaf in leaves):
        raise CiscoValidationApprovalError(
            f"payload structure differs from the source-bound {render.feature_id} slice"
        )
    if not (leaves[0].text or "").strip():
        raise CiscoValidationApprovalError("payload interface name must remain nonempty")

    value = (leaves[1].text or "").strip()
    if render.feature_id == "interface.description.set":
        if not value:
            raise CiscoValidationApprovalError("payload description must remain nonempty")
    elif render.feature_id == "interface.mtu.set":
        if not value.isdigit():
            raise CiscoValidationApprovalError("payload MTU must be an unsigned decimal integer")
        mtu = int(value)
        if not _MIN_INTERFACE_MTU <= mtu <= _MAX_INTERFACE_MTU:
            raise CiscoValidationApprovalError("payload MTU is outside the source-bound range")


def validate_desired_state_render(
    *,
    target_id: str,
    pre_state_sha256: str,
    render: DesiredStateRender,
) -> CiscoValidationAttestation:
    """Validate one C07 artifact without creating approval or write authority."""

    target = _require_ref(target_id, "target_id", _TARGET_ID_RE)
    pre_state = _require_sha256(pre_state_sha256, "pre_state_sha256")
    schema_digest = _require_sha256(
        render.schema_inventory_digest_sha256,
        "render.schema_inventory_digest_sha256",
    )
    catalog_digest = _require_sha256(
        render.catalog_digest_sha256,
        "render.catalog_digest_sha256",
    )
    if catalog_digest != desired_state_catalog_digest():
        raise CiscoValidationApprovalError("desired-state artifact uses a stale or different catalog")
    if render.approval_bound or render.apply_authorized or render.production_write_authorized:
        raise CiscoValidationApprovalError("C07 artifact crossed the pre-write safety boundary")
    if render.target_datastore != "candidate":
        raise CiscoValidationApprovalError("C08 validation accepts only candidate-datastore artifacts")
    if render.required_module != "Cisco-IOS-XE-native":
        raise CiscoValidationApprovalError("C08 validation requires the pinned Cisco Native module")

    _validate_exact_native_payload(render)
    payload_digest = _require_sha256(
        render.payload_digest_sha256,
        "render.payload_digest_sha256",
    )
    unsigned = {
        "schema_version": "cisco-validation-attestation/1",
        "target_id": target,
        "pre_state_sha256": pre_state,
        "payload_digest_sha256": payload_digest,
        "schema_inventory_digest_sha256": schema_digest,
        "catalog_digest_sha256": catalog_digest,
        "model": render.model,
        "iosxe_version": render.iosxe_version,
        "documentation_train": render.documentation_train,
        "platform_family": render.platform_family,
        "role": render.role,
        "feature_id": render.feature_id,
        "passed": True,
        "findings": [],
        "c08_complete": False,
        "write_authorized": False,
        "production_write_authorized": False,
    }
    return CiscoValidationAttestation(
        target_id=target,
        pre_state_sha256=pre_state,
        payload_digest_sha256=payload_digest,
        schema_inventory_digest_sha256=schema_digest,
        catalog_digest_sha256=catalog_digest,
        model=render.model,
        iosxe_version=render.iosxe_version,
        documentation_train=render.documentation_train,
        platform_family=render.platform_family,
        role=render.role,
        feature_id=render.feature_id,
        validation_sha256=_canonical_sha256(unsigned),
    )


def build_approval_binding(
    *,
    change_id: str,
    target_id: str,
    pre_state_sha256: str,
    render: DesiredStateRender,
    validation: CiscoValidationAttestation,
) -> CiscoApprovalBinding:
    """Build a fingerprint to approve later; this function does not approve it."""

    change = _require_ref(change_id, "change_id", _CHANGE_ID_RE)
    target = _require_ref(target_id, "target_id", _TARGET_ID_RE)
    pre_state = _require_sha256(pre_state_sha256, "pre_state_sha256")
    expected = validate_desired_state_render(
        target_id=target,
        pre_state_sha256=pre_state,
        render=render,
    )
    if validation != expected or not validation.passed or validation.findings:
        raise CiscoValidationApprovalError(
            "validation attestation is stale or belongs to a different target/state/render set"
        )

    unsigned = {
        "schema_version": "cisco-approval-binding/1",
        "change_id": change,
        "target_id": target,
        "pre_state_sha256": pre_state,
        "payload_digest_sha256": render.payload_digest_sha256,
        "schema_inventory_digest_sha256": render.schema_inventory_digest_sha256,
        "catalog_digest_sha256": render.catalog_digest_sha256,
        "validation_sha256": validation.validation_sha256,
        "model": render.model,
        "iosxe_version": render.iosxe_version,
        "documentation_train": render.documentation_train,
        "platform_family": render.platform_family,
        "role": render.role,
        "feature_id": render.feature_id,
        "target_datastore": render.target_datastore,
    }
    return CiscoApprovalBinding(
        change_id=change,
        target_id=target,
        pre_state_sha256=pre_state,
        payload_digest_sha256=render.payload_digest_sha256,
        schema_inventory_digest_sha256=render.schema_inventory_digest_sha256,
        catalog_digest_sha256=render.catalog_digest_sha256,
        validation_sha256=validation.validation_sha256,
        model=render.model,
        iosxe_version=render.iosxe_version,
        documentation_train=render.documentation_train,
        platform_family=render.platform_family,
        role=render.role,
        feature_id=render.feature_id,
        target_datastore=render.target_datastore,
        approval_sha256=_canonical_sha256(unsigned),
    )


def validate_approval_fingerprint(
    binding: CiscoApprovalBinding,
    approved_sha256: str,
) -> None:
    """Verify an externally recorded fingerprint without granting write authority."""

    supplied = _require_sha256(approved_sha256, "approved_sha256")
    if supplied != binding.approval_sha256:
        raise CiscoValidationApprovalError(
            "approval fingerprint is stale or belongs to a different target/state/render set"
        )
