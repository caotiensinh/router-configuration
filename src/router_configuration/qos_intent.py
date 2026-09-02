from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


class QoSIntentError(ValueError):
    pass


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,30}$")
_EXPLICIT_FACTS = ("egress_limits_mbps", "classes")
_SUPPORTED_POLICY = "latency_sensitive_first"


def _name(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _NAME.fullmatch(text):
        raise QoSIntentError(f"{label} contains unsupported characters")
    return text


def _positive_int(value: Any, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise QoSIntentError(f"{label} must be an integer from 1 to {maximum}")
    return value


@dataclass(frozen=True)
class NormalizedQoSIntent:
    attributes: Mapping[str, Any]


def normalize_qos_intent(qos: Mapping[str, Any]) -> NormalizedQoSIntent:
    if qos.get("enabled") is not True:
        raise QoSIntentError("QoS intent requires enabled=true")

    policy = str(qos.get("policy") or _SUPPORTED_POLICY).strip()
    if policy != _SUPPORTED_POLICY:
        raise QoSIntentError(
            f"QoS v0.1 supports only policy={_SUPPORTED_POLICY}"
        )

    explicit = [field for field in _EXPLICIT_FACTS if field in qos]
    if not explicit:
        return NormalizedQoSIntent(
            attributes={
                "enabled": True,
                "policy": policy,
            }
        )

    missing = [field for field in _EXPLICIT_FACTS if field not in qos]
    if missing:
        raise QoSIntentError(
            "explicit QoS configuration is incomplete; missing: " + ", ".join(missing)
        )

    raw_limits = qos.get("egress_limits_mbps")
    if not isinstance(raw_limits, Mapping) or not raw_limits:
        raise QoSIntentError("qos.egress_limits_mbps must be a non-empty object")
    egress_limits: dict[str, int] = {}
    for raw_name, raw_limit in raw_limits.items():
        wan_name = _name(raw_name, "qos.egress_limits_mbps WAN name")
        if wan_name in egress_limits:
            raise QoSIntentError("qos.egress_limits_mbps WAN names must be unique")
        egress_limits[wan_name] = _positive_int(
            raw_limit,
            f"qos.egress_limits_mbps.{wan_name}",
            maximum=1_000_000,
        )

    raw_classes = qos.get("classes")
    if not isinstance(raw_classes, list) or not raw_classes:
        raise QoSIntentError("qos.classes must be a non-empty list")

    names: set[str] = set()
    claimed_dscp: dict[int, str] = {}
    default_count = 0
    bandwidth_total = 0
    classes: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_classes):
        if not isinstance(raw, Mapping):
            raise QoSIntentError(f"qos.classes[{index}] must be an object")
        name = _name(raw.get("name"), f"qos.classes[{index}].name")
        if name in names:
            raise QoSIntentError("qos class names must be unique")
        names.add(name)

        priority = _positive_int(
            raw.get("priority"),
            f"qos.classes[{index}].priority",
            maximum=8,
        )
        bandwidth_percent = _positive_int(
            raw.get("bandwidth_percent"),
            f"qos.classes[{index}].bandwidth_percent",
            maximum=100,
        )
        bandwidth_total += bandwidth_percent
        if bandwidth_total > 100:
            raise QoSIntentError("sum of qos.classes bandwidth_percent must not exceed 100")

        is_default = raw.get("default", False)
        if not isinstance(is_default, bool):
            raise QoSIntentError(f"qos.classes[{index}].default must be boolean")

        raw_dscp = raw.get("dscp", [])
        if not isinstance(raw_dscp, list):
            raise QoSIntentError(f"qos.classes[{index}].dscp must be a list")
        dscp_values: list[int] = []
        for dscp_index, value in enumerate(raw_dscp):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 63:
                raise QoSIntentError(
                    f"qos.classes[{index}].dscp[{dscp_index}] must be an integer from 0 to 63"
                )
            if value in dscp_values:
                continue
            previous = claimed_dscp.get(value)
            if previous is not None:
                raise QoSIntentError(
                    f"DSCP {value} is assigned to both QoS classes {previous!r} and {name!r}"
                )
            claimed_dscp[value] = name
            dscp_values.append(value)

        if is_default:
            default_count += 1
            if dscp_values:
                raise QoSIntentError("default QoS class must not declare DSCP values")
        elif not dscp_values:
            raise QoSIntentError("non-default QoS classes require at least one DSCP value")

        classes.append(
            {
                "name": name,
                "priority": priority,
                "bandwidth_percent": bandwidth_percent,
                "default": is_default,
                "dscp": sorted(dscp_values),
            }
        )

    if default_count != 1:
        raise QoSIntentError("explicit QoS configuration requires exactly one default class")

    classes.sort(key=lambda item: (int(item["priority"]), str(item["name"])))
    return NormalizedQoSIntent(
        attributes={
            "enabled": True,
            "policy": policy,
            "classification": "existing_dscp_only",
            "queue_kind": "fq-codel",
            "egress_limits_mbps": dict(sorted(egress_limits.items())),
            "classes": classes,
        }
    )
