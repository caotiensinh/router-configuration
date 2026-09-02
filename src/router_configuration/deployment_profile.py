from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .harness import DeploymentSpec, Environment, OperatorMode
from .m04_multiwan import MultiWanPlanner, WanLink


@dataclass(frozen=True)
class ProfileValidationResult:
    ok: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    deployment_spec: DeploymentSpec | None = None
    wan_weights: tuple[tuple[str, int], ...] = ()


class DeploymentProfileValidator:
    _SENSITIVE = (
        "password", "passwd", "private_key", "preshared_key", "psk",
        "token", "credential",
    )

    def _scan_plaintext_secrets(self, value: Any, path: str = "$") -> list[str]:
        findings: list[str] = []
        if isinstance(value, Mapping):
            for key, child in value.items():
                key_text = str(key)
                lowered = key_text.lower()
                child_path = f"{path}.{key_text}"
                is_reference = lowered.endswith("_ref") or lowered in {
                    "secret_ref", "credential_ref"
                }
                if not is_reference and any(token in lowered for token in self._SENSITIVE):
                    findings.append(child_path)
                findings.extend(self._scan_plaintext_secrets(child, child_path))
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                findings.extend(self._scan_plaintext_secrets(child, f"{path}[{index}]"))
        return findings

    def validate(self, data: Mapping[str, Any]) -> ProfileValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        if data.get("schema_version") != "1.0":
            errors.append("schema_version must be 1.0")

        sensitive = self._scan_plaintext_secrets(data)
        if sensitive:
            errors.append(
                "plaintext secret-like fields are forbidden: " + ", ".join(sensitive)
            )

        device = data.get("device")
        if not isinstance(device, Mapping):
            errors.append("device object is required")
            device = {}

        try:
            environment = Environment(str(data.get("environment", "production")))
        except ValueError:
            errors.append("environment must be lab, staging or production")
            environment = Environment.PRODUCTION

        try:
            operator_mode = OperatorMode(str(data.get("operator_mode", "guided")))
        except ValueError:
            errors.append("operator_mode must be guided, admin or expert")
            operator_mode = OperatorMode.GUIDED

        allow_write = data.get("allow_write", False)
        if not isinstance(allow_write, bool):
            errors.append("allow_write must be boolean")
            allow_write = False

        spec = DeploymentSpec(
            device_id=str(device.get("id", "")),
            vendor=str(device.get("vendor", "")),
            management_target=str(device.get("management_target", "")),
            environment=environment,
            operator_mode=operator_mode,
            site_name=str(data.get("site_name", "default")),
            allow_write=allow_write,
        )
        errors.extend(spec.validate())

        topology = data.get("topology")
        if not isinstance(topology, Mapping):
            errors.append("topology object is required")
            topology = {}

        wans = topology.get("wans", [])
        if not isinstance(wans, list):
            errors.append("topology.wans must be a list")
            wans = []
        if len(wans) < 2:
            errors.append("dual-WAN profile requires at least two WAN links")

        links: list[WanLink] = []
        names: set[str] = set()
        interfaces: set[str] = set()
        for index, wan in enumerate(wans):
            if not isinstance(wan, Mapping):
                errors.append(f"topology.wans[{index}] must be an object")
                continue
            name = str(wan.get("name", "")).strip()
            interface = str(wan.get("interface", "")).strip()
            capacity = wan.get("capacity_mbps")
            if not name:
                errors.append(f"topology.wans[{index}].name is required")
            elif name in names:
                errors.append(f"duplicate WAN name: {name}")
            names.add(name)
            if not interface:
                errors.append(f"topology.wans[{index}].interface is required")
            elif interface in interfaces:
                errors.append(f"duplicate interface assignment: {interface}")
            interfaces.add(interface)
            if not isinstance(capacity, int) or capacity <= 0:
                errors.append(
                    f"topology.wans[{index}].capacity_mbps must be a positive integer"
                )
            elif name:
                links.append(
                    WanLink(name, capacity, bool(wan.get("enabled", True)))
                )

        core = topology.get("core")
        if not isinstance(core, Mapping):
            errors.append("topology.core object is required")
        else:
            core_interface = str(core.get("interface", "")).strip()
            core_capacity = core.get("capacity_mbps")
            if not core_interface:
                errors.append("topology.core.interface is required")
            elif core_interface in interfaces:
                errors.append("core interface must not also be assigned to a WAN")
            if not isinstance(core_capacity, int) or core_capacity <= 0:
                errors.append(
                    "topology.core.capacity_mbps must be a positive integer"
                )

        if environment is Environment.PRODUCTION and allow_write and not data.get("maintenance_window"):
            warnings.append("production write profile has no maintenance_window metadata")
        if environment is Environment.PRODUCTION and not data.get("recovery_access"):
            warnings.append(
                "production profile should document console/out-of-band recovery access"
            )

        weights: tuple[tuple[str, int], ...] = ()
        if links:
            try:
                weights = MultiWanPlanner().derive_capacity_weights(links).weights
            except ValueError as exc:
                errors.append(str(exc))

        return ProfileValidationResult(
            ok=not errors,
            errors=tuple(errors),
            warnings=tuple(warnings),
            deployment_spec=spec if not errors else None,
            wan_weights=weights,
        )
