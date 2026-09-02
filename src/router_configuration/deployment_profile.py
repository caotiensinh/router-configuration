from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .harness import DeploymentSpec, Environment, OperatorMode
from .m04_multiwan import MultiWanPlanner, WanLink


_ROUTING_TABLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}[A-Za-z0-9]$|^[A-Za-z0-9]$")


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
    _ADDRESSING_MODES = {"isp_defined", "static", "dhcp", "pppoe"}

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

    @staticmethod
    def _parse_ip(value: Any, label: str, errors: list[str]) -> ipaddress._BaseAddress | None:
        text = str(value or "").strip()
        if not text:
            errors.append(f"{label} is required")
            return None
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            errors.append(f"{label} must be an IP address")
            return None
        if address.is_unspecified or address.is_multicast:
            errors.append(f"{label} must be a usable unicast IP address")
            return None
        return address

    def _validate_wan_routing_facts(
        self,
        *,
        wan: Mapping[str, Any],
        index: int,
        addressing: str,
        routing_tables: set[str],
        errors: list[str],
    ) -> None:
        prefix = f"topology.wans[{index}]"
        static_interface: ipaddress._BaseAddress | None = None
        static_network: ipaddress._BaseNetwork | None = None

        if addressing == "static":
            address_text = str(wan.get("address") or "").strip()
            if not address_text:
                errors.append(f"{prefix}.address is required when addressing=static")
            else:
                try:
                    interface = ipaddress.ip_interface(address_text)
                except ValueError:
                    errors.append(f"{prefix}.address must be an IP interface with prefix length")
                else:
                    if interface.ip.is_unspecified or interface.ip.is_multicast or interface.ip.is_loopback:
                        errors.append(f"{prefix}.address must use a usable unicast interface address")
                    else:
                        static_interface = interface.ip
                        static_network = interface.network

        routing = wan.get("routing")
        if routing is None:
            return
        if not isinstance(routing, Mapping):
            errors.append(f"{prefix}.routing must be an object")
            return

        gateway = self._parse_ip(routing.get("gateway"), f"{prefix}.routing.gateway", errors)
        table = str(routing.get("table") or "").strip()
        if not table:
            errors.append(f"{prefix}.routing.table is required")
        elif table == "main":
            errors.append(f"{prefix}.routing.table must be a dedicated non-main table")
        elif not _ROUTING_TABLE.fullmatch(table):
            errors.append(f"{prefix}.routing.table contains unsupported characters")
        elif table in routing_tables:
            errors.append(f"duplicate WAN routing table: {table}")
        else:
            routing_tables.add(table)

        probes = routing.get("health_probe_targets")
        parsed_probes: list[ipaddress._BaseAddress] = []
        if not isinstance(probes, list):
            errors.append(f"{prefix}.routing.health_probe_targets must be a list")
        elif len(probes) < 2:
            errors.append(f"{prefix}.routing.health_probe_targets requires at least two independent targets")
        else:
            seen: set[str] = set()
            for probe_index, value in enumerate(probes):
                probe = self._parse_ip(
                    value,
                    f"{prefix}.routing.health_probe_targets[{probe_index}]",
                    errors,
                )
                if probe is None:
                    continue
                key = str(probe)
                if key in seen:
                    errors.append(f"{prefix}.routing.health_probe_targets must be unique")
                    continue
                seen.add(key)
                if gateway is not None and probe == gateway:
                    errors.append(f"{prefix}.routing.health_probe_targets must not reuse the WAN gateway")
                    continue
                parsed_probes.append(probe)

        if gateway is not None and static_network is not None and static_interface is not None:
            if gateway.version != static_interface.version:
                errors.append(f"{prefix}.routing.gateway IP family must match the static WAN address")
            elif gateway not in static_network:
                errors.append(f"{prefix}.routing.gateway must be reachable within the static WAN subnet")

        if gateway is not None:
            for probe in parsed_probes:
                if probe.version != gateway.version:
                    errors.append(f"{prefix}.routing.health_probe_targets IP family must match the gateway")
                    break

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
        routing_tables: set[str] = set()
        for index, wan in enumerate(wans):
            if not isinstance(wan, Mapping):
                errors.append(f"topology.wans[{index}] must be an object")
                continue
            name = str(wan.get("name", "")).strip()
            interface = str(wan.get("interface", "")).strip()
            capacity = wan.get("capacity_mbps")
            addressing = str(wan.get("addressing") or "isp_defined").strip().lower()
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
            if addressing not in self._ADDRESSING_MODES:
                errors.append(
                    f"topology.wans[{index}].addressing must be one of "
                    + ", ".join(sorted(self._ADDRESSING_MODES))
                )
            else:
                self._validate_wan_routing_facts(
                    wan=wan,
                    index=index,
                    addressing=addressing,
                    routing_tables=routing_tables,
                    errors=errors,
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
