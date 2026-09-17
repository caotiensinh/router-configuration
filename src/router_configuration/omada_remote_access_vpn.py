from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


class RemoteAccessVpnError(ValueError):
    pass


_PROTOCOLS = frozenset({"WIREGUARD", "OPENVPN", "L2TP", "PPTP"})
_SECRET_KEYS = frozenset({"password", "psk", "private_key", "token", "secret", "client_secret"})
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{2,255}$")


def _safe_text(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise RemoteAccessVpnError(f"{label} must be a non-empty safe value")
    return text


def _reject_secret_values(value: object, path: str = "vpn") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if name in _SECRET_KEYS or any(marker in name for marker in ("password", "private_key", "client_secret", "preshared")):
                raise RemoteAccessVpnError(f"{path} contains secret-bearing field: {key}")
            _reject_secret_values(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_secret_values(child, f"{path}[{index}]")


def _networks(values: Iterable[str], label: str) -> tuple[str, ...]:
    result: list[ipaddress._BaseNetwork] = []
    for raw in values:
        try:
            network = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise RemoteAccessVpnError(f"{label} contains invalid network") from exc
        result.append(network)
    if not result:
        raise RemoteAccessVpnError(f"{label} must not be empty")
    canonical = [str(item) for item in result]
    if len(canonical) != len(set(canonical)):
        raise RemoteAccessVpnError(f"{label} contains duplicates")
    return tuple(canonical)


@dataclass(frozen=True)
class RemoteAccessVpnPlan:
    protocol: str
    model: str
    firmware: str
    region: str
    controller_version: str
    mode: str
    client_pool: tuple[str, ...]
    protected_networks: tuple[str, ...]
    credential_ref: str
    write_authorized: bool = False
    hardware_verified: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "model": self.model,
            "firmware": self.firmware,
            "region": self.region,
            "controller_version": self.controller_version,
            "mode": self.mode,
            "client_pool": list(self.client_pool),
            "protected_networks": list(self.protected_networks),
            "credential_ref": self.credential_ref,
            "write_authorized": False,
            "hardware_verified": False,
        }


def build_remote_access_vpn_plan(
    *,
    protocol: str,
    model: str,
    firmware: str,
    region: str,
    controller_version: str,
    mode: str,
    client_pool: Sequence[str],
    protected_networks: Sequence[str],
    credential_ref: str,
    extra: Mapping[str, object] | None = None,
) -> RemoteAccessVpnPlan:
    proto = _safe_text(protocol, "protocol").upper()
    if proto not in _PROTOCOLS:
        raise RemoteAccessVpnError("protocol is not in the documented normalized family set")
    model_v = _safe_text(model, "model")
    firmware_v = _safe_text(firmware, "firmware")
    region_v = _safe_text(region, "region")
    controller_v = _safe_text(controller_version, "controller_version")
    mode_v = _safe_text(mode, "mode").upper()
    if mode_v not in {"CONTROLLER", "STANDALONE"}:
        raise RemoteAccessVpnError("mode must be CONTROLLER or STANDALONE")
    ref = _safe_text(credential_ref, "credential_ref")
    if not _SAFE_REF.fullmatch(ref) or "://" not in ref:
        raise RemoteAccessVpnError("credential_ref must be an opaque reference, not a secret value")

    clients = _networks(client_pool, "client_pool")
    protected = _networks(protected_networks, "protected_networks")
    client_objs = [ipaddress.ip_network(item) for item in clients]
    protected_objs = [ipaddress.ip_network(item) for item in protected]
    if any(a.overlaps(b) for a in client_objs for b in protected_objs):
        raise RemoteAccessVpnError("client_pool must not overlap protected_networks")

    if extra is not None:
        _reject_secret_values(extra)

    return RemoteAccessVpnPlan(
        protocol=proto,
        model=model_v,
        firmware=firmware_v,
        region=region_v,
        controller_version=controller_v,
        mode=mode_v,
        client_pool=clients,
        protected_networks=protected,
        credential_ref=ref,
    )
