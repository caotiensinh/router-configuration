from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .deployment_profile import DeploymentProfileValidator


@dataclass(frozen=True)
class GuidedProfileRequest:
    site_name: str
    device_id: str
    management_target: str
    model: str = "CCR2116-12G-4S+"
    environment: str = "production"
    wan_primary_interface: str = "sfp-sfpplus1"
    wan_primary_capacity_mbps: int = 10000
    wan_secondary_interface: str = "ether1"
    wan_secondary_capacity_mbps: int = 1000
    core_interface: str = "sfp-sfpplus2"
    core_capacity_mbps: int = 10000
    recovery_method: str | None = None
    enable_wireguard: bool = False
    wireguard_secret_ref: str | None = None
    enable_qos: bool = False


class GuidedProfileBuilder:
    """Build a conservative deployment profile from basic network facts.

    The builder never enables write access. Advanced RouterOS implementation
    details such as PCC buckets, mangle rules or routing-table syntax are not
    exposed to the beginner-facing request.
    """

    def build(self, request: GuidedProfileRequest) -> dict:
        if request.enable_wireguard and not request.wireguard_secret_ref:
            raise ValueError(
                "WireGuard requires a secret reference; plaintext private keys are forbidden"
            )

        profile: dict = {
            "schema_version": "1.0",
            "site_name": request.site_name.strip(),
            "environment": request.environment,
            "operator_mode": "guided",
            "allow_write": False,
            "device": {
                "id": request.device_id.strip(),
                "vendor": "mikrotik",
                "model": request.model.strip(),
                "management_target": request.management_target.strip(),
            },
            "topology": {
                "wans": [
                    {
                        "name": "wan-primary",
                        "interface": request.wan_primary_interface.strip(),
                        "capacity_mbps": request.wan_primary_capacity_mbps,
                        "addressing": "isp_defined",
                        "enabled": True,
                    },
                    {
                        "name": "wan-secondary",
                        "interface": request.wan_secondary_interface.strip(),
                        "capacity_mbps": request.wan_secondary_capacity_mbps,
                        "addressing": "isp_defined",
                        "enabled": True,
                    },
                ],
                "core": {
                    "interface": request.core_interface.strip(),
                    "capacity_mbps": request.core_capacity_mbps,
                },
            },
            "intent": {
                "multiwan": {
                    "mode": "capacity_weighted",
                    "failover": True,
                    "failback": "health_hysteresis",
                },
                "security": {
                    "profile": "enterprise_baseline",
                    "wan_input_default": "deny",
                    "management_from_wan": False,
                },
                "vpn": {
                    "wireguard": {
                        "enabled": request.enable_wireguard,
                    }
                },
                "qos": {
                    "enabled": request.enable_qos,
                    "policy": "latency_sensitive_first",
                },
            },
        }

        if request.recovery_method and request.recovery_method.strip():
            profile["recovery_access"] = {
                "documented": True,
                "method": request.recovery_method.strip(),
            }

        if request.enable_wireguard:
            profile["intent"]["vpn"]["wireguard"]["secret_ref"] = (
                request.wireguard_secret_ref
            )

        result = DeploymentProfileValidator().validate(profile)
        if not result.ok:
            raise ValueError("generated profile is invalid: " + "; ".join(result.errors))
        return profile


def prompt_guided_request(
    *,
    input_fn: Callable[[str], str] = input,
    default_model: str = "CCR2116-12G-4S+",
) -> GuidedProfileRequest:
    """Collect only beginner-level facts; no router credentials are requested."""

    def required(prompt: str) -> str:
        value = input_fn(prompt).strip()
        if not value:
            raise ValueError(f"required value was empty: {prompt.strip()}")
        return value

    site_name = required("Site name: ")
    device_id = required("Router ID/name: ")
    management_target = required("Router management IP/host: ")
    model = input_fn(f"Router model [{default_model}]: ").strip() or default_model
    wan_primary = (
        input_fn("10G/primary WAN interface [sfp-sfpplus1]: ").strip()
        or "sfp-sfpplus1"
    )
    wan_secondary = input_fn("1G/secondary WAN interface [ether1]: ").strip() or "ether1"
    core = input_fn("10G core uplink interface [sfp-sfpplus2]: ").strip() or "sfp-sfpplus2"
    recovery = input_fn(
        "Recovery access method (console/OOB; leave blank if not documented): "
    ).strip()

    wireguard_answer = input_fn("Enable WireGuard intent? [y/N]: ").strip().lower()
    enable_wireguard = wireguard_answer in {"y", "yes"}
    secret_ref = None
    if enable_wireguard:
        secret_ref = required("WireGuard secret reference (not a private key): ")

    qos_answer = input_fn("Enable QoS intent? [y/N]: ").strip().lower()
    enable_qos = qos_answer in {"y", "yes"}

    return GuidedProfileRequest(
        site_name=site_name,
        device_id=device_id,
        management_target=management_target,
        model=model,
        wan_primary_interface=wan_primary,
        wan_secondary_interface=wan_secondary,
        core_interface=core,
        recovery_method=recovery or None,
        enable_wireguard=enable_wireguard,
        wireguard_secret_ref=secret_ref,
        enable_qos=enable_qos,
    )
