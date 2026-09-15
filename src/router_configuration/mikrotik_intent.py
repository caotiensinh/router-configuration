"""Backward-compatible imports for the MikroTik vendor intent compiler."""

from .vendors.mikrotik.intent import (
    MikroTikIntentError,
    MikroTikIntentKind,
    MikroTikIntentPlan,
    compile_mikrotik_operator_intent,
    compile_secure_internet_gateway,
    compile_site_to_site_wireguard,
)

__all__ = [
    "MikroTikIntentError",
    "MikroTikIntentKind",
    "MikroTikIntentPlan",
    "compile_mikrotik_operator_intent",
    "compile_secure_internet_gateway",
    "compile_site_to_site_wireguard",
]
