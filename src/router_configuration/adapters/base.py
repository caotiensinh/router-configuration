from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from router_configuration.m02_state_engine import ChangePlan
from router_configuration.types import Vendor


@dataclass(frozen=True)
class AdapterCapability:
    vendor: Vendor
    feature: str
    supported: bool
    reason: str = ""


@dataclass(frozen=True)
class AdapterPreflight:
    ready: bool
    reasons: tuple[str, ...] = ()


class RouterAdapter(Protocol):
    vendor: Vendor

    def preflight(self, plan: ChangePlan) -> AdapterPreflight:
        ...

    def render_dry_run(self, plan: ChangePlan) -> tuple[str, ...]:
        ...
