from __future__ import annotations

from enum import Enum, IntEnum


class Vendor(str, Enum):
    MIKROTIK = "mikrotik"
    YAMAHA = "yamaha"
    OMADA = "omada"
    QNAP = "qnap"
    UNKNOWN = "unknown"


class RiskLevel(IntEnum):
    READ_ONLY = 0
    PLAN_ONLY = 1
    BOUNDED_CHANGE = 2
    NETWORK_CHANGE = 3
    CRITICAL_CHANGE = 4


class OperationKind(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
