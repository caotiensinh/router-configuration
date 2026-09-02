from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


_SECRET_KEYS = (
    "password",
    "passwd",
    "private_key",
    "private-key",
    "preshared_key",
    "pre_shared_key",
    "psk",
    "token",
    "secret",
)
_ALLOWED_SECRET_SCHEMES = ("env://", "vault://", "keyring://")


@dataclass(frozen=True)
class CompilerFinding:
    path: str
    message: str


@dataclass(frozen=True)
class CompiledField:
    path: str
    value: Any
    secret_reference: bool = False


@dataclass(frozen=True)
class CompiledIntent:
    fields: tuple[CompiledField, ...]


class ConfigCompiler:
    """Validates and flattens intent without resolving secret values."""

    def validate(self, intent: Mapping[str, Any]) -> tuple[CompilerFinding, ...]:
        findings: list[CompilerFinding] = []
        self._validate_value(intent, "", findings)
        return tuple(findings)

    def compile(self, intent: Mapping[str, Any]) -> CompiledIntent:
        findings = self.validate(intent)
        if findings:
            joined = "; ".join(f"{item.path}: {item.message}" for item in findings)
            raise ValueError(f"intent validation failed: {joined}")

        fields: list[CompiledField] = []
        self._flatten(intent, "", fields)
        fields.sort(key=lambda item: item.path)
        return CompiledIntent(tuple(fields))

    def _validate_value(
        self,
        value: Any,
        path: str,
        findings: list[CompilerFinding],
    ) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                child_path = self._child(path, key)
                if self._looks_secret(str(key)):
                    if not isinstance(child, str) or not child.startswith(_ALLOWED_SECRET_SCHEMES):
                        findings.append(
                            CompilerFinding(
                                child_path,
                                "secret-like fields must use env://, vault://, or keyring:// references",
                            )
                        )
                self._validate_value(child, child_path, findings)
            return

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for index, child in enumerate(value):
                self._validate_value(child, f"{path}[{index}]", findings)

    def _flatten(
        self,
        value: Any,
        path: str,
        fields: list[CompiledField],
    ) -> None:
        if isinstance(value, Mapping):
            for key in sorted(value, key=str):
                self._flatten(value[key], self._child(path, key), fields)
            return

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for index, child in enumerate(value):
                self._flatten(child, f"{path}[{index}]", fields)
            return

        secret_reference = isinstance(value, str) and value.startswith(_ALLOWED_SECRET_SCHEMES)
        fields.append(CompiledField(path or "$", value, secret_reference))

    @staticmethod
    def _looks_secret(key: str) -> bool:
        lowered = key.strip().lower()
        return any(token in lowered for token in _SECRET_KEYS)

    @staticmethod
    def _child(path: str, key: Any) -> str:
        text = str(key)
        return text if not path else f"{path}.{text}"
