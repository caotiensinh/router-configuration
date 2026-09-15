from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .knowledge import MikroTikOfflineKnowledge


class MikroTikReasoningProviderKind(str, Enum):
    OPENAI = "openai"
    CODEX = "codex"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


@dataclass(frozen=True)
class MikroTikReasoningConfig:
    provider: MikroTikReasoningProviderKind
    model: str
    base_url: str
    api_key_env: str | None = None
    timeout_seconds: float = 90.0


@dataclass(frozen=True)
class MikroTikReasoningRequest:
    task: str
    evidence: Mapping[str, Any]
    constraints: tuple[str, ...] = ()
    knowledge_limit: int = 6


@dataclass(frozen=True)
class MikroTikReasoningResult:
    provider: str
    model: str
    text: str
    knowledge_ids: tuple[str, ...]


class MikroTikReasoningProvider(Protocol):
    config: MikroTikReasoningConfig

    def reason(self, request: MikroTikReasoningRequest) -> MikroTikReasoningResult: ...


_SECRET_TOKENS = (
    "password",
    "passwd",
    "private-key",
    "private_key",
    "preshared-key",
    "preshared_key",
    "token",
    "secret",
    "credential",
    "api_key",
    "apikey",
)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            clean[str(key)] = "<redacted>" if any(t in lowered for t in _SECRET_TOKENS) else _redact(item)
        return clean
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    return value


def build_grounded_prompt(
    request: MikroTikReasoningRequest,
    *,
    knowledge: MikroTikOfflineKnowledge | None = None,
) -> tuple[str, tuple[str, ...]]:
    store = knowledge or MikroTikOfflineKnowledge.bundled()
    hits = store.search(request.task, limit=request.knowledge_limit)
    knowledge_payload = [
        {
            "id": hit.record.id,
            "title": hit.record.title,
            "summary": hit.record.summary,
            "routeros_paths": list(hit.record.routeros_paths),
            "safety_rules": list(hit.record.safety_rules),
            "source_url": hit.record.source_url,
        }
        for hit in hits
    ]
    prompt = {
        "role": "MikroTik RouterOS reasoning assistant",
        "task": request.task,
        "rules": [
            "Use only the supplied MikroTik offline knowledge and observed evidence for RouterOS facts.",
            "Do not invent interface names, addresses, routes, credentials, or capabilities.",
            "Do not output or request plaintext secrets when a secret reference is sufficient.",
            "Treat model output as advisory. Deterministic validators, safety gates, and transaction controls remain authoritative.",
            "If evidence is insufficient, return explicit missing facts instead of guessing.",
            *request.constraints,
        ],
        "knowledge": knowledge_payload,
        "observed_evidence": _redact(request.evidence),
    }
    return json.dumps(prompt, ensure_ascii=False, sort_keys=True), tuple(
        hit.record.id for hit in hits
    )


class _JsonHttpProvider:
    config: MikroTikReasoningConfig

    def _post(self, url: str, payload: Mapping[str, Any], headers: Mapping[str, str]) -> Any:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json", **dict(headers)},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

    def _api_key(self) -> str:
        env = self.config.api_key_env
        if not env:
            raise ValueError("api_key_env is required for this provider")
        value = os.environ.get(env, "")
        if not value:
            raise ValueError(f"required API key environment variable is not set: {env}")
        return value


class OpenAIResponsesProvider(_JsonHttpProvider):
    """OpenAI Responses API provider; CODEX is an alias with a caller-selected model."""

    def __init__(self, config: MikroTikReasoningConfig, *, knowledge: MikroTikOfflineKnowledge | None = None) -> None:
        self.config = config
        self.knowledge = knowledge or MikroTikOfflineKnowledge.bundled()

    def reason(self, request: MikroTikReasoningRequest) -> MikroTikReasoningResult:
        prompt, ids = build_grounded_prompt(request, knowledge=self.knowledge)
        data = self._post(
            self.config.base_url.rstrip("/") + "/v1/responses",
            {"model": self.config.model, "input": prompt},
            {"Authorization": f"Bearer {self._api_key()}"},
        )
        text = str(data.get("output_text") or "")
        if not text:
            fragments: list[str] = []
            for item in data.get("output", []):
                if not isinstance(item, Mapping):
                    continue
                for content in item.get("content", []):
                    if isinstance(content, Mapping) and content.get("type") in {"output_text", "text"}:
                        fragments.append(str(content.get("text") or ""))
            text = "\n".join(fragment for fragment in fragments if fragment)
        return MikroTikReasoningResult(self.config.provider.value, self.config.model, text, ids)


class AnthropicMessagesProvider(_JsonHttpProvider):
    def __init__(self, config: MikroTikReasoningConfig, *, knowledge: MikroTikOfflineKnowledge | None = None) -> None:
        self.config = config
        self.knowledge = knowledge or MikroTikOfflineKnowledge.bundled()

    def reason(self, request: MikroTikReasoningRequest) -> MikroTikReasoningResult:
        prompt, ids = build_grounded_prompt(request, knowledge=self.knowledge)
        data = self._post(
            self.config.base_url.rstrip("/") + "/v1/messages",
            {"model": self.config.model, "max_tokens": 4096, "messages": [{"role": "user", "content": prompt}]},
            {"x-api-key": self._api_key(), "anthropic-version": "2023-06-01"},
        )
        fragments = [
            str(item.get("text") or "")
            for item in data.get("content", [])
            if isinstance(item, Mapping) and item.get("type") == "text"
        ]
        return MikroTikReasoningResult(
            self.config.provider.value, self.config.model, "\n".join(filter(None, fragments)), ids
        )


class OllamaProvider(_JsonHttpProvider):
    """Local/offline reasoning provider for Ollama-compatible installations."""

    def __init__(self, config: MikroTikReasoningConfig, *, knowledge: MikroTikOfflineKnowledge | None = None) -> None:
        self.config = config
        self.knowledge = knowledge or MikroTikOfflineKnowledge.bundled()

    def reason(self, request: MikroTikReasoningRequest) -> MikroTikReasoningResult:
        prompt, ids = build_grounded_prompt(request, knowledge=self.knowledge)
        data = self._post(
            self.config.base_url.rstrip("/") + "/api/chat",
            {
                "model": self.config.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            },
            {},
        )
        message = data.get("message", {})
        text = str(message.get("content") or "") if isinstance(message, Mapping) else ""
        return MikroTikReasoningResult(self.config.provider.value, self.config.model, text, ids)


def create_reasoning_provider(
    config: MikroTikReasoningConfig,
    *,
    knowledge: MikroTikOfflineKnowledge | None = None,
) -> MikroTikReasoningProvider:
    if not config.model.strip():
        raise ValueError("reasoning model must be explicit")
    if config.provider in {MikroTikReasoningProviderKind.OPENAI, MikroTikReasoningProviderKind.CODEX}:
        return OpenAIResponsesProvider(config, knowledge=knowledge)
    if config.provider is MikroTikReasoningProviderKind.ANTHROPIC:
        return AnthropicMessagesProvider(config, knowledge=knowledge)
    if config.provider is MikroTikReasoningProviderKind.OLLAMA:
        return OllamaProvider(config, knowledge=knowledge)
    raise ValueError(f"unsupported MikroTik reasoning provider: {config.provider}")
