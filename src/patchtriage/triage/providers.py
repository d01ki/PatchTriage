"""Provider adapters for optional AI-assisted triage.

The triage engine depends on this small protocol instead of a vendor SDK.
Anthropic remains supported for backwards compatibility, while the
OpenAI-compatible adapter also works with OpenAI and local gateways such as
Ollama when a compatible ``/v1/chat/completions`` endpoint is configured.
"""

from __future__ import annotations

import json
import os
from typing import Any, Protocol

import httpx


ANTHROPIC_DEFAULT_MODEL = "claude-opus-4-8"
ANTHROPIC_DEFAULT_SCREEN_MODEL = "claude-haiku-4-5"
OPENAI_DEFAULT_BASE_URL = "https://api.openai.com/v1"
OLLAMA_DEFAULT_BASE_URL = "http://localhost:11434/v1"

_PROVIDER_ALIASES = {
    "anthropic": "anthropic",
    "claude": "anthropic",
    "openai": "openai-compatible",
    "openai-compatible": "openai-compatible",
    "ollama": "openai-compatible",
}


class AIProvider(Protocol):
    """Minimal inference boundary consumed by the triage engine."""

    name: str

    def complete(self, *, model: str, system_prompt: str, payload: str,
                 tool: dict) -> dict:
        """Return the structured arguments for the requested tool call."""


def normalize_provider_name(name: str) -> str:
    normalized = name.strip().lower().replace("_", "-")
    try:
        return _PROVIDER_ALIASES[normalized]
    except KeyError as exc:
        choices = ", ".join(sorted(_PROVIDER_ALIASES))
        raise ValueError(
            f"Unknown AI provider {name!r}; choose one of: {choices}"
        ) from exc


def resolve_provider_name(name: str | None = None) -> str:
    """Resolve an explicit provider or infer the only configured provider."""
    explicit = name or os.environ.get("PATCHTRIAGE_AI_PROVIDER")
    if explicit:
        return normalize_provider_name(explicit)

    configured: list[str] = []
    if os.environ.get("ANTHROPIC_API_KEY"):
        configured.append("anthropic")
    if (os.environ.get("OPENAI_API_KEY")
            or os.environ.get("PATCHTRIAGE_AI_API_KEY")
            or os.environ.get("PATCHTRIAGE_AI_BASE_URL")):
        configured.append("openai-compatible")
    if len(configured) == 1:
        return configured[0]
    if len(configured) > 1:
        raise RuntimeError(
            "Multiple AI providers are configured; set "
            "PATCHTRIAGE_AI_PROVIDER explicitly"
        )
    raise RuntimeError(
        "No AI provider is configured. Set PATCHTRIAGE_AI_PROVIDER and the "
        "provider API key/base URL, or use the deterministic 'rules' backend."
    )


def resolve_model(provider: str, requested: str | None = None,
                  *, tier: str = "deep") -> str:
    """Resolve a model without hard-coding another vendor's model catalog."""
    if requested:
        return requested
    if tier == "screen":
        configured = os.environ.get("PATCHTRIAGE_AI_SCREEN_MODEL")
    else:
        configured = (os.environ.get("PATCHTRIAGE_AI_DEEP_MODEL")
                      or os.environ.get("PATCHTRIAGE_AI_MODEL"))
    if configured:
        return configured
    if provider == "anthropic":
        return (
            ANTHROPIC_DEFAULT_SCREEN_MODEL
            if tier == "screen"
            else ANTHROPIC_DEFAULT_MODEL
        )
    raise RuntimeError(
        "An AI model is required for an OpenAI-compatible provider. Pass "
        "--model or set PATCHTRIAGE_AI_MODEL; cascade can additionally use "
        "PATCHTRIAGE_AI_SCREEN_MODEL and PATCHTRIAGE_AI_DEEP_MODEL."
    )


def has_ai_configuration() -> bool:
    """Return whether the environment can construct a usable AI backend."""
    try:
        provider = resolve_provider_name()
        resolve_model(provider, tier="deep")
        if provider == "anthropic":
            return bool(os.environ.get("ANTHROPIC_API_KEY"))
        configured_name = os.environ.get(
            "PATCHTRIAGE_AI_PROVIDER", ""
        ).strip().lower()
        base_url = os.environ.get("PATCHTRIAGE_AI_BASE_URL")
        return bool(
            base_url
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("PATCHTRIAGE_AI_API_KEY")
            or configured_name == "ollama"
        )
    except (RuntimeError, ValueError):
        return False


def _anthropic_client():
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            "The Anthropic provider requires its SDK: "
            "pip install 'patchtriage[anthropic]'"
        ) from exc
    try:
        return anthropic.Anthropic()
    except Exception as exc:
        raise RuntimeError(
            "Could not create an Anthropic client. Set ANTHROPIC_API_KEY and "
            "retry."
        ) from exc


class AnthropicProvider:
    """Anthropic Messages API adapter."""

    name = "anthropic"

    def __init__(self, client=None):
        self.client = client or _anthropic_client()

    def complete(self, *, model: str, system_prompt: str, payload: str,
                 tool: dict) -> dict:
        response = self.client.messages.create(
            model=model,
            max_tokens=1024,
            system=[{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": payload}],
            tools=[tool],
            tool_choice={"type": "tool", "name": tool["name"]},
        )
        for block in response.content:
            if block.type == "tool_use" and block.name == tool["name"]:
                return dict(block.input)
        raise RuntimeError("Anthropic returned no triage tool-use block")


class OpenAICompatibleProvider:
    """Adapter for OpenAI-compatible Chat Completions APIs."""

    name = "openai-compatible"

    def __init__(self, *, api_key: str | None = None,
                 base_url: str | None = None, client=None):
        configured_name = (
            os.environ.get("PATCHTRIAGE_AI_PROVIDER", "").strip().lower()
        )
        if base_url:
            resolved_base_url = base_url
        elif os.environ.get("PATCHTRIAGE_AI_BASE_URL"):
            resolved_base_url = os.environ["PATCHTRIAGE_AI_BASE_URL"]
        elif configured_name == "ollama":
            resolved_base_url = OLLAMA_DEFAULT_BASE_URL
        else:
            resolved_base_url = OPENAI_DEFAULT_BASE_URL
        self.base_url = resolved_base_url.rstrip("/")
        self.api_key = (
            api_key
            or os.environ.get("PATCHTRIAGE_AI_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        )
        if self.base_url == OPENAI_DEFAULT_BASE_URL and not self.api_key:
            raise RuntimeError(
                "OPENAI_API_KEY or PATCHTRIAGE_AI_API_KEY is required for "
                "the default OpenAI endpoint"
            )
        self.client = client or httpx.Client(timeout=60)

    def complete(self, *, model: str, system_prompt: str, payload: str,
                 tool: dict) -> dict:
        function = {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "parameters": tool["input_schema"],
            "strict": bool(tool.get("strict", True)),
        }
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": payload},
            ],
            "tools": [{"type": "function", "function": function}],
            "tool_choice": {
                "type": "function",
                "function": {"name": tool["name"]},
            },
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        response = self.client.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=body,
        )
        response.raise_for_status()
        try:
            message = response.json()["choices"][0]["message"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise RuntimeError(
                "OpenAI-compatible endpoint returned an invalid response"
            ) from exc
        for call in message.get("tool_calls") or []:
            function_call = call.get("function") or {}
            if function_call.get("name") != tool["name"]:
                continue
            arguments: Any = function_call.get("arguments")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError as exc:
                    raise RuntimeError(
                        "OpenAI-compatible endpoint returned invalid tool JSON"
                    ) from exc
            if isinstance(arguments, dict):
                return arguments
        raise RuntimeError(
            "OpenAI-compatible endpoint returned no triage tool call"
        )


def make_provider(name: str | None = None, *,
                  base_url: str | None = None) -> AIProvider:
    resolved = resolve_provider_name(name)
    if resolved == "anthropic":
        return AnthropicProvider()
    if name and name.strip().lower() == "ollama" and not base_url:
        base_url = OLLAMA_DEFAULT_BASE_URL
    return OpenAICompatibleProvider(base_url=base_url)
