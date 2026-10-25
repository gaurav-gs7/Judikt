"""Optional LLM incident summaries across hosted and self-hosted providers.

The model only summarizes audit events for an operator. It never takes part
in an allow or deny decision, and every failure falls back to a deterministic
local summary.

Providers are opt-in. ``JUDIKT_LLM_PROVIDER`` selects one of ``groq``,
``openai``, ``anthropic``, ``gemini`` or ``openai-compatible``. When it is
unset, Judikt keeps its original behaviour and uses Groq only if a Groq key is
configured; a developer's unrelated ``OPENAI_API_KEY`` or ``ANTHROPIC_API_KEY``
never starts sending audit data anywhere on its own.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .secrets import resolve_configured_secret
from .telemetry import Telemetry

MAX_REQUEST_BYTES = 262_144
MAX_RESPONSE_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_TIMEOUT_SECONDS = 300.0
MAX_OUTPUT_TOKENS = 4096
ANTHROPIC_VERSION = "2026-10-21"
SENSITIVE_KEY = re.compile(r"api[_-]?key|authorization|password|secret|token", re.IGNORECASE)
SENSITIVE_VALUE = re.compile(
    r"sk-[A-Za-z0-9_-]{8,}|gsk_[A-Za-z0-9]{8,}|AIza[0-9A-Za-z_-]{20,}|ghp_[A-Za-z0-9]{8,}"
    r"|Bearer\s+[A-Za-z0-9._~+/=-]{8,}",
    re.IGNORECASE,
)
MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}$")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
SYSTEM_PROMPT = (
    "You are an SRE incident analyst. Summarize the supplied MCP audit events "
    "in five concise bullets: impact, blocked activity, allowed actions, "
    "likely cause, and next remediation. Do not invent facts."
)


class LLMConfigurationError(RuntimeError):
    """The operator's LLM summary configuration cannot be used."""


@dataclass(frozen=True)
class Provider:
    name: str
    label: str
    wire: str  # "openai" (chat completions) | "anthropic" | "gemini"
    endpoint: str
    key_env: str
    default_model: str
    model_env: str = ""
    temperature: float | None = None
    key_required: bool = True


PROVIDERS: dict[str, Provider] = {
    "groq": Provider(
        name="groq",
        label="Groq",
        wire="openai",
        endpoint="https://api.groq.com/openai/v1/chat/completions",
        key_env="GROQ_API_KEY",
        default_model="openai/gpt-oss-20b",
        model_env="GROQ_MODEL",
        temperature=0.1,
    ),
    "openai": Provider(
        name="openai",
        label="OpenAI",
        wire="openai",
        endpoint="https://api.openai.com/v1/chat/completions",
        key_env="OPENAI_API_KEY",
        default_model="gpt-6-luna",
    ),
    "anthropic": Provider(
        name="anthropic",
        label="Anthropic",
        wire="anthropic",
        endpoint="https://api.anthropic.com/v1/messages",
        key_env="ANTHROPIC_API_KEY",
        default_model="claude-haiku-5-5",
    ),
    "gemini": Provider(
        name="gemini",
        label="Gemini",
        wire="gemini",
        endpoint="https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        key_env="GEMINI_API_KEY",
        default_model="gemini-3.5-flash-lite",
    ),
    "openai-compatible": Provider(
        name="openai-compatible",
        label="OpenAI-compatible endpoint",
        wire="openai",
        endpoint="",
        key_env="",
        default_model="",
        key_required=False,
    ),
}
ALIASES = {"claude": "anthropic", "chatgpt": "openai", "google": "gemini"}
DISABLED = {"none", "off", "local", "disabled"}


def _key_sources(base: str) -> dict[str, str]:
    return {
        "direct_env": base,
        "aws_secret_env": f"{base}_SECRET_ARN",
        "vault_path_env": f"{base}_VAULT_PATH",
        "json_key_env": f"{base}_JSON_KEY",
    }


def _configured(base: str) -> bool:
    sources = _key_sources(base)
    return any(
        os.getenv(sources[name], "").strip()
        for name in ("direct_env", "aws_secret_env", "vault_path_env")
    )


def _choose_provider(explicit: str | None, api_key: str | None) -> tuple[Provider | None, bool]:
    """Return the provider and whether the operator selected it explicitly."""
    raw = explicit if explicit is not None else os.getenv("JUDIKT_LLM_PROVIDER", "")
    name = raw.strip().lower()
    if name in DISABLED:
        return None, True
    if name:
        name = ALIASES.get(name, name)
        if name not in PROVIDERS:
            choices = ", ".join([*PROVIDERS, "none"])
            raise LLMConfigurationError(
                f"JUDIKT_LLM_PROVIDER={raw.strip()!r} is not supported; choose one of: {choices}"
            )
        return PROVIDERS[name], True
    # Backward compatibility: Groq was the original, and only, provider.
    if (api_key is not None and api_key.strip()) or (api_key is None and _configured("GROQ_API_KEY")):
        return PROVIDERS["groq"], False
    return None, False


def _base_url_endpoint(raw: str) -> str:
    parsed = urllib.parse.urlparse(raw.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LLMConfigurationError("JUDIKT_LLM_BASE_URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise LLMConfigurationError("JUDIKT_LLM_BASE_URL must not contain credentials, query, or fragment")
    allow_http = os.getenv("JUDIKT_LLM_ALLOW_INSECURE_HTTP", "").strip().lower() in {"1", "true", "yes"}
    if parsed.scheme == "http" and parsed.hostname not in LOOPBACK_HOSTS and not allow_http:
        raise LLMConfigurationError("non-loopback JUDIKT_LLM_BASE_URL requires HTTPS")
    base = raw.strip().rstrip("/")
    return base if base.endswith("/chat/completions") else f"{base}/chat/completions"


def _timeout(explicit: float | None) -> float:
    if explicit is not None:
        value = explicit
    else:
        raw = os.getenv("JUDIKT_LLM_TIMEOUT_SECONDS", "").strip()
        if not raw:
            return DEFAULT_TIMEOUT_SECONDS
        try:
            value = float(raw)
        except ValueError:
            raise LLMConfigurationError("JUDIKT_LLM_TIMEOUT_SECONDS must be a number") from None
    if not 0 < value <= MAX_TIMEOUT_SECONDS:
        raise LLMConfigurationError(
            f"JUDIKT_LLM_TIMEOUT_SECONDS must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g}"
        )
    return value


class IncidentAnalyst:
    def __init__(
        self,
        api_key: str | None = None,
        telemetry: Telemetry | None = None,
        *,
        provider: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.telemetry = telemetry or Telemetry()
        self.timeout = _timeout(timeout)
        self.provider, explicit = _choose_provider(provider, api_key)
        self.model = ""
        self.endpoint = ""
        self.api_key = ""
        if self.provider is None:
            return

        chosen = self.provider
        raw_base = base_url if base_url is not None else os.getenv("JUDIKT_LLM_BASE_URL", "")
        if chosen.name == "openai-compatible" and not raw_base.strip():
            raise LLMConfigurationError("JUDIKT_LLM_PROVIDER=openai-compatible requires JUDIKT_LLM_BASE_URL")
        configured_model = model or os.getenv("JUDIKT_LLM_MODEL", "").strip()
        if not configured_model and chosen.model_env:
            configured_model = os.getenv(chosen.model_env, "").strip()
        self.model = configured_model or chosen.default_model
        if not self.model:
            raise LLMConfigurationError(f"JUDIKT_LLM_PROVIDER={chosen.name} requires JUDIKT_LLM_MODEL")
        if not MODEL_NAME.fullmatch(self.model):
            raise LLMConfigurationError("JUDIKT_LLM_MODEL contains unsupported characters")

        if chosen.name == "openai-compatible":
            self.endpoint = _base_url_endpoint(raw_base)
        elif chosen.wire == "gemini":
            model_id = self.model.removeprefix("models/")
            if "/" in model_id:
                raise LLMConfigurationError("Gemini model names must not contain '/'")
            self.endpoint = chosen.endpoint.format(model=urllib.parse.quote(model_id, safe=""))
        else:
            self.endpoint = chosen.endpoint

        if api_key is not None:
            self.api_key = api_key
            return
        generic = "JUDIKT_LLM_API_KEY"
        base = generic if _configured(generic) or not chosen.key_env else chosen.key_env
        names = f"{generic} or {chosen.key_env}" if chosen.key_env else generic
        self.api_key = resolve_configured_secret(
            **_key_sources(base),
            required=explicit and chosen.key_required,
            description=f"{chosen.label} API key ({names})",
        )

    def summarize(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        chosen = self.provider
        if chosen is None or (chosen.key_required and not self.api_key):
            return {"provider": "local-fallback", "summary": self._fallback(events)}
        safe_events = _bounded_events(events)
        with self.telemetry.span(
            "llm.incident_summary",
            "LLM",
            {"llm.provider": chosen.name, "llm.model_name": self.model},
        ) as span:
            span.set_json_input({"events": safe_events})
            try:
                summary = self._request(chosen, json.dumps(safe_events, sort_keys=True))
                result = {"provider": chosen.name, "model": self.model, "summary": summary}
            except (
                OSError,
                http.client.HTTPException,
                json.JSONDecodeError,
                KeyError,
                IndexError,
                TypeError,
                UnicodeDecodeError,
                ValueError,
            ):
                result = {
                    "provider": "local-fallback",
                    "warning": f"{chosen.label} request failed; local fallback used",
                    "summary": self._fallback(events),
                }
            span.set_json_output(result)
            return result

    def _request(self, chosen: Provider, events_json: str) -> str:
        headers = {"Content-Type": "application/json"}
        payload: dict[str, Any]
        if chosen.wire == "anthropic":
            headers["x-api-key"] = self.api_key
            headers["anthropic-version"] = ANTHROPIC_VERSION
            payload = {
                "model": self.model,
                "max_tokens": MAX_OUTPUT_TOKENS,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": events_json}],
            }
        elif chosen.wire == "gemini":
            headers["x-goog-api-key"] = self.api_key
            payload = {
                "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": [{"role": "user", "parts": [{"text": events_json}]}],
            }
        else:
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": events_json},
                ],
            }
            if chosen.temperature is not None:
                payload["temperature"] = chosen.temperature

        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("response exceeded size limit")
        body = json.loads(raw)

        if chosen.wire == "anthropic":
            summary = "".join(
                block["text"] for block in body["content"] if block.get("type") == "text"
            )
        elif chosen.wire == "gemini":
            parts = body["candidates"][0]["content"]["parts"]
            summary = "".join(part["text"] for part in parts if "text" in part and not part.get("thought"))
        else:
            summary = body["choices"][0]["message"]["content"]
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError("response summary is empty")
        return summary

    @staticmethod
    def _fallback(events: list[dict[str, Any]]) -> str:
        blocked = [event for event in events if event.get("allowed") is False]
        allowed = [event for event in events if event.get("allowed") is True]
        rules = sorted(
            {str(event.get("rule", "unknown")) for event in blocked}
        )
        return "\n".join(
            [
                f"- Impact: reviewed {len(events)} MCP tool calls; {len(blocked)} were blocked.",
                f"- Blocked activity: rules triggered: {', '.join(rules) if rules else 'none'}.",
                f"- Allowed actions: {len(allowed)} calls completed through the gateway.",
                "- Likely cause: inspect the correlated audit events before assigning root cause.",
                "- Next remediation: keep risky tools approval-gated and validate kill-switch drills.",
            ]
        )


def _bounded_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Operator diagnostics can hold upstream-controlled text (stderr, upstream
    # error messages). They are never sent to a model.
    safe_events = [
        _redact_for_llm({key: item for key, item in event.items() if key != "diagnostic"})
        for event in events[:30]
    ]
    event_budget = MAX_REQUEST_BYTES - 4096
    while safe_events and len(json.dumps(safe_events, sort_keys=True).encode()) > event_budget:
        safe_events.pop()
    return safe_events


def _redact_for_llm(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SENSITIVE_KEY.search(str(key)) else _redact_for_llm(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_for_llm(item) for item in value]
    if isinstance(value, str):
        return SENSITIVE_VALUE.sub("[REDACTED]", value)
    return value
