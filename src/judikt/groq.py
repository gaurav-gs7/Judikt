from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from .secrets import resolve_configured_secret
from .telemetry import Telemetry


MAX_REQUEST_BYTES = 262_144
MAX_RESPONSE_BYTES = 1_048_576
SENSITIVE_KEY = re.compile(r"api[_-]?key|authorization|password|secret|token", re.IGNORECASE)
SENSITIVE_VALUE = re.compile(
    r"sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}",
    re.IGNORECASE,
)


class IncidentAnalyst:
    def __init__(self, api_key: str | None = None, telemetry: Telemetry | None = None) -> None:
        self.api_key = api_key
        if api_key is None:
            self.api_key = resolve_configured_secret(
                direct_env="GROQ_API_KEY",
                aws_secret_env="GROQ_API_KEY_SECRET_ARN",
                vault_path_env="GROQ_API_KEY_VAULT_PATH",
                json_key_env="GROQ_API_KEY_JSON_KEY",
                description="Groq API key",
            )
        self.model = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
        self.telemetry = telemetry or Telemetry()

    def summarize(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        if not self.api_key:
            return {"provider": "local-fallback", "summary": self._fallback(events)}
        safe_events = _bounded_events(events)
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an SRE incident analyst. Summarize the supplied MCP audit events "
                        "in five concise bullets: impact, blocked activity, allowed actions, "
                        "likely cause, and next remediation. Do not invent facts."
                    ),
                },
                {"role": "user", "content": json.dumps(safe_events, sort_keys=True)},
            ],
            "temperature": 0.1,
        }
        with self.telemetry.span(
            "groq.incident_summary",
            "LLM",
            {"llm.provider": "groq", "llm.model_name": self.model},
        ) as span:
            span.set_json_input({"events": safe_events})
            request = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                data=json.dumps(payload).encode(),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("response exceeded size limit")
                body = json.loads(raw)
                summary = body["choices"][0]["message"]["content"]
                if not isinstance(summary, str) or not summary.strip():
                    raise ValueError("response summary is empty")
                result = {
                    "provider": "groq",
                    "model": self.model,
                    "summary": summary,
                }
            except (
                urllib.error.URLError,
                json.JSONDecodeError,
                KeyError,
                IndexError,
                TypeError,
                TimeoutError,
                UnicodeDecodeError,
                ValueError,
            ):
                result = {
                    "provider": "local-fallback",
                    "warning": "Groq request failed; local fallback used",
                    "summary": self._fallback(events),
                }
            span.set_json_output(result)
            return result

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
