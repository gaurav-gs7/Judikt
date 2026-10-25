from __future__ import annotations

import http.client
import io
import json
import os
import unittest
import urllib.error
from typing import Any
from unittest import mock

from judikt.llm import (
    ANTHROPIC_VERSION,
    MAX_REQUEST_BYTES,
    IncidentAnalyst,
    LLMConfigurationError,
)
from judikt.secrets import SecretBrokerError
from judikt.telemetry import Telemetry

EVENTS = [{"allowed": False, "rule": "blocked_pattern"}, {"allowed": True, "rule": "allow"}]
LLM_ENV_PREFIXES = ("JUDIKT_LLM_", "GROQ_", "OPENAI_", "ANTHROPIC_", "GEMINI_")


class Response(io.BytesIO):
    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def clean_env(**values: str) -> dict[str, str]:
    """The current environment without any LLM settings, plus ``values``."""
    base = {key: item for key, item in os.environ.items() if not key.startswith(LLM_ENV_PREFIXES)}
    return {**base, **values}


class Capture:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = json.dumps(body).encode()
        self.request: Any = None
        self.timeout: float | None = None

    def __call__(self, request: Any, timeout: float) -> Response:
        self.request = request
        self.timeout = timeout
        return Response(self.body)

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.request.data)


def analyst(**kwargs: Any) -> IncidentAnalyst:
    return IncidentAnalyst(telemetry=Telemetry("disabled"), **kwargs)


OPENAI_BODY = {"choices": [{"message": {"content": "- Impact: one blocked call"}}]}


class ProviderSelectionTest(unittest.TestCase):
    def test_no_configuration_uses_the_local_summary(self) -> None:
        with mock.patch.dict(os.environ, clean_env(), clear=True), mock.patch(
            "urllib.request.urlopen"
        ) as urlopen:
            result = analyst().summarize(EVENTS)
        self.assertEqual(result["provider"], "local-fallback")
        self.assertIn("2 MCP tool calls", result["summary"])
        urlopen.assert_not_called()

    def test_unrelated_provider_keys_never_enable_a_provider_on_their_own(self) -> None:
        keys = {"OPENAI_API_KEY": "sk-dev", "ANTHROPIC_API_KEY": "sk-ant-dev", "GEMINI_API_KEY": "AIza-dev"}
        with mock.patch.dict(os.environ, clean_env(**keys), clear=True), mock.patch(
            "urllib.request.urlopen"
        ) as urlopen:
            instance = analyst()
            result = instance.summarize(EVENTS)
        self.assertIsNone(instance.provider)
        self.assertEqual(result["provider"], "local-fallback")
        urlopen.assert_not_called()

    def test_groq_key_alone_keeps_the_original_groq_behaviour(self) -> None:
        capture = Capture(OPENAI_BODY)
        with mock.patch.dict(
            os.environ, clean_env(GROQ_API_KEY="gsk-test", GROQ_MODEL="llama-test"), clear=True
        ), mock.patch("urllib.request.urlopen", side_effect=capture):
            result = analyst().summarize(EVENTS)
        self.assertEqual(result, {"provider": "groq", "model": "llama-test", "summary": "- Impact: one blocked call"})
        self.assertEqual(capture.request.full_url, "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(capture.request.get_header("Authorization"), "Bearer gsk-test")
        self.assertEqual(capture.payload["temperature"], 0.1)
        self.assertEqual(capture.timeout, 15)

    def test_explicit_api_key_without_a_provider_means_groq(self) -> None:
        with mock.patch.dict(os.environ, clean_env(), clear=True):
            self.assertEqual(analyst(api_key="test-key").provider.name, "groq")
            self.assertIsNone(analyst(api_key="").provider)

    def test_disabling_wins_over_a_configured_groq_key(self) -> None:
        with mock.patch.dict(
            os.environ, clean_env(GROQ_API_KEY="gsk-test", JUDIKT_LLM_PROVIDER="none"), clear=True
        ):
            self.assertIsNone(analyst().provider)

    def test_aliases_and_case_are_accepted(self) -> None:
        for raw, expected in (("Claude", "anthropic"), ("chatgpt", "openai"), (" GEMINI ", "gemini")):
            with self.subTest(raw=raw), mock.patch.dict(
                os.environ, clean_env(JUDIKT_LLM_PROVIDER=raw, JUDIKT_LLM_API_KEY="k"), clear=True
            ):
                self.assertEqual(analyst().provider.name, expected)

    def test_unknown_provider_is_a_configuration_error(self) -> None:
        with mock.patch.dict(os.environ, clean_env(JUDIKT_LLM_PROVIDER="mistral"), clear=True):
            with self.assertRaisesRegex(LLMConfigurationError, "openai-compatible, none"):
                analyst()

    def test_an_explicit_provider_without_a_key_fails_at_startup(self) -> None:
        with mock.patch.dict(os.environ, clean_env(JUDIKT_LLM_PROVIDER="anthropic"), clear=True):
            with self.assertRaisesRegex(SecretBrokerError, "Anthropic API key .*ANTHROPIC_API_KEY"):
                analyst()

    def test_generic_key_takes_precedence_over_the_provider_key(self) -> None:
        with mock.patch.dict(
            os.environ,
            clean_env(JUDIKT_LLM_PROVIDER="openai", OPENAI_API_KEY="native", JUDIKT_LLM_API_KEY="generic"),
            clear=True,
        ):
            self.assertEqual(analyst().api_key, "generic")

    def test_provider_keys_can_come_from_the_secret_broker(self) -> None:
        with mock.patch.dict(
            os.environ,
            clean_env(JUDIKT_LLM_PROVIDER="anthropic", ANTHROPIC_API_KEY_SECRET_ARN="arn:secret"),
            clear=True,
        ), mock.patch("judikt.llm.resolve_configured_secret", return_value="brokered") as resolve:
            instance = analyst()
        self.assertEqual(instance.api_key, "brokered")
        kwargs = resolve.call_args.kwargs
        self.assertEqual(kwargs["direct_env"], "ANTHROPIC_API_KEY")
        self.assertEqual(kwargs["aws_secret_env"], "ANTHROPIC_API_KEY_SECRET_ARN")
        self.assertTrue(kwargs["required"])

    def test_model_and_timeout_validation(self) -> None:
        cases = [
            ({"JUDIKT_LLM_PROVIDER": "openai", "JUDIKT_LLM_MODEL": "bad model"}, "unsupported characters"),
            ({"JUDIKT_LLM_PROVIDER": "gemini", "JUDIKT_LLM_MODEL": "a/b"}, "must not contain '/'"),
            ({"JUDIKT_LLM_TIMEOUT_SECONDS": "soon"}, "must be a number"),
            ({"JUDIKT_LLM_TIMEOUT_SECONDS": "0"}, "greater than 0"),
            ({"JUDIKT_LLM_TIMEOUT_SECONDS": "301"}, "at most 300"),
        ]
        for values, message in cases:
            with self.subTest(values=values), mock.patch.dict(
                os.environ, clean_env(JUDIKT_LLM_API_KEY="k", **values), clear=True
            ):
                with self.assertRaisesRegex(LLMConfigurationError, message):
                    analyst()


class ProviderRequestTest(unittest.TestCase):
    def run_provider(self, provider: str, body: dict[str, Any], **env: str) -> tuple[dict[str, Any], Capture]:
        capture = Capture(body)
        with mock.patch.dict(
            os.environ, clean_env(JUDIKT_LLM_PROVIDER=provider, **env), clear=True
        ), mock.patch("urllib.request.urlopen", side_effect=capture):
            result = analyst().summarize(EVENTS)
        return result, capture

    def test_openai_uses_chat_completions_without_temperature(self) -> None:
        result, capture = self.run_provider("openai", OPENAI_BODY, OPENAI_API_KEY="sk-test")
        self.assertEqual(result["provider"], "openai")
        self.assertEqual(result["model"], "gpt-6-luna")
        self.assertEqual(capture.request.full_url, "https://api.openai.com/v1/chat/completions")
        self.assertEqual(capture.request.get_header("Authorization"), "Bearer sk-test")
        self.assertNotIn("temperature", capture.payload)
        self.assertEqual(capture.payload["messages"][0]["role"], "system")

    def test_anthropic_uses_the_messages_api_and_reads_only_text_blocks(self) -> None:
        body = {
            "content": [
                {"type": "thinking", "thinking": "private reasoning"},
                {"type": "text", "text": "- Impact: "},
                {"type": "text", "text": "one blocked call"},
            ],
            "stop_reason": "end_turn",
        }
        result, capture = self.run_provider("anthropic", body, ANTHROPIC_API_KEY="sk-ant-test")
        self.assertEqual(result["summary"], "- Impact: one blocked call")
        self.assertEqual(result["model"], "claude-haiku-5-5")
        self.assertEqual(capture.request.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(capture.request.get_header("X-api-key"), "sk-ant-test")
        self.assertEqual(capture.request.get_header("Anthropic-version"), ANTHROPIC_VERSION)
        self.assertIsNone(capture.request.get_header("Authorization"))
        payload = capture.payload
        self.assertIn("SRE incident analyst", payload["system"])
        self.assertEqual(payload["messages"][0]["role"], "user")
        self.assertGreater(payload["max_tokens"], 0)
        for sampling in ("temperature", "top_p", "top_k"):
            self.assertNotIn(sampling, payload)

    def test_gemini_keeps_the_key_out_of_the_url_and_skips_thought_parts(self) -> None:
        body = {
            "candidates": [
                {"content": {"parts": [{"text": "thinking...", "thought": True}, {"text": "- Impact: one"}]}}
            ]
        }
        result, capture = self.run_provider(
            "gemini", body, GEMINI_API_KEY="AIza-test", JUDIKT_LLM_MODEL="models/gemini-test"
        )
        self.assertEqual(result["summary"], "- Impact: one")
        self.assertEqual(
            capture.request.full_url,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-test:generateContent",
        )
        self.assertNotIn("AIza", capture.request.full_url)
        self.assertEqual(capture.request.get_header("X-goog-api-key"), "AIza-test")
        payload = capture.payload
        self.assertIn("SRE incident analyst", payload["systemInstruction"]["parts"][0]["text"])
        self.assertNotIn("generationConfig", payload)

    def test_openai_compatible_endpoint_on_loopback_needs_no_key(self) -> None:
        result, capture = self.run_provider(
            "openai-compatible",
            OPENAI_BODY,
            JUDIKT_LLM_BASE_URL="http://localhost:11434/v1/",
            JUDIKT_LLM_MODEL="llama3.1:8b",
            JUDIKT_LLM_TIMEOUT_SECONDS="90",
        )
        self.assertEqual(result["provider"], "openai-compatible")
        self.assertEqual(capture.request.full_url, "http://localhost:11434/v1/chat/completions")
        self.assertIsNone(capture.request.get_header("Authorization"))
        self.assertEqual(capture.timeout, 90)

    def test_openai_compatible_endpoint_validation(self) -> None:
        cases = [
            ({}, "requires JUDIKT_LLM_BASE_URL"),
            ({"JUDIKT_LLM_BASE_URL": "https://llm.internal/v1"}, "requires JUDIKT_LLM_MODEL"),
            ({"JUDIKT_LLM_BASE_URL": "http://10.0.0.5/v1", "JUDIKT_LLM_MODEL": "m"}, "requires HTTPS"),
            ({"JUDIKT_LLM_BASE_URL": "https://u:p@llm.internal/v1", "JUDIKT_LLM_MODEL": "m"}, "credentials"),
            ({"JUDIKT_LLM_BASE_URL": "https://llm.internal/v1?key=x", "JUDIKT_LLM_MODEL": "m"}, "query"),
            ({"JUDIKT_LLM_BASE_URL": "ftp://llm.internal", "JUDIKT_LLM_MODEL": "m"}, "absolute HTTP"),
        ]
        for values, message in cases:
            with self.subTest(values=values), mock.patch.dict(
                os.environ, clean_env(JUDIKT_LLM_PROVIDER="openai-compatible", **values), clear=True
            ):
                with self.assertRaisesRegex(LLMConfigurationError, message):
                    analyst()
        with mock.patch.dict(
            os.environ,
            clean_env(
                JUDIKT_LLM_PROVIDER="openai-compatible",
                JUDIKT_LLM_BASE_URL="http://10.0.0.5/v1",
                JUDIKT_LLM_MODEL="m",
                JUDIKT_LLM_ALLOW_INSECURE_HTTP="true",
            ),
            clear=True,
        ):
            self.assertEqual(analyst().endpoint, "http://10.0.0.5/v1/chat/completions")

    def test_requests_are_redacted_and_bounded_for_every_provider(self) -> None:
        events = [
            {
                "allowed": False,
                "rule": "blocked_pattern",
                "api_key": "sk-private-value",
                "message": "Bearer private-provider-token gsk_privategroqkey AIzaSyPrivateGoogleKey123456",
                "diagnostic": "upstream stderr must never reach a model",
                "large": "x" * 20_000,
            }
            for _ in range(30)
        ]
        bodies = {
            "openai": (OPENAI_BODY, {"OPENAI_API_KEY": "k"}),
            "anthropic": ({"content": [{"type": "text", "text": "ok"}]}, {"ANTHROPIC_API_KEY": "k"}),
            "gemini": ({"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}, {"GEMINI_API_KEY": "k"}),
        }
        for provider, (body, env) in bodies.items():
            capture = Capture(body)
            with self.subTest(provider=provider), mock.patch.dict(
                os.environ, clean_env(JUDIKT_LLM_PROVIDER=provider, **env), clear=True
            ), mock.patch("urllib.request.urlopen", side_effect=capture):
                analyst().summarize(events)
                sent = capture.request.data.decode()
                self.assertLessEqual(len(sent.encode()), MAX_REQUEST_BYTES + 8192)
                for secret in (
                    "sk-private-value",
                    "private-provider-token",
                    "gsk_privategroqkey",
                    "AIzaSyPrivateGoogleKey",
                    "upstream stderr",
                ):
                    self.assertNotIn(secret, sent)
                self.assertIn("[REDACTED]", sent)

    def test_provider_failures_fall_back_without_leaking_details(self) -> None:
        outcomes: list[object] = [
            urllib.error.URLError("private network detail"),
            http.client.RemoteDisconnected("private network detail"),
            TimeoutError("private network detail"),
            Response(b"not-json"),
            Response(b"{}"),
            Response(b"x" * 1_048_577),
            Response(json.dumps({"choices": [{"message": {"content": ""}}]}).encode()),
        ]
        for outcome in outcomes:
            with self.subTest(outcome=type(outcome).__name__), mock.patch.dict(
                os.environ, clean_env(JUDIKT_LLM_PROVIDER="chatgpt", OPENAI_API_KEY="k"), clear=True
            ), mock.patch(
                "urllib.request.urlopen",
                side_effect=outcome if isinstance(outcome, Exception) else None,
                return_value=None if isinstance(outcome, Exception) else outcome,
            ):
                result = analyst().summarize(EVENTS)
            self.assertEqual(result["provider"], "local-fallback")
            self.assertEqual(result["warning"], "OpenAI request failed; local fallback used")
            self.assertNotIn("private network detail", json.dumps(result))

    def test_empty_anthropic_and_gemini_responses_fall_back(self) -> None:
        cases = {
            "anthropic": ({"content": [{"type": "thinking", "thinking": "x"}]}, "ANTHROPIC_API_KEY"),
            "gemini": ({"candidates": [{"content": {"parts": [{"text": "x", "thought": True}]}}]}, "GEMINI_API_KEY"),
        }
        for provider, (body, key) in cases.items():
            with self.subTest(provider=provider):
                result, _ = self.run_provider(provider, body, **{key: "k"})
                self.assertEqual(result["provider"], "local-fallback")


class CompatibilityTest(unittest.TestCase):
    def test_the_groq_module_still_exports_the_analyst(self) -> None:
        from judikt import groq, llm

        self.assertIs(groq.IncidentAnalyst, llm.IncidentAnalyst)
        self.assertIs(groq._bounded_events, llm._bounded_events)


if __name__ == "__main__":
    unittest.main()
