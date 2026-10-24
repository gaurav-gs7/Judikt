from __future__ import annotations

import json
import os
from contextlib import contextmanager
from typing import Any, Iterator

from . import __version__


class TraceSpan:
    """Small adapter that keeps OpenTelemetry optional for the default demo."""

    def __init__(self, span: Any = None) -> None:
        self._span = span

    def set_attribute(self, name: str, value: Any) -> None:
        if self._span is not None and value is not None:
            self._span.set_attribute(name, value)

    def set_json_input(self, value: Any) -> None:
        self.set_attribute("input.value", _json(value))
        self.set_attribute("input.mime_type", "application/json")

    def set_json_output(self, value: Any) -> None:
        self.set_attribute("output.value", _json(value))
        self.set_attribute("output.mime_type", "application/json")

    def set_policy(self, *, allowed: bool, rule: str, reason: str) -> None:
        self.set_attribute("judikt.policy.allowed", allowed)
        self.set_attribute("judikt.policy.rule", rule)
        self.set_attribute("judikt.policy.reason", reason)

    def record_exception(self, exc: Exception) -> None:
        if self._span is not None:
            self._span.set_attribute("judikt.error.type", exc.__class__.__name__)
            self._span.set_status(self._status_code("ERROR"))

    def set_ok(self) -> None:
        if self._span is not None:
            self._span.set_status(self._status_code("OK"))

    @staticmethod
    def _status_code(name: str) -> Any:
        from opentelemetry.trace import StatusCode

        return getattr(StatusCode, name)


class Telemetry:
    """Optional OpenInference-compatible tracing for Judikt."""

    def __init__(self, mode: str | None = None) -> None:
        self.mode = (mode or os.getenv("JUDIKT_TELEMETRY", "disabled")).lower()
        self._tracer: Any = None
        if self.mode in {"", "0", "disabled", "false", "off"}:
            self.mode = "disabled"
            return
        if self.mode not in {"console", "otlp"}:
            raise ValueError("JUDIKT_TELEMETRY must be disabled, console, or otlp")
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
        except ImportError as exc:
            raise RuntimeError(
                "OpenInference tracing requires the optional observability dependencies. "
                "Install them with: python3 -m pip install -e '.[observability]'"
            ) from exc

        provider = TracerProvider(resource=Resource.create({"service.name": "judikt"}))
        if self.mode == "console":
            exporter = ConsoleSpanExporter()
        else:
            exporter = OTLPSpanExporter(
                endpoint=os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:6006/v1/traces")
            )
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        self._tracer = provider.get_tracer("judikt", __version__)

    def status(self) -> dict[str, Any]:
        result = {"enabled": self._tracer is not None, "mode": self.mode}
        if self.mode == "otlp":
            result["endpoint"] = os.getenv(
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:6006/v1/traces"
            )
        return result

    @contextmanager
    def span(self, name: str, kind: str, attributes: dict[str, Any] | None = None) -> Iterator[TraceSpan]:
        if self._tracer is None:
            yield TraceSpan()
            return
        from openinference.semconv.trace import OpenInferenceSpanKindValues, SpanAttributes

        openinference_kind = getattr(OpenInferenceSpanKindValues, kind).value
        span_attributes = {
            SpanAttributes.OPENINFERENCE_SPAN_KIND: openinference_kind,
            **(attributes or {}),
        }
        with self._tracer.start_as_current_span(
            name,
            attributes=span_attributes,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            wrapped = TraceSpan(span)
            try:
                yield wrapped
            except Exception as exc:
                wrapped.record_exception(exc)
                raise
            else:
                wrapped.set_ok()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
