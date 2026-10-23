from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .content_guard import ContentGuard


PAPER_ID = "arXiv:2508.10991"
DEFAULT_PAYLOAD_FIELDS = (
    "payload",
    "mcp_payload",
    "content",
    "text",
    "prompt",
    "description",
    "input",
)
DEFAULT_LABEL_FIELDS = ("label", "is_attack", "malicious", "unsafe", "target")
DEFAULT_CATEGORY_FIELDS = ("category", "attack_type", "type", "scenario")
DEFAULT_SURFACE_FIELDS = ("surface", "channel", "mcp_surface")
POSITIVE_LABELS = {"1", "true", "attack", "malicious", "unsafe", "positive", "blocked"}
NEGATIVE_LABELS = {"0", "false", "benign", "safe", "negative", "allowed"}


@dataclass(frozen=True)
class AttackSample:
    payload: Any
    expected_attack: bool
    category: str
    surface: str
    sample_hash: str


@dataclass(frozen=True)
class Detection:
    predicted_attack: bool
    rules: tuple[str, ...]
    latency_ms: float


@dataclass(frozen=True)
class ScoredSample:
    expected_attack: bool
    predicted_attack: bool
    category: str
    surface: str


class AttackBenchError(ValueError):
    pass


class AttackBenchEvaluator:
    """Runs production content controls against labeled MCP security samples."""

    def __init__(self, policy_path: Path) -> None:
        self.policy_path = policy_path
        self.config = json.loads(policy_path.read_text())
        self.content_guard = ContentGuard.from_policy(self.config)
        self._blocked = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.config.get("blocked_argument_patterns", [])
        ]
        self._forbidden_keys = {
            str(key).lower() for key in self.config.get("forbidden_argument_keys", [])
        }

    def detect(self, payload: Any, surface: str) -> Detection:
        started = time.perf_counter_ns()
        content_surface = {
            "arguments": "tool_argument",
            "tool_argument": "tool_argument",
            "tool_description": "tool_description",
            "description": "tool_description",
        }.get(surface, "tool_result")
        inspection = self.content_guard.inspect(payload, surface=content_surface)
        rules = {finding.rule for finding in inspection.findings}
        predicted_attack = inspection.action in {"redact", "block"}
        canonical = _canonical(payload)

        if surface in {"arguments", "auto", "unknown"}:
            if any(pattern.search(canonical) for pattern in self._blocked):
                rules.add("blocked_argument_pattern")
                predicted_attack = True
            if _contains_forbidden_key(payload, self._forbidden_keys):
                rules.add("caller_credential_passthrough")
                predicted_attack = True

        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        return Detection(predicted_attack, tuple(sorted(rules)), elapsed_ms)


def run_attackbench(
    dataset_path: Path,
    policy_path: Path,
    *,
    dataset_id: str = "",
    payload_field: str = "",
    label_field: str = "",
    category_field: str = "",
    surface_field: str = "",
    expected_samples: int | None = None,
) -> dict[str, Any]:
    if expected_samples is not None and expected_samples <= 0:
        raise AttackBenchError("expected_samples must be a positive integer")
    evaluator = AttackBenchEvaluator(policy_path)
    scored: list[ScoredSample] = []
    latencies: list[float] = []
    misses: list[dict[str, Any]] = []
    for record in _read_records(dataset_path):
        sample = _to_sample(
            record,
            payload_field=payload_field,
            label_field=label_field,
            category_field=category_field,
            surface_field=surface_field,
        )
        detection = evaluator.detect(sample.payload, sample.surface)
        scored.append(
            ScoredSample(
                expected_attack=sample.expected_attack,
                predicted_attack=detection.predicted_attack,
                category=sample.category,
                surface=sample.surface,
            )
        )
        latencies.append(detection.latency_ms)
        if sample.expected_attack != detection.predicted_attack:
            misses.append(
                {
                    "sample_hash": sample.sample_hash,
                    "category": sample.category,
                    "surface": sample.surface,
                    "expected_attack": sample.expected_attack,
                    "predicted_attack": detection.predicted_attack,
                    "matched_rules": list(detection.rules),
                }
            )
    if expected_samples is not None and len(scored) != expected_samples:
        raise AttackBenchError(
            f"expected {expected_samples} records but loaded {len(scored)} from {dataset_path}"
        )
    if not scored:
        raise AttackBenchError(f"dataset is empty: {dataset_path}")

    overall = _metrics(scored)
    return {
        "schema_version": 1,
        "benchmark": {
            "name": "MCP-AttackBench-compatible evaluation",
            "paper": PAPER_ID,
            "dataset_id": dataset_id or dataset_path.stem,
            "input_sha256": _file_sha256(dataset_path),
            "policy_sha256": _file_sha256(policy_path),
            "sample_count": len(scored),
            "claim_scope": "operator-supplied dataset",
        },
        "field_mapping": {
            "payload": payload_field or "auto",
            "label": label_field or "auto",
            "category": category_field or "auto",
            "surface": surface_field or "auto",
        },
        "overall": overall,
        "latency_ms": {
            "mean": _rounded(sum(latencies) / len(latencies)),
            "p50": _rounded(_percentile(latencies, 0.50)),
            "p95": _rounded(_percentile(latencies, 0.95)),
            "p99": _rounded(_percentile(latencies, 0.99)),
            "max": _rounded(max(latencies)),
        },
        "throughput_samples_per_second": _rounded(
            len(scored) / max(sum(latencies) / 1000, 0.000001)
        ),
        "by_category": _grouped_metrics(scored, lambda sample: sample.category),
        "by_surface": _grouped_metrics(scored, lambda sample: sample.surface),
        "misses": misses,
        "privacy": {
            "raw_payloads_in_report": False,
            "sample_identifiers": "sha256",
        },
    }


def report_passes(
    report: dict[str, Any],
    *,
    min_precision: float = 0.0,
    min_recall: float = 0.0,
    min_f1: float = 0.0,
) -> bool:
    for name, value in (
        ("min_precision", min_precision),
        ("min_recall", min_recall),
        ("min_f1", min_f1),
    ):
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise AttackBenchError(f"{name} must be between 0 and 1")
    overall = report["overall"]
    return (
        overall["precision"] >= min_precision
        and overall["recall"] >= min_recall
        and overall["f1"] >= min_f1
    )


def _read_records(path: Path) -> Iterable[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        with path.open() as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AttackBenchError(f"invalid JSON on line {line_number}: {exc}") from exc
                yield _require_record(record, line_number)
        return
    if suffix == ".json":
        document = json.loads(path.read_text())
        if isinstance(document, dict):
            document = document.get("samples", document.get("records"))
        if not isinstance(document, list):
            raise AttackBenchError("JSON dataset must be an array or contain samples/records array")
        for index, record in enumerate(document, start=1):
            yield _require_record(record, index)
        return
    if suffix == ".csv":
        with path.open(newline="") as handle:
            for index, record in enumerate(csv.DictReader(handle), start=2):
                yield _require_record(record, index)
        return
    if suffix == ".parquet":
        try:
            import pyarrow.parquet as parquet
        except ImportError as exc:  # pragma: no cover - optional large-corpus profile
            raise AttackBenchError(
                "Parquet input requires: python3 -m pip install -e '.[benchmark]'"
            ) from exc
        for batch in parquet.ParquetFile(path).iter_batches(batch_size=4096):
            for record in batch.to_pylist():
                yield _require_record(record, 0)
        return
    raise AttackBenchError("dataset must use .jsonl, .ndjson, .json, .csv, or .parquet")


def _to_sample(
    record: dict[str, Any],
    *,
    payload_field: str,
    label_field: str,
    category_field: str,
    surface_field: str,
) -> AttackSample:
    label_value, resolved_label = _select(record, label_field, DEFAULT_LABEL_FIELDS, required=True)
    payload_value, resolved_payload = _select(
        record, payload_field, DEFAULT_PAYLOAD_FIELDS, required=False
    )
    if not resolved_payload:
        payload_value = {
            key: value for key, value in record.items() if key != resolved_label.split(".")[0]
        }
    category, _ = _select(record, category_field, DEFAULT_CATEGORY_FIELDS, required=False)
    surface, _ = _select(record, surface_field, DEFAULT_SURFACE_FIELDS, required=False)
    canonical = _canonical(payload_value)
    return AttackSample(
        payload=payload_value,
        expected_attack=_parse_label(label_value),
        category=str(category or "uncategorized").strip().lower(),
        surface=_normalize_surface(str(surface or _infer_surface(resolved_payload))),
        sample_hash=hashlib.sha256(canonical.encode()).hexdigest(),
    )


def _select(
    record: dict[str, Any],
    explicit: str,
    defaults: tuple[str, ...],
    *,
    required: bool,
) -> tuple[Any, str]:
    candidates = (explicit,) if explicit else defaults
    for candidate in candidates:
        if not candidate:
            continue
        found, value = _get_path(record, candidate)
        if found:
            return value, candidate
    if required:
        target = explicit or ", ".join(defaults)
        raise AttackBenchError(f"record is missing required field; tried: {target}")
    return None, ""


def _get_path(record: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _parse_label(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in POSITIVE_LABELS:
        return True
    if normalized in NEGATIVE_LABELS:
        return False
    raise AttackBenchError(f"unsupported binary label: {value!r}")


def _normalize_surface(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "tool_arguments": "arguments",
        "argument": "arguments",
        "request": "arguments",
        "tool_response": "result",
        "response": "result",
        "output": "result",
        "tool_description": "metadata",
        "description": "metadata",
        "definition": "metadata",
    }
    return aliases.get(normalized, normalized or "auto")


def _infer_surface(payload_field: str) -> str:
    lowered = payload_field.lower()
    if "description" in lowered:
        return "metadata"
    if "result" in lowered or "response" in lowered or "output" in lowered:
        return "result"
    return "auto"


def _metrics(samples: list[ScoredSample]) -> dict[str, Any]:
    tp = sum(sample.expected_attack and sample.predicted_attack for sample in samples)
    fp = sum(not sample.expected_attack and sample.predicted_attack for sample in samples)
    tn = sum(not sample.expected_attack and not sample.predicted_attack for sample in samples)
    fn = sum(sample.expected_attack and not sample.predicted_attack for sample in samples)
    total = tp + fp + tn + fn
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "samples": total,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "accuracy": _ratio(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "f1": _ratio(2 * precision * recall, precision + recall),
        "false_positive_rate": _ratio(fp, fp + tn),
        "false_negative_rate": _ratio(fn, fn + tp),
    }


def _grouped_metrics(
    samples: list[ScoredSample],
    key: Any,
) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[ScoredSample]] = {}
    for sample in samples:
        groups.setdefault(key(sample), []).append(sample)
    return {name: _metrics(items) for name, items in sorted(groups.items())}


def _ratio(numerator: float, denominator: float) -> float:
    return _rounded(numerator / denominator) if denominator else 0.0


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _contains_forbidden_key(value: Any, forbidden: set[str]) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in forbidden or _contains_forbidden_key(item, forbidden)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_key(item, forbidden) for item in value)
    return False


def _require_record(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttackBenchError(f"dataset record {index} must be an object")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rounded(value: float) -> float:
    return round(float(value), 6)
