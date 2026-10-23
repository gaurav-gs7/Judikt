from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .content_guard import ContentGuard


VALID_SPLITS = {"dev", "test"}
VALID_SURFACES = {"tool_description", "tool_result", "tool_argument"}
VALID_LABELS = {"benign", "attack"}


class ContentEvaluationError(ValueError):
    pass


@dataclass(frozen=True)
class ContentScore:
    expected_attack: bool
    predicted_attack: bool
    surface: str
    category: str
    latency_ms: float


def run_content_evaluation(
    corpus_path: Path,
    policy_path: Path,
    *,
    split: str,
) -> dict[str, Any]:
    if split not in VALID_SPLITS:
        raise ContentEvaluationError("split must be dev or test")
    config = json.loads(policy_path.read_text())
    guard = ContentGuard.from_policy(config)
    scores: list[ContentScore] = []
    mistakes: list[dict[str, Any]] = []
    for line_number, line in enumerate(corpus_path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ContentEvaluationError(f"invalid JSON on line {line_number}: {exc}") from exc
        _validate_record(record, line_number)
        if record["split"] != split:
            continue
        started = time.perf_counter_ns()
        inspection = guard.inspect(_record_payload(record))
        latency_ms = (time.perf_counter_ns() - started) / 1_000_000
        score = ContentScore(
            expected_attack=record["label"] == "attack",
            predicted_attack=bool(inspection.findings),
            surface=record["surface"],
            category=record["category"],
            latency_ms=latency_ms,
        )
        scores.append(score)
        if score.expected_attack != score.predicted_attack:
            mistakes.append(
                {
                    "sample_id_sha256": hashlib.sha256(record["id"].encode()).hexdigest(),
                    "surface": score.surface,
                    "category": score.category,
                    "expected_attack": score.expected_attack,
                    "predicted_attack": score.predicted_attack,
                    "matched_rules": sorted({finding.rule for finding in inspection.findings}),
                }
            )
    if not scores:
        raise ContentEvaluationError(f"corpus has no records for split {split!r}")
    return {
        "schema_version": 1,
        "evaluation": {
            "name": "Judikt content-guard precision corpus",
            "split": split,
            "sample_count": len(scores),
            "corpus_sha256": _sha256_file(corpus_path),
            "policy_sha256": _sha256_file(policy_path),
        },
        "overall": _metrics(scores),
        "by_surface": _grouped(scores, "surface"),
        "by_category": _grouped(scores, "category"),
        "mistakes": mistakes,
        "privacy": {
            "raw_payloads_in_report": False,
            "sample_identifiers": "sha256",
        },
    }


def _validate_record(record: Any, line_number: int) -> None:
    if not isinstance(record, dict):
        raise ContentEvaluationError(f"record on line {line_number} must be an object")
    required = {"id", "split", "surface", "category", "label", "text", "source"}
    missing = sorted(required - set(record))
    if missing:
        raise ContentEvaluationError(
            f"record on line {line_number} is missing: {', '.join(missing)}"
        )
    if not isinstance(record["id"], str) or not record["id"]:
        raise ContentEvaluationError(f"record on line {line_number} has an invalid id")
    if record["split"] not in VALID_SPLITS:
        raise ContentEvaluationError(f"record on line {line_number} has an invalid split")
    if record["surface"] not in VALID_SURFACES:
        raise ContentEvaluationError(f"record on line {line_number} has an invalid surface")
    if record["label"] not in VALID_LABELS:
        raise ContentEvaluationError(f"record on line {line_number} has an invalid label")
    if not isinstance(record["category"], str) or not record["category"]:
        raise ContentEvaluationError(f"record on line {line_number} has an invalid category")
    if not isinstance(record["text"], str):
        raise ContentEvaluationError(f"record on line {line_number} text must be a string")
    if not isinstance(record["source"], str) or not record["source"]:
        raise ContentEvaluationError(f"record on line {line_number} has an invalid source")


def _record_payload(record: dict[str, Any]) -> Any:
    if record["category"] != "split_fields":
        return record["text"]
    try:
        payload = json.loads(record["text"])
    except json.JSONDecodeError as exc:
        raise ContentEvaluationError("split_fields text must contain a JSON object or array") from exc
    if not isinstance(payload, (dict, list)):
        raise ContentEvaluationError("split_fields text must contain a JSON object or array")
    return payload


def _grouped(scores: list[ContentScore], field: str) -> dict[str, dict[str, Any]]:
    values = sorted({str(getattr(score, field)) for score in scores})
    return {
        value: _metrics([score for score in scores if getattr(score, field) == value])
        for value in values
    }


def _metrics(scores: list[ContentScore]) -> dict[str, Any]:
    true_positive = sum(score.expected_attack and score.predicted_attack for score in scores)
    false_positive = sum(not score.expected_attack and score.predicted_attack for score in scores)
    true_negative = sum(not score.expected_attack and not score.predicted_attack for score in scores)
    false_negative = sum(score.expected_attack and not score.predicted_attack for score in scores)
    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    latencies = sorted(score.latency_ms for score in scores)
    return {
        "sample_count": len(scores),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "precision": _rounded(precision),
        "recall": _rounded(recall),
        "false_positive_rate": _rounded(_ratio(false_positive, false_positive + true_negative)),
        "f1": _rounded(_ratio(2 * precision * recall, precision + recall)),
        "latency_ms": {
            "p50": _rounded(_percentile(latencies, 0.50)),
            "p95": _rounded(_percentile(latencies, 0.95)),
            "p99": _rounded(_percentile(latencies, 0.99)),
        },
    }


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, max(0, round((len(values) - 1) * quantile)))
    return values[index]


def _rounded(value: float) -> float:
    return round(float(value), 6)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
