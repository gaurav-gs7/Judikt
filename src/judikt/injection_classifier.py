"""Dependency-free scorer for Judikt's learned prompt-injection classifier.

The model is a logistic regression over two TF-IDF blocks (word 1-2 grams and
character 3-5 grams within word boundaries), trained offline by
``scripts/build_injection_classifier.py``. This module reproduces
scikit-learn's feature extraction exactly, so scoring is deterministic and
needs only the standard library. No language model is involved.

Text is split into windows and the highest-scoring window decides, so an
instruction hidden inside a long, otherwise benign document still scores high.
"""

from __future__ import annotations

import gzip
import json
import math
import re
import threading
from collections import Counter
from importlib import resources
from typing import Any

WINDOW_CHARS = 600
WINDOW_OVERLAP = 120
MAX_WINDOWS = 64
_TOKEN = re.compile(r"(?u)\b\w\w+\b")
_WHITE_SPACES = re.compile(r"\s\s+")
_RESOURCE = "injection_classifier.json.gz"
_IMPERATIVES = (
    "send|transfer|grant|delete|write|tell|give|include|add|remove|create|update|share|forward|email|call|run|execute|"
    "open|visit|click|print|reply|respond|answer|ignore|disregard|forget|summari[sz]e|translate|list|show|provide|explain|"
    "describe|generate|make|do|go|use|change|set|post|upload|download|buy|pay|book|schedule|cancel|unlock|disable|enable|"
    "reset|move|copy|read|fetch|retrieve|search|find|order|withdraw|deposit|approve|merge|install|invoke|append|output|"
    "repeat|say|reveal|get|let|ask|stop|start|keep|check|look|try|put|bring|take|leave|turn|switch|follow|act|behave|"
    "pretend|submit|export|save|store|wire|notify|contact|message|text|invite|modify|draft|compose|develop|break|replace|"
    "proceed|treat|edit|rewrite|convert|calculate|compute|count|sort|rank|compare|analy[sz]e|evaluate|review|identify|"
    "classify|extract|insert|apply|plan|design|build|implement|fix|debug|refactor|test|deploy|configure|enter|type|fill|"
    "complete|confirm|verify|accept|decline|refuse|reserve|purchase|request|revoke|rename|archive|publish|tweet|like|"
    "subscribe|unsubscribe|join|lock|wipe|erase|format|encrypt|decrypt|login|log|sign|register|authori[sz]e|allow|permit|"
    "block|ban|kick|mute|pin|star|fork|clone|push|pull|commit|close|reopen|assign|tag|label|mark|flag|report|recommend|"
    "suggest|choose|select|pick|return|display|render|draw|imagine|assume|consider|remember|note|cease|halt|continue|"
    "resume|begin|end|finish|exit|quit|shut|restart|reboot|kill|terminate|transfer"
)
# An injection has to instruct. A window with no second person, no request,
# no question and no sentence that starts with a command verb only describes.
INSTRUCTION_CUE = re.compile(
    r"\byou(?:r|rs|rself)?\b|\bplease\b|\bkindly\b|\?|"
    rf"(?:^|[.!:;)\]>\n]\s*|[-*]\s+|\"|'|_|\b(?:and|then)\s+|,\s*)(?:{_IMPERATIVES})\b",
    re.IGNORECASE | re.MULTILINE,
)


def window_spans(text: str) -> list[tuple[int, int]]:
    """Character spans of at most ``WINDOW_CHARS``, grouped on line boundaries.

    Over-long lines are split with ``WINDOW_OVERLAP`` characters of overlap.
    Spans index into ``text`` so a flagged window can be redacted in place.
    """

    spans: list[tuple[int, int]] = []
    start = end = -1
    position = 0
    for raw in text.splitlines(keepends=True):
        line_start = position + (len(raw) - len(raw.lstrip()))
        line_end = position + len(raw.rstrip())
        position += len(raw)
        if line_end <= line_start:
            continue
        while line_end - line_start > WINDOW_CHARS:
            if start >= 0:
                spans.append((start, end))
                start = end = -1
            spans.append((line_start, line_start + WINDOW_CHARS))
            line_start += WINDOW_CHARS - WINDOW_OVERLAP
        if start >= 0 and line_end - start > WINDOW_CHARS:
            spans.append((start, end))
            start = -1
        if start < 0:
            start = line_start
        end = line_end
    if start >= 0:
        spans.append((start, end))
    return spans


def windows(text: str) -> list[str]:
    """The text of each window from ``window_spans``."""

    return [text[start:end] for start, end in window_spans(text)]


def _word_ngrams(text: str, low: int, high: int) -> list[str]:
    tokens = _TOKEN.findall(text.lower())
    grams: list[str] = []
    for n in range(low, high + 1):
        if n == 1:
            grams.extend(tokens)
        else:
            grams.extend(" ".join(tokens[index : index + n]) for index in range(len(tokens) - n + 1))
    return grams


def _char_wb_ngrams(text: str, low: int, high: int) -> list[str]:
    grams: list[str] = []
    for word in _WHITE_SPACES.sub(" ", text.lower()).split():
        padded = f" {word} "
        length = len(padded)
        for n in range(low, high + 1):
            offset = 0
            grams.append(padded[offset : offset + n])
            while offset + n < length:
                offset += 1
                grams.append(padded[offset : offset + n])
            if offset == 0:
                break
    return grams


class _Block:
    def __init__(self, spec: dict[str, Any]) -> None:
        self.analyzer = spec["analyzer"]
        self.low, self.high = spec["ngram_range"]
        self.index = {term: position for position, term in enumerate(spec["terms"])}
        self.idf = spec["idf"]
        self.coef = spec["coef"]

    def score(self, text: str) -> float:
        grams = (
            _word_ngrams(text, self.low, self.high)
            if self.analyzer == "word"
            else _char_wb_ngrams(text, self.low, self.high)
        )
        counts = Counter(position for gram in grams if (position := self.index.get(gram)) is not None)
        if not counts:
            return 0.0
        weights = {position: (1.0 + math.log(count)) * self.idf[position] for position, count in counts.items()}
        norm = math.sqrt(sum(value * value for value in weights.values()))
        return sum(value * self.coef[position] for position, value in weights.items()) / norm


class InjectionClassifier:
    def __init__(self, model: dict[str, Any]) -> None:
        if model.get("format") != "judikt-injection-classifier/1":
            raise ValueError("unsupported injection classifier format")
        self.blocks = [_Block(block) for block in model["blocks"]]
        self.intercept = float(model["intercept"])
        self.threshold = float(model["threshold"])

    def decision(self, text: str) -> float:
        """The raw linear score of one window (scikit-learn's decision_function)."""

        return self.intercept + sum(block.score(text) for block in self.blocks)

    def score(self, text: str) -> float:
        """The highest window score in ``text``."""

        pieces = windows(text)[:MAX_WINDOWS]
        return max((self.decision(piece) for piece in pieces), default=float("-inf"))

    def flags(self, text: str, margin: float = 0.0) -> bool:
        return self.score(text) > self.threshold + margin

    def flagged_spans(self, text: str) -> list[tuple[int, int]]:
        """Spans of the windows that score above the threshold.

        Known limitation: an instruction that shares its window with several
        benign lines can be diluted below the threshold. Scoring lines alone
        was measured and rejected: it raised BIPIA recall from 54.8% to 73.2%
        but tripled false positives on real package documentation (0.64% to
        2.20%).
        """

        return [
            (start, end)
            for start, end in window_spans(text)[:MAX_WINDOWS]
            if self.decision(text[start:end]) > self.threshold
        ]


_DEFAULT: InjectionClassifier | None = None
_LOCK = threading.Lock()


def default_classifier() -> InjectionClassifier | None:
    """The packaged model, or ``None`` when it is not installed."""

    global _DEFAULT
    with _LOCK:
        if _DEFAULT is None:
            try:
                raw = resources.files("judikt.resources").joinpath(_RESOURCE).read_bytes()
            except (FileNotFoundError, ModuleNotFoundError):
                return None
            _DEFAULT = InjectionClassifier(json.loads(gzip.decompress(raw)))
        return _DEFAULT
