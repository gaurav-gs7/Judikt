"""Track values that reach an agent through untrusted tool output.

A prompt injection succeeds when the agent acts on something the attacker
planted: an address to send data to, an account to pay, a link to visit. Judikt
cannot read the agent's mind, but it sees both sides: every untrusted tool
result going in, and every tool call coming out. This module records concrete
values (email addresses, URLs and domains, IBANs, long account or phone
numbers, crypto addresses, @handles) that first appear in tool output, and
reports when a later write or destructive call reuses one.

A value the agent used in its own arguments before any tool returned it came
from the user or the agent's task, not from untrusted content, so it is
trusted and never matches.

The tracker is deterministic and in-memory for one gateway process, and it
stores only normalised values and where they were first seen.
"""

from __future__ import annotations

import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

MAX_TRACKED_VALUES = 50_000
MAX_SCAN_CHARS = 262_144
COMMON_TLDS = (
    "com|net|org|io|dev|app|ai|co|me|info|biz|xyz|ru|cn|uk|de|fr|in|us|eu|sh|gg|tv|ly|to|cc|ws|"
    "site|online|top|club|link|live|tech|store|shop|cloud|page|email|zip|mov|ch|nl|se|no|es|it|"
    "pl|br|au|ca|jp|kr|tk|ml|ga|cf|gq|su|pw|example|invalid|test"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_URL = re.compile(r"\bhttps?://[^\s<>\"'`)\]}]+", re.IGNORECASE)
_DOMAIN = re.compile(
    rf"(?<![@A-Za-z0-9._-])(?:www\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?\.)+(?:{COMMON_TLDS})(?![A-Za-z0-9-])",
    re.IGNORECASE,
)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){10,30}\b")
_CRYPTO = re.compile(r"\b0x[0-9a-fA-F]{40}\b|\bbc1[a-z0-9]{25,60}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_LONG_NUMBER = re.compile(r"(?<![\w.])\+?\(?\d(?:[ ().-]{0,2}\d){7,}(?![\w.])")
_DATE_LIKE = re.compile(r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|^\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}$")
_HANDLE = re.compile(r"(?<![A-Za-z0-9_.])@[A-Za-z][A-Za-z0-9_]{2,30}\b")


def indicators(text: str) -> set[tuple[str, str]]:
    """Normalised ``(kind, value)`` pairs found in ``text``."""

    text = text[:MAX_SCAN_CHARS]
    found: set[tuple[str, str]] = set()
    for match in _EMAIL.finditer(text):
        email = match.group(0).lower().strip(".")
        found.add(("email", email))
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(".,;:!?").lower()
        host = re.sub(r"^https?://", "", url).split("/", 1)[0].split(":", 1)[0]
        found.add(("url", url.rstrip("/")))
        if host:
            found.add(("domain", host.removeprefix("www.")))
    without_emails = _EMAIL.sub(" ", text)
    for match in _DOMAIN.finditer(without_emails):
        found.add(("domain", match.group(0).lower().removeprefix("www.")))
    for match in _IBAN.finditer(text):
        found.add(("account", match.group(0).replace(" ", "")))
    for match in _CRYPTO.finditer(text):
        found.add(("crypto", match.group(0).lower()))
    for match in _LONG_NUMBER.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 8 <= len(digits) <= 34 and not _DATE_LIKE.match(match.group(0).lstrip("+(")):
            found.add(("number", digits))
    for match in _HANDLE.finditer(text):
        found.add(("handle", match.group(0).lower()))
    return found


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for key, child in value.items() for item in [str(key), *strings(child)]]
    if isinstance(value, (list, tuple)):
        return [item for child in value for item in strings(child)]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [str(value)]
    return []


MODES = ("require_approval", "deny", "report", "off")
KINDS = ("email", "url", "domain", "account", "crypto", "number", "handle")
DEFAULT_MODE = "require_approval"


@dataclass(frozen=True)
class ProvenanceConfig:
    mode: str = DEFAULT_MODE
    kinds: frozenset[str] = frozenset(KINDS)

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    @classmethod
    def from_policy(cls, policy: dict[str, Any]) -> ProvenanceConfig:
        """Read ``untrusted_provenance`` from a policy, raising ``ValueError`` when malformed."""

        section = policy.get("untrusted_provenance", {})
        if isinstance(section, bool):
            return cls(mode=DEFAULT_MODE if section else "off")
        if not isinstance(section, dict):
            raise ValueError("'untrusted_provenance' must be an object or true/false")
        unknown = set(section) - {"mode", "kinds"}
        if unknown:
            raise ValueError(f"'untrusted_provenance' has unknown key(s): {', '.join(sorted(unknown))}")
        mode = section.get("mode", DEFAULT_MODE)
        if mode not in MODES:
            raise ValueError(f"'untrusted_provenance.mode' must be one of {', '.join(MODES)}")
        kinds = section.get("kinds", list(KINDS))
        if not isinstance(kinds, list) or not kinds or any(kind not in KINDS for kind in kinds):
            raise ValueError(f"'untrusted_provenance.kinds' must be a non-empty list drawn from {', '.join(KINDS)}")
        return cls(mode=mode, kinds=frozenset(kinds))


@dataclass(frozen=True)
class ProvenanceMatch:
    kind: str
    source_server: str
    source_tool: str

    def evidence(self) -> str:
        return f"untrusted_provenance:{self.kind}:{self.source_server}/{self.source_tool}"


class ProvenanceTracker:
    """Where each value an agent has seen came from, per actor.

    ``scope`` separates agents that share one gateway (the authenticated actor
    on a remote gateway; a single scope for a local ``wrap``).
    """

    def __init__(self, config: ProvenanceConfig | None = None, max_values: int = MAX_TRACKED_VALUES) -> None:
        self.config = config or ProvenanceConfig()
        self._origins: OrderedDict[tuple[str, str, str], tuple[str, str] | None] = OrderedDict()
        self._max_values = max_values
        self._lock = threading.Lock()

    def _found(self, value: Any) -> set[tuple[str, str]]:
        return {item for text in strings(value) for item in indicators(text) if item[0] in self.config.kinds}

    def _remember(self, key: tuple[str, str, str], origin: tuple[str, str] | None) -> None:
        if key in self._origins:
            return
        self._origins[key] = origin
        while len(self._origins) > self._max_values:
            self._origins.popitem(last=False)

    def observe_arguments(self, scope: str, arguments: Any) -> None:
        """Values the agent supplies before any tool returned them are trusted."""

        if not self.config.enabled:
            return
        found = self._found(arguments)
        with self._lock:
            for kind, value in found:
                self._remember((scope, kind, value), None)

    def observe_result(self, scope: str, server: str, tool: str, result: Any) -> None:
        if not self.config.enabled:
            return
        found = self._found(result)
        with self._lock:
            for kind, value in found:
                self._remember((scope, kind, value), (server, tool))

    def matches(self, scope: str, arguments: Any) -> list[ProvenanceMatch]:
        """Untrusted values reused in ``arguments``, one match per kind and source."""

        if not self.config.enabled:
            return []
        found = self._found(arguments)
        hits: dict[tuple[str, str, str], ProvenanceMatch] = {}
        with self._lock:
            for kind, value in found:
                origin = self._origins.get((scope, kind, value))
                if origin is not None:
                    hits.setdefault((kind, *origin), ProvenanceMatch(kind, *origin))
        return sorted(hits.values(), key=lambda match: (match.kind, match.source_server, match.source_tool))
