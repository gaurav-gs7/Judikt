"""Measure the content guard's false-positive rate on real package documentation.

Collects README text from installed Python distributions (the long description
in each ``*.dist-info/METADATA``) and npm packages (``node_modules/*/README.md``),
splits it into chunks of at most 4 KB on line boundaries, and inspects every
chunk as a ``tool_result``. A chunk counts as a false positive when the guard
would redact or block it.

Third-party text is never written to the report: flagged chunks are identified
by package name, chunk index, sha256, and matched rule names only.

Usage:
    python3 scripts/measure_real_docs_fpr.py --output docs/evidence/real-docs-fpr.json
"""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from judikt.content_guard import ContentGuard  # noqa: E402

CHUNK_BYTES = 4096
DEFAULT_POLICY = ROOT / "src" / "judikt" / "resources" / "default-policy.json"


def _python_documents() -> Iterator[tuple[str, str]]:
    seen: set[str] = set()
    roots = [Path(entry) for entry in sys.path if entry and Path(entry).is_dir()]
    for root in roots:
        for metadata in sorted(root.glob("*.dist-info/METADATA")):
            try:
                message = email.parser.Parser().parsestr(
                    metadata.read_text(encoding="utf-8", errors="replace")
                )
            except OSError:
                continue
            name = str(message.get("Name", metadata.parent.name)).lower()
            if name in seen or name == "judikt":
                continue
            seen.add(name)
            body = message.get_payload()
            description = body if isinstance(body, str) else ""
            if not description.strip():
                description = str(message.get("Description", ""))
            if description.strip():
                yield f"pypi:{name}", description


EXTRA_NPM_ROOTS: list[Path] = []


def _npm_roots() -> list[Path]:
    roots: list[Path] = list(EXTRA_NPM_ROOTS)
    try:
        completed = subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True, timeout=30, check=False
        )
        if completed.returncode == 0 and completed.stdout.strip():
            roots.append(Path(completed.stdout.strip()))
    except (OSError, subprocess.TimeoutExpired):
        pass
    for candidate in ("/usr/local/lib/node_modules", "/usr/lib/node_modules"):
        roots.append(Path(candidate))
    roots.extend(sorted(Path("/opt").glob("*/node_modules")))
    roots.extend(sorted(Path("/opt").glob("*/lib/node_modules")))
    unique: list[Path] = []
    for root in roots:
        if root.is_dir() and root.resolve() not in {item.resolve() for item in unique}:
            unique.append(root)
    return unique


def _npm_documents() -> Iterator[tuple[str, str]]:
    seen: set[str] = set()
    for root in _npm_roots():
        for readme in sorted(root.rglob("README.md")):
            parts = readme.relative_to(root).parts
            if "node_modules" not in readme.parts or len(parts) < 2:
                continue
            package_parts = [part for part in parts[:-1]]
            # Use the innermost package path after the last node_modules.
            if "node_modules" in package_parts:
                last = len(package_parts) - 1 - package_parts[::-1].index("node_modules")
                package_parts = package_parts[last + 1 :]
            if package_parts and package_parts[0].startswith("@") and len(package_parts) >= 2:
                package = "/".join(package_parts[:2])
                if len(package_parts) > 2:
                    continue
            elif len(package_parts) == 1:
                package = package_parts[0]
            else:
                continue
            if package in seen:
                continue
            seen.add(package)
            try:
                yield f"npm:{package}", readme.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue


def _chunks(text: str) -> Iterator[str]:
    current: list[str] = []
    size = 0
    for line in text.splitlines(keepends=True):
        encoded = len(line.encode("utf-8", errors="replace"))
        if current and size + encoded > CHUNK_BYTES:
            yield "".join(current)
            current, size = [], 0
        while encoded > CHUNK_BYTES:
            head = line.encode("utf-8", errors="replace")[:CHUNK_BYTES].decode("utf-8", errors="ignore")
            yield head
            line = line[len(head) :]
            encoded = len(line.encode("utf-8", errors="replace"))
        current.append(line)
        size += encoded
    if current and "".join(current).strip():
        yield "".join(current)


def measure(policy_path: Path) -> dict[str, object]:
    guard = ContentGuard.from_policy(json.loads(policy_path.read_text()))
    total = 0
    flagged: list[dict[str, object]] = []
    packages = 0
    by_ecosystem: dict[str, dict[str, int]] = {}
    for package, text in [*_python_documents(), *_npm_documents()]:
        packages += 1
        ecosystem = package.split(":", 1)[0]
        stats = by_ecosystem.setdefault(ecosystem, {"packages": 0, "chunks": 0, "flagged": 0})
        stats["packages"] += 1
        for index, chunk in enumerate(_chunks(text)):
            total += 1
            stats["chunks"] += 1
            inspection = guard.inspect(chunk, surface="tool_result")
            if inspection.action in {"redact", "block"}:
                stats["flagged"] += 1
                flagged.append(
                    {
                        "package": package,
                        "chunk": index,
                        "chunk_sha256": hashlib.sha256(chunk.encode()).hexdigest(),
                        "action": inspection.action,
                        "rules": sorted({finding.rule for finding in inspection.findings}),
                    }
                )
    return {
        "schema_version": 1,
        "measurement": "content guard tool_result false-positive rate on real package documentation",
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "content_guard_sha256": hashlib.sha256(
            (ROOT / "src" / "judikt" / "content_guard.py").read_bytes()
        ).hexdigest(),
        "chunk_bytes": CHUNK_BYTES,
        "packages": packages,
        "chunks": total,
        "flagged_chunks": len(flagged),
        "false_positive_rate": round(len(flagged) / total, 6) if total else 0.0,
        "by_ecosystem": by_ecosystem,
        "flagged": flagged,
        "privacy": {"third_party_text_in_report": False},
        "environment": {"python": sys.version.split()[0], "platform": sys.platform, "cwd_independent": True},
    }


def main() -> None:
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    arguments.add_argument("--output", type=Path)
    arguments.add_argument(
        "--npm-root",
        type=Path,
        action="append",
        default=[],
        help="additional node_modules directory to scan (repeatable)",
    )
    args = arguments.parse_args()
    EXTRA_NPM_ROOTS.extend(args.npm_root)
    report = measure(args.policy)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    summary = {key: report[key] for key in ("packages", "chunks", "flagged_chunks", "false_positive_rate")}
    print(json.dumps(summary, indent=2))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
