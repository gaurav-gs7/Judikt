"""Build Judikt's external content-guard holdout from pinned public datasets.

The holdout measures generalisation, so it must never be used to tune rules.
This script only converts pinned upstream files; it never prints payloads.

Usage:
    python3 scripts/build_external_holdout.py --fetch /tmp/judikt-external
    python3 scripts/build_external_holdout.py --sources /tmp/judikt-external

``--fetch`` clones each source at its pinned commit (requires git and network
access to github.com) and then builds. Every source file is verified against
its pinned sha256 before use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_content_guard_corpus import BENIGN_TEMPLATES  # noqa: E402

OUTPUT = ROOT / "tests" / "fixtures" / "content_guard" / "external" / "holdout.jsonl"

SOURCES: dict[str, dict[str, Any]] = {
    "bipia": {
        "repository": "https://github.com/microsoft/BIPIA.git",
        "commit": "a004b69ec0dd446e0afd461d98cb5e96e120a5d0",
        "license": "MIT (Copyright (c) Microsoft Corporation)",
        "files": {
            "LICENSE": "",
            "benchmark/text_attack_test.json": "",
            "benchmark/code_attack_test.json": "",
            # EmailQA contexts derive from OpenAI Evals invoices data (MIT).
            # Code (Stack Exchange) and table (WikiTableQuestions) contexts are
            # CC BY-SA 4.0 and are deliberately not used.
            "benchmark/email/test.jsonl": "",
        },
    },
    "injecagent": {
        "repository": "https://github.com/uiuc-kang-lab/InjecAgent.git",
        "commit": "f19c9f2c79a41046eb13c03c51a24c567a8ffa07",
        "license": "MIT (Copyright (c) 2023 Qiusi Zhan)",
        "files": {
            "LICENCE": "",
            "data/test_cases_dh_base.json": "",
            "data/test_cases_ds_base.json": "",
            "data/user_cases.jsonl": "",
        },
    },
}
PINNED_SHA256_PATH = ROOT / "tests" / "fixtures" / "content_guard" / "external" / "sources.lock.json"
INJECAGENT_SAMPLE_PER_FILE = 125
INJECAGENT_BENIGN_FILLS = 5
PLACEHOLDER = "<Attacker Instruction>"


def _line(category: str, index: int) -> str:
    templates = BENIGN_TEMPLATES[category]
    return templates[index % len(templates)].format(i=index)


def _wrap(wrapper: str, payload: str, index: int) -> str:
    """Embed a payload in a realistic tool-result wrapper.

    Surrounding text reuses lines from Judikt's existing benign corpus so the
    wrapper itself is known not to trigger the guard.
    """

    if wrapper == "readme":
        return (
            f"# component-{index}\n\n## Setup\n\n{_line('readme_setup', index)}\n\n"
            f"## Changelog\n\n- {_line('issue_pr', index)}\n- {payload}\n"
        )
    if wrapper == "issue_body":
        return (
            f"### Issue #{1000 + index}\n\n{_line('issue_pr', index + 1)}\n\n"
            f"{payload}\n\nSteps to reproduce: {_line('cli_help', index)}"
        )
    if wrapper == "web_page":
        return (
            f"<html><body><h1>Release notes {index}</h1><p>{_line('ordinary_prose', index)}</p>"
            f"<p>{payload}</p></body></html>"
        )
    if wrapper == "email":
        return (
            f"From: ops-{index}@example.com\nSubject: Weekly update {index}\n\n"
            f"Hi team,\n\n{_line('policy_documentation', index)}\n\n{payload}\n\nThanks,\nOps"
        )
    if wrapper == "log":
        return f"{_line('log_line', index)}\n{payload}\n{_line('log_line', index + 1)}"
    if wrapper == "tool_description":
        return f"Fetch records for component {index}. {payload}"
    raise ValueError(f"unknown wrapper: {wrapper}")


TOOL_RESULT_WRAPPERS = ("readme", "issue_body", "web_page", "email", "log")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, source in SOURCES.items():
        target = directory / name
        if not target.exists():
            subprocess.run(
                ["git", "clone", "--quiet", source["repository"], str(target)],
                check=True,
            )
        subprocess.run(
            ["git", "-C", str(target), "checkout", "--quiet", source["commit"]],
            check=True,
        )


def verify(directory: Path, *, write_lock: bool) -> dict[str, dict[str, str]]:
    observed: dict[str, dict[str, str]] = {}
    for name, source in SOURCES.items():
        commit = subprocess.run(
            ["git", "-C", str(directory / name), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if commit != source["commit"]:
            raise SystemExit(f"{name} is at {commit}, expected pinned {source['commit']}")
        observed[name] = {
            relative: _sha256(directory / name / relative) for relative in source["files"]
        }
    if write_lock:
        PINNED_SHA256_PATH.parent.mkdir(parents=True, exist_ok=True)
        PINNED_SHA256_PATH.write_text(json.dumps(observed, indent=2, sort_keys=True) + "\n")
        return observed
    pinned = json.loads(PINNED_SHA256_PATH.read_text())
    if pinned != observed:
        raise SystemExit("source files do not match sources.lock.json")
    return observed


def _record(
    *,
    sample_id: str,
    surface: str,
    category: str,
    label: str,
    text: str,
    source: str,
    wrapper: str,
) -> dict[str, str]:
    return {
        "id": sample_id,
        "split": "test",
        "surface": surface,
        "category": category,
        "label": label,
        "text": text,
        "source": source,
        "wrapper": wrapper,
    }


def build(directory: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    bipia = directory / "bipia" / "benchmark"
    for filename in ("text_attack_test.json", "code_attack_test.json"):
        attacks = json.loads((bipia / filename).read_text())
        for category, payloads in sorted(attacks.items()):
            for position, payload in enumerate(payloads):
                index = len(records)
                slug = category.lower().replace(" ", "_").replace("&", "and")
                wrapper = TOOL_RESULT_WRAPPERS[index % len(TOOL_RESULT_WRAPPERS)]
                for surface, chosen in (("tool_result", wrapper), ("tool_description", "tool_description")):
                    records.append(
                        _record(
                            sample_id=f"bipia-{filename.split('_')[0]}-{slug}-{position}-{surface}",
                            surface=surface,
                            category=f"bipia_{filename.split('_')[0]}",
                            label="attack",
                            text=_wrap(chosen, str(payload), index),
                            source="BIPIA (MIT)",
                            wrapper=chosen,
                        )
                    )

    emails = [
        json.loads(line)
        for line in (bipia / "email" / "test.jsonl").read_text().splitlines()
        if line.strip()
    ]
    for position, email in enumerate(emails):
        records.append(
            _record(
                sample_id=f"bipia-email-benign-{position}",
                surface="tool_result",
                category="bipia_email_benign",
                label="benign",
                text=str(email["context"]),
                source="BIPIA (MIT)",
                wrapper="bipia_email_context",
            )
        )

    injecagent = directory / "injecagent" / "data"
    for filename in ("test_cases_dh_base.json", "test_cases_ds_base.json"):
        cases = json.loads((injecagent / filename).read_text())
        step = max(1, len(cases) // INJECAGENT_SAMPLE_PER_FILE)
        selected = cases[::step][:INJECAGENT_SAMPLE_PER_FILE]
        kind = "dh" if "_dh_" in filename else "ds"
        for position, case in enumerate(selected):
            records.append(
                _record(
                    sample_id=f"injecagent-{kind}-{position}",
                    surface="tool_result",
                    category=f"injecagent_{kind}",
                    label="attack",
                    text=str(case["Tool Response"]),
                    source="InjecAgent (MIT)",
                    wrapper="injecagent_tool_response",
                )
            )
    user_cases = [
        json.loads(line)
        for line in (injecagent / "user_cases.jsonl").read_text().splitlines()
        if line.strip()
    ]
    fill_categories = ("readme_setup", "issue_pr", "runbook", "ordinary_prose", "log_line")
    for position, case in enumerate(user_cases):
        template = str(case["Tool Response Template"])
        for fill in range(INJECAGENT_BENIGN_FILLS):
            filler = _line(fill_categories[fill % len(fill_categories)], position + fill)
            records.append(
                _record(
                    sample_id=f"injecagent-benign-{position}-{fill}",
                    surface="tool_result",
                    category="injecagent_benign",
                    label="benign",
                    text=template.replace(PLACEHOLDER, filler),
                    source="InjecAgent (MIT)",
                    wrapper="injecagent_template_with_judikt_benign_fill",
                )
            )
    return records


def main() -> None:
    arguments = argparse.ArgumentParser(description=__doc__)
    group = arguments.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", type=Path, help="clone pinned sources into this directory, then build")
    group.add_argument("--sources", type=Path, help="build from already cloned pinned sources")
    arguments.add_argument(
        "--write-lock",
        action="store_true",
        help="record source sha256 values (first import only)",
    )
    args = arguments.parse_args()
    directory = args.fetch or args.sources
    if args.fetch:
        fetch(directory)
    verify(directory, write_lock=args.write_lock)
    records = build(directory)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records)
    )
    counts: dict[str, int] = {}
    for record in records:
        key = f"{record['source']}/{record['label']}/{record['surface']}"
        counts[key] = counts.get(key, 0) + 1
    print(json.dumps({"output": str(OUTPUT), "sha256": _sha256(OUTPUT), "counts": counts}, indent=2))


if __name__ == "__main__":
    main()
