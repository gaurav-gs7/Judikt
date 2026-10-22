from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from judikt.attackbench import AttackBenchError, run_attackbench
from judikt.paths import DEMO_POLICY_PATH


SOURCE_URL = "https://github.com/GenTelLab/MCP-Guard"
SOURCE_COMMIT = "4bc97790256280480cf827c0a0fdb85e86754dfb"
SOURCE_SHA256 = "b53588fd4390288d309b8489faef85cb207e31c6d2b062aab9382a98becc8667"
SOURCE_ROWS = 1_053
FULL_CORPUS_ROWS = 70_448


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reproduce Judikt's evaluation of GenTelLab's published dev.csv file."
    )
    parser.add_argument("checkout", type=Path, help="Checkout of GenTelLab/MCP-Guard")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("build/attackbench-gentellab-public-dev.json"),
    )
    parser.add_argument("--policy", type=Path, default=DEMO_POLICY_PATH)
    args = parser.parse_args()

    checkout = args.checkout.resolve()
    dataset = checkout / "test_data" / "dev.csv"
    if not dataset.is_file():
        raise SystemExit(f"published development file not found: {dataset}")
    commit = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if commit != SOURCE_COMMIT:
        raise SystemExit(
            f"source commit changed: expected {SOURCE_COMMIT}, received {commit}; "
            "review and publish a new evidence record"
        )
    digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
    if digest != SOURCE_SHA256:
        raise SystemExit(
            f"source digest changed: expected {SOURCE_SHA256}, received {digest}"
        )

    try:
        raw = run_attackbench(
            dataset,
            args.policy,
            dataset_id="gentellab-mcp-guard-public-dev",
            payload_field="description",
            label_field="Label",
            expected_samples=SOURCE_ROWS,
        )
    except AttackBenchError as exc:
        raise SystemExit(str(exc)) from exc

    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "source": {
            "repository": SOURCE_URL,
            "commit": commit,
            "path": "test_data/dev.csv",
            "sha256": digest,
            "sample_count": SOURCE_ROWS,
            "scope": (
                "Public development file in the authors' framework repository; the authors "
                "do not identify it as the complete MCP-AttackBench corpus."
            ),
        },
        "evaluation": {
            "policy_sha256": raw["benchmark"]["policy_sha256"],
            "field_mapping": raw["field_mapping"],
            "overall": raw["overall"],
            "latency_ms": raw["latency_ms"],
            "throughput_samples_per_second": raw["throughput_samples_per_second"],
            "mismatch_count": len(raw["misses"]),
            "privacy": raw["privacy"],
        },
        "full_corpus": {
            "expected_sample_count": FULL_CORPUS_ROWS,
            "status": "not_run_corpus_not_publicly_released",
            "checked_at": datetime.now(UTC).date().isoformat(),
            "evidence": f"{SOURCE_URL}#-todo-list",
        },
        "interpretation": (
            "The public file labels broad harmful or unsafe descriptions and supplies no MCP "
            "surface or attack-category field. Its score measures Judikt's narrow deterministic "
            "MCP controls against that broader binary classification task; it is not a full "
            "MCP-AttackBench score."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
