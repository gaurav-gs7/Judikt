from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from judikt.content_eval import ContentEvaluationError, run_content_evaluation


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS = PROJECT_ROOT / "tests" / "fixtures" / "content_guard" / "corpus.jsonl"
POLICY = PROJECT_ROOT / "src" / "judikt" / "resources" / "default-policy.json"


class ContentEvaluationTest(unittest.TestCase):
    def test_corpus_size_schema_split_and_surface_balance(self) -> None:
        records = [json.loads(line) for line in CORPUS.read_text().splitlines()]

        self.assertEqual(len(records), 432)
        self.assertEqual(Counter(record["label"] for record in records), {"benign": 264, "attack": 168})
        self.assertEqual(Counter(record["split"] for record in records), {"dev": 254, "test": 178})
        self.assertEqual(set(record["surface"] for record in records), {
            "tool_description",
            "tool_result",
            "tool_argument",
        })
        self.assertEqual(len({record["id"] for record in records}), len(records))
        for record in records:
            self.assertEqual(
                set(record),
                {"id", "split", "surface", "category", "label", "text", "source"},
            )
        for label, category in {
            (record["label"], record["category"]) for record in records
        }:
            group = [
                record
                for record in records
                if record["label"] == label and record["category"] == category
            ]
            self.assertEqual({record["split"] for record in group}, {"dev", "test"})
            self.assertEqual({record["surface"] for record in group}, {
                "tool_description",
                "tool_result",
                "tool_argument",
            })

    def test_report_has_grouped_metrics_and_no_raw_payloads(self) -> None:
        report = run_content_evaluation(CORPUS, POLICY, split="dev")
        rendered = json.dumps(report)

        self.assertEqual(report["evaluation"]["sample_count"], 254)
        self.assertEqual(set(report["by_surface"]), {
            "tool_description",
            "tool_result",
            "tool_argument",
        })
        self.assertIn("instruction_override", report["by_category"])
        for group in [report["overall"], *report["by_surface"].values(), *report["by_category"].values()]:
            self.assertIn("precision", group)
            self.assertIn("recall", group)
            self.assertIn("false_positive_rate", group)
            self.assertIn("f1", group)
            self.assertEqual(set(group["latency_ms"]), {"p50", "p95", "p99"})
        self.assertFalse(report["privacy"]["raw_payloads_in_report"])
        self.assertNotIn("ignore previous system instructions", rendered.lower())

    def test_rejects_unknown_split(self) -> None:
        with self.assertRaisesRegex(ContentEvaluationError, "split must be"):
            run_content_evaluation(CORPUS, POLICY, split="holdout")

    def test_cli_writes_requested_split_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "eval-content",
                    "--corpus",
                    str(CORPUS),
                    "--split",
                    "dev",
                    "--output",
                    str(output),
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout), json.loads(output.read_text()))


if __name__ == "__main__":
    unittest.main()
