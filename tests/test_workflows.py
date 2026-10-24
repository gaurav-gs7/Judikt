from __future__ import annotations

import re
import unittest
from pathlib import Path


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _jobs(text: str) -> dict[str, str]:
    """Split a workflow file into its top-level jobs (name -> job body text)."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\n", body)
    return {parts[index]: parts[index + 1] for index in range(1, len(parts) - 1, 2)}


class WorkflowTest(unittest.TestCase):
    def test_gh_cli_jobs_without_checkout_name_the_repository(self) -> None:
        # Without a checkout, gh cannot infer the repository and exits 1. That
        # broke the first release's skill upload.
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            for name, job in _jobs(workflow.read_text()).items():
                runs_gh = re.search(r"(?m)^\s*(run:.*\bgh |gh )", job) is not None
                checked_out = "actions/checkout@" in job
                with self.subTest(workflow=workflow.name, job=name):
                    if runs_gh and not checked_out:
                        self.assertRegex(job, r"GH_REPO:|--repo\b")


if __name__ == "__main__":
    unittest.main()
