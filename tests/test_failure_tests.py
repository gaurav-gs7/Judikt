from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from judikt.failure_tests import main, run_failure_tests


class FailureDrillTest(unittest.TestCase):
    def test_every_documented_failure_mode_behaves_as_expected(self) -> None:
        report = run_failure_tests()

        self.assertEqual(report["case_count"], 5)
        self.assertEqual(report["passed_count"], 5)
        self.assertTrue(report["passed"])
        names = {result["name"] for result in report["results"]}
        self.assertEqual(
            names,
            {
                "approval gate blocks destructive rollback",
                "kill switch blocks a read tool",
                "circuit breaker opens after repeated tool failures",
                "secret redaction protects config output",
                "rate limit blocks excessive health checks",
            },
        )
        for result in report["results"]:
            self.assertTrue(result["passed"], result)

    def test_main_prints_the_report_and_exits_zero_on_success(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            exit_code = main()

        self.assertEqual(exit_code, 0)
        self.assertIn('"passed": true', buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
