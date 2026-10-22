from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from judikt import cli
from judikt.auth import AuthError
from judikt.policy_init import PolicyInitializationError


parser = cli.parser


class CLITest(unittest.TestCase):
    def run_main(self, arguments: list[str]) -> str:
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["judikt", *arguments]), redirect_stdout(output):
            cli.main()
        return output.getvalue()

    def run_main_with_exit(self, arguments: list[str]) -> tuple[str, object]:
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["judikt", *arguments]), redirect_stdout(output):
            try:
                cli.main()
            except SystemExit as exc:
                return output.getvalue(), exc.code
        self.fail("command did not raise SystemExit")

    def test_remote_server_configuration_error_is_concise(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        environment = {
            **os.environ,
            "PYTHONPATH": str(project_root / "src"),
            "JUDIKT_HTTP_BEARER_TOKEN": "",
            "JUDIKT_JWT_HS256_SECRET": "",
            "JUDIKT_JWT_JWKS_URL": "",
        }
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "serve-real-mcp",
                "--host",
                "0.0.0.0",
                "--port",
                "18080",
            ],
            cwd=project_root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("remote MCP binding requires bearer or JWT authentication", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_runtime_options_are_accepted_after_public_subcommand(self) -> None:
        args = parser().parse_args(["serve-mcp", "--audit-db", "/tmp/judikt-test.db"])

        self.assertEqual(args.command, "serve-mcp")
        self.assertEqual(args.audit_db, Path("/tmp/judikt-test.db"))

    def test_runtime_options_are_still_accepted_before_public_subcommand(self) -> None:
        args = parser().parse_args(["--audit-db", "/tmp/judikt-test.db", "serve-mcp"])

        self.assertEqual(args.command, "serve-mcp")
        self.assertEqual(args.audit_db, Path("/tmp/judikt-test.db"))

    def test_attackbench_threshold_options_are_parsed(self) -> None:
        args = parser().parse_args(
            [
                "attackbench",
                "tests/fixtures/attackbench_smoke.jsonl",
                "--expected-samples",
                "8",
                "--min-recall",
                "0.9",
            ]
        )

        self.assertEqual(args.command, "attackbench")
        self.assertEqual(args.expected_samples, 8)
        self.assertEqual(args.min_recall, 0.9)

    def test_performance_threshold_options_are_parsed(self) -> None:
        args = parser().parse_args(
            [
                "performance",
                "--iterations",
                "50",
                "--warmup",
                "5",
                "--max-p99-ms",
                "25",
                "--min-throughput",
                "20",
            ]
        )

        self.assertEqual(args.command, "performance")
        self.assertEqual(args.iterations, 50)
        self.assertEqual(args.warmup, 5)
        self.assertEqual(args.max_p99_ms, 25)
        self.assertEqual(args.min_throughput, 20)

    def test_init_dispatches_and_renders_machine_readable_report(self) -> None:
        report = {"policy": "policy.json", "server": "tools", "tool_count": 1}
        with mock.patch.object(cli, "initialize_policy", return_value=report) as initialize:
            rendered = self.run_main(
                ["init", "--identity", "operator", "--", "company-mcp", "--stdio"]
            )

        self.assertEqual(json.loads(rendered), report)
        self.assertEqual(initialize.call_args.args[0], ["company-mcp", "--stdio"])
        self.assertEqual(initialize.call_args.kwargs["server_name"], "company-mcp")
        self.assertEqual(initialize.call_args.kwargs["identity"], "operator")

    def test_init_and_wrap_errors_are_concise(self) -> None:
        with mock.patch.object(
            cli,
            "initialize_policy",
            side_effect=PolicyInitializationError("invalid upstream"),
        ), self.assertRaisesRegex(SystemExit, "init: invalid upstream"):
            self.run_main(["init", "--", "company-mcp"])

        args = SimpleNamespace(
            upstream_command=[],
            name="",
            policy_explicit=False,
            policy=Path("policy.json"),
            audit_db=Path("audit.db"),
            identity="local-operator",
        )
        with self.assertRaisesRegex(SystemExit, "wrap: an upstream command is required"):
            cli._run_wrap(args)

    def test_wrap_uses_explicit_policy_without_discovery(self) -> None:
        args = SimpleNamespace(
            upstream_command=["--", "company-mcp"],
            name="company-tools",
            policy_explicit=True,
            policy=Path("policy.json"),
            audit_db=Path("audit.db"),
            identity="local-operator",
        )
        runtime = mock.Mock()
        with mock.patch.object(cli, "JudiktRuntime", return_value=runtime) as runtime_type, mock.patch.object(
            cli, "initialize_policy"
        ) as initialize, mock.patch.object(cli, "serve_gateway") as serve:
            cli._run_wrap(args)

        initialize.assert_not_called()
        self.assertEqual(runtime_type.call_args.args[:2], (Path("policy.json"), Path("audit.db")))
        self.assertEqual(runtime_type.call_args.kwargs["upstream_servers"][0].name, "company-tools")
        serve.assert_called_once_with(runtime)

    def test_wrap_discovers_policy_when_none_is_explicit(self) -> None:
        args = SimpleNamespace(
            upstream_command=["company-mcp"],
            name="",
            policy_explicit=False,
            policy=Path("unused.json"),
            audit_db=Path("audit.db"),
            identity="operator",
        )
        runtime = mock.Mock()
        with mock.patch.object(cli, "JudiktRuntime", return_value=runtime) as runtime_type, mock.patch.object(
            cli, "initialize_policy"
        ) as initialize, mock.patch.object(cli, "serve_gateway") as serve:
            cli._run_wrap(args)

        generated_policy = initialize.call_args.kwargs["output_path"]
        self.assertEqual(initialize.call_args.kwargs["identity"], "operator")
        self.assertEqual(runtime_type.call_args.args[0], generated_policy)
        serve.assert_called_once_with(runtime)

    def test_backend_eval_and_interop_commands_dispatch(self) -> None:
        with mock.patch.object(cli, "run_backend") as backend:
            self.run_main(["backend", "platform-ops"])
            backend.assert_called_once_with("platform-ops")

        with mock.patch.object(cli, "print_evals", return_value=7), self.assertRaises(
            SystemExit
        ) as raised:
            self.run_main(["eval"])
        self.assertEqual(raised.exception.code, 7)

        with mock.patch.object(cli, "print_interop_profiles", return_value=3), self.assertRaises(
            SystemExit
        ) as raised:
            self.run_main(["interop"])
        self.assertEqual(raised.exception.code, 3)

    def test_benchmark_commands_write_reports_and_return_threshold_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            attack_output = Path(directory) / "attack.json"
            attack_report = {"overall": {"precision": 1.0}}
            with mock.patch.object(cli, "run_attackbench", return_value=attack_report), mock.patch.object(
                cli, "attackbench_report_passes", return_value=False
            ):
                rendered, exit_code = self.run_main_with_exit(
                    ["attackbench", "dataset.jsonl", "--output", str(attack_output)]
                )
            self.assertEqual(exit_code, 1)
            self.assertEqual(json.loads(attack_output.read_text()), attack_report)
            self.assertEqual(json.loads(rendered), attack_report)

            performance_output = Path(directory) / "performance.json"
            performance_report = {"guarded_latency_ms": {"p99": 1.0}}
            with mock.patch.object(
                cli, "run_gateway_benchmark", return_value=performance_report
            ), mock.patch.object(
                cli, "performance_report_passes", return_value=True
            ):
                rendered, exit_code = self.run_main_with_exit(
                    ["performance", "--output", str(performance_output)]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(performance_output.read_text()), performance_report)
            self.assertEqual(json.loads(rendered), performance_report)

    def test_server_and_runtime_commands_dispatch_and_close_owners(self) -> None:
        with mock.patch.object(cli, "serve_real_mcp", side_effect=AuthError("auth required")), self.assertRaisesRegex(
            SystemExit, "serve-real-mcp: auth required"
        ):
            self.run_main(["serve-real-mcp"])

        runtime = mock.Mock()
        runtime.policy.issue_approval.return_value = "signed-token"
        with mock.patch.object(cli, "JudiktRuntime", return_value=runtime), mock.patch.object(
            cli, "run_demo"
        ) as demo:
            self.run_main(["demo"])
            demo.assert_called_once_with(runtime)
            runtime.close.assert_called_once_with()

        runtime.reset_mock()
        with mock.patch.object(cli, "JudiktRuntime", return_value=runtime), mock.patch.object(
            cli, "serve_dashboard"
        ) as dashboard:
            self.run_main(["dashboard", "--port", "9090"])
            dashboard.assert_called_once_with(runtime, "127.0.0.1", 9090, None)

        runtime.reset_mock()
        with mock.patch.object(cli, "JudiktRuntime", return_value=runtime):
            rendered = self.run_main(
                [
                    "issue-approval",
                    "--actor",
                    "operator",
                    "--reason",
                    "maintenance",
                    "--server",
                    "tools",
                    "--tool",
                    "restart",
                    "--arguments",
                    '{"service":"api"}',
                ]
            )
        self.assertEqual(rendered.strip(), "signed-token")
        runtime.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
