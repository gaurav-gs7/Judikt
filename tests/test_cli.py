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
from judikt.audit import AuditStore
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

    def test_explicit_policy_wins_over_subcommand_default_policy(self) -> None:
        custom = "/tmp/judikt-custom-policy.json"
        for command in (["eval"], ["demo"], ["performance"], ["attackbench", "data.jsonl"]):
            with self.subTest(command=command[0]):
                self.assertEqual(cli.parse_arguments(command).policy, cli.DEMO_POLICY_PATH)
                before = cli.parse_arguments(["--policy", custom, *command])
                self.assertEqual(before.policy, Path(custom))
                after = cli.parse_arguments([*command, "--policy", custom])
                self.assertEqual(after.policy, Path(custom))
        content = ["eval-content", "--corpus", "c.jsonl", "--split", "dev", "--output", "o.json"]
        self.assertEqual(cli.parse_arguments(content).policy, cli.DEFAULT_POLICY_PATH)
        self.assertEqual(
            cli.parse_arguments(["--policy", custom, *content]).policy, Path(custom)
        )
        self.assertEqual(cli.parse_arguments(["serve-mcp"]).policy, cli.DEFAULT_POLICY_PATH)

    def test_configuration_errors_exit_cleanly_without_tracebacks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid_json = root / "invalid.json"
            invalid_json.write_text('{"broken": ')
            missing_key = root / "missing.json"
            missing_key.write_text('{"allowed_tools": {}}')
            policy = json.loads(cli.DEFAULT_POLICY_PATH.read_text())
            policy["risk"]["levels"] = {"critical": 80}
            bad_risk = root / "bad-risk.json"
            bad_risk.write_text(json.dumps(policy))
            bad_upstreams = root / "upstreams.json"
            bad_upstreams.write_text('{"servers": {"x": {"command": "not-a-list"}}}')
            cases = [
                (["--policy", str(root / "absent.json"), "serve-mcp"], "policy file not found"),
                (["--policy", str(root / "absent.json"), "eval"], "policy file not found"),
                (["--policy", str(invalid_json), "serve-mcp"], "is not valid JSON"),
                (["--policy", str(missing_key), "serve-mcp"], "'blocked_argument_patterns' is required"),
                (["interop", "--profile", "unknown-profile"], "unknown interoperability profile"),
                (["--policy", str(bad_risk), "serve-mcp"], "risk.levels"),
                (
                    ["issue-approval", "--actor", "a", "--reason", "r", "--server", "s",
                     "--tool", "t", "--arguments", "{bad"],
                    "--arguments is not valid JSON",
                ),
                (
                    ["issue-approval", "--actor", "a", "--reason", "r", "--server", "s",
                     "--tool", "t", "--arguments", "[1]"],
                    "--arguments must decode to a JSON object",
                ),
            ]
            environment = {
                **os.environ,
                "HOME": str(root),
                "XDG_STATE_HOME": str(root / "state"),
                "PYTHONPATH": str(Path(cli.__file__).resolve().parents[1]),
            }
            env_cases = [
                ({"JUDIKT_UPSTREAM_CONFIG": str(bad_upstreams)}, "command must be a non-empty string array"),
                ({"JUDIKT_KILL_SWITCH_BACKEND": "bogus"}, "kill_switches.backend must be"),
                (
                    {"JUDIKT_REDIS_URL": "redis://127.0.0.1:1/0", "JUDIKT_REDIS_REQUIRED": "true"},
                    "Redis rate limiting backend is unavailable",
                ),
            ]
            cases.extend((["serve-mcp"], expected, extra) for extra, expected in env_cases)
            remote_secrets = {
                "JUDIKT_HTTP_BEARER_TOKEN": "cli-test-bearer-token-at-least-32-bytes-long",
                "JUDIKT_APPROVAL_SECRET": "cli-test-approval-secret-at-least-32-bytes",
                "JUDIKT_AUDIT_HMAC_SECRET": "cli-test-independent-audit-secret-32-bytes",
                "JUDIKT_RESOURCE_URI": "http://127.0.0.1:18089/mcp",
                "JUDIKT_REDIS_URL": "",
                "JUDIKT_SINGLE_INSTANCE": "",
            }
            cases.append(
                (
                    ["serve-real-mcp", "--host", "0.0.0.0", "--port", "18089"],
                    "requires Redis approval replay protection",
                    remote_secrets,
                )
            )
            cases.append(
                (
                    ["serve-real-mcp", "--host", "0.0.0.0", "--port", "18089"],
                    "must be independent from JUDIKT_APPROVAL_SECRET",
                    {
                        **remote_secrets,
                        "JUDIKT_SINGLE_INSTANCE": "true",
                        "JUDIKT_AUDIT_HMAC_SECRET": remote_secrets["JUDIKT_APPROVAL_SECRET"],
                    },
                )
            )
            cases.append(
                (
                    ["serve-real-mcp", "--host", "0.0.0.0", "--port", "18089"],
                    "Redis approval replay backend is unavailable",
                    {**remote_secrets, "JUDIKT_REDIS_URL": "redis://127.0.0.1:1/0"},
                )
            )
            for case in cases:
                argv, expected = case[0], case[1]
                extra_environment = case[2] if len(case) > 2 else {}
                with self.subTest(argv=argv[:3], environment=sorted(extra_environment)):
                    result = subprocess.run(
                        [sys.executable, "-m", "judikt.cli", *argv],
                        capture_output=True,
                        text=True,
                        env={**environment, **extra_environment},
                        stdin=subprocess.DEVNULL,
                        timeout=60,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)
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

    def test_audit_checkpoint_command_captures_head_for_truncation_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET": "cli-audit-secret-with-at-least-32-bytes",
                "JUDIKT_AUDIT_SINK": "none",
            },
            clear=False,
        ):
            audit_path = Path(directory) / "audit.db"
            checkpoint_path = Path(directory) / "external" / "checkpoint.json"
            store = AuditStore(audit_path)
            for index in range(10):
                store.record(
                    correlation_id=f"checkpoint-{index}",
                    server="test",
                    tool="test.read",
                    allowed=True,
                    rule="allow",
                    reason="allowed",
                    arguments={},
                    result={"ok": True},
                    duration_ms=1,
                )
            store._connection.close()

            output = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "judikt",
                    "audit",
                    "checkpoint",
                    "--audit-db",
                    str(audit_path),
                    "--output",
                    str(checkpoint_path),
                ],
            ), redirect_stdout(output):
                cli.main()
            printed = json.loads(output.getvalue())
            exported = json.loads(checkpoint_path.read_text())
            self.assertEqual(set(printed), {"chain_id", "seq", "head_hash"})
            self.assertEqual(printed["seq"], 10)
            self.assertEqual(exported["seq"], 10)
            self.assertEqual(exported["head_hash"], printed["head_hash"])
            self.assertTrue(exported["signature"])

            tampered = AuditStore(audit_path)
            tampered._connection.execute("DELETE FROM audit_events WHERE seq > 7")
            tampered._connection.execute("DELETE FROM audit_checkpoints")
            tampered._connection.commit()
            tampered.close()

            output, exit_code = self.run_main_with_exit(
                [
                    "audit",
                    "verify",
                    "--audit-db",
                    str(audit_path),
                    "--checkpoint",
                    str(checkpoint_path),
                    "--full",
                ]
            )

        report = json.loads(output)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["status"], "tampered")
        self.assertIn("truncated", {error["error"] for error in report["errors"]})

    def test_audit_checkpoint_to_s3_fails_clearly_without_credentials(self) -> None:
        from judikt.audit import write_checkpoint

        with mock.patch.dict(
            os.environ,
            {
                "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent",
                "AWS_CONFIG_FILE": "/nonexistent",
                "AWS_EC2_METADATA_DISABLED": "true",
                "AWS_DEFAULT_REGION": "us-east-1",
            },
        ):
            for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
                os.environ.pop(name, None)
            with self.assertRaisesRegex(RuntimeError, "credentials|boto3"):
                write_checkpoint({"seq": 1}, "s3://bucket/key.json")
        with self.assertRaisesRegex(RuntimeError, "s3://bucket/key"):
            write_checkpoint({"seq": 1}, "s3://bucket-only")

    def test_audit_verify_reports_truncation_against_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET": "cli-audit-secret-with-at-least-32-bytes",
                "JUDIKT_AUDIT_CHECKPOINT_EVENTS": "1",
                "JUDIKT_AUDIT_SINK": "none",
            },
            clear=False,
        ):
            audit_path = Path(directory) / "audit.db"
            checkpoint_path = Path(directory) / "checkpoint.json"
            store = AuditStore(audit_path)
            for index in range(4):
                store.record(
                    correlation_id=f"cli-{index}",
                    server="test",
                    tool="test.read",
                    allowed=True,
                    rule="allow",
                    reason="allowed",
                    arguments={},
                    result={"ok": True},
                    duration_ms=1,
                )
            store.export_checkpoint(checkpoint_path)
            store._connection.execute("DELETE FROM audit_events WHERE seq > 1")
            store._connection.commit()
            store.close()

            output, exit_code = self.run_main_with_exit(
                [
                    "audit",
                    "verify",
                    "--audit-db",
                    str(audit_path),
                    "--checkpoint",
                    str(checkpoint_path),
                    "--full",
                ]
            )

            report = json.loads(output)
            self.assertEqual(exit_code, 1)
            self.assertFalse(report["valid"])
            self.assertIn("truncated", {error["error"] for error in report["errors"]})

    def test_audit_status_and_reconcile_commands_render_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET": "cli-status-audit-secret-at-least-32-bytes",
                "JUDIKT_AUDIT_SINK": "none",
            },
            clear=False,
        ):
            audit_path = Path(directory) / "audit.db"

            status = json.loads(
                self.run_main(["audit", "status", "--audit-db", str(audit_path)])
            )
            reconciled = json.loads(
                self.run_main(
                    ["audit", "reconcile", "--audit-db", str(audit_path), "--limit", "10"]
                )
            )

            self.assertEqual(status["pending"], 0)
            self.assertEqual(reconciled["delivered_now"], 0)

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
        self.assertEqual(initialize.call_args.kwargs["profile"], "read-only")

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
            audit_explicit=True,
            identity="local-operator",
            profile="read-only",
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
            audit_explicit=True,
            identity="local-operator",
            profile="read-only",
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
            audit_explicit=True,
            identity="operator",
            profile="approve-writes",
        )
        runtime = mock.Mock()
        with mock.patch.object(cli, "JudiktRuntime", return_value=runtime) as runtime_type, mock.patch.object(
            cli, "initialize_policy"
        ) as initialize, mock.patch.object(cli, "serve_gateway") as serve:
            cli._run_wrap(args)

        generated_policy = initialize.call_args.kwargs["output_path"]
        self.assertEqual(initialize.call_args.kwargs["identity"], "operator")
        self.assertEqual(initialize.call_args.kwargs["profile"], "approve-writes")
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

    def test_demo_uses_a_fresh_in_memory_approval_secret_per_run(self) -> None:
        secrets_seen = []

        def runtime_factory(*args: object, **kwargs: object) -> mock.Mock:
            authority = kwargs["approval_authority"]
            secrets_seen.append(authority.secret)
            return mock.Mock()

        with mock.patch.object(cli, "JudiktRuntime", side_effect=runtime_factory), mock.patch.object(
            cli, "run_demo"
        ):
            self.run_main(["demo"])
            self.run_main(["demo"])

        self.assertEqual(len(secrets_seen), 2)
        self.assertNotEqual(secrets_seen[0], secrets_seen[1])


if __name__ == "__main__":
    unittest.main()
