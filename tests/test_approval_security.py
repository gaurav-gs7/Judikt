from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.approval import (
    ApprovalAuthority,
    ApprovalConfigurationError,
    REVOKED_DEV_SECRET,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STRONG_SECRET = "approval-test-secret-with-at-least-32-bytes"


class ApprovalSecretSecurityTest(unittest.TestCase):
    def test_local_install_key_is_private_and_shared_by_authorities(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"XDG_STATE_HOME": directory},
            clear=True,
        ):
            first = ApprovalAuthority()
            second = ApprovalAuthority()
            state_directory = Path(directory) / "judikt"
            key_path = state_directory / "approval.key"

            self.assertEqual(first.secret, second.secret)
            self.assertEqual(stat.S_IMODE(state_directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)

    def test_world_readable_install_key_is_refused_with_fix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_directory = Path(directory) / "judikt"
            state_directory.mkdir(mode=0o700)
            key_path = state_directory / "approval.key"
            key_path.write_text(STRONG_SECRET)
            key_path.chmod(0o644)
            with patch.dict(os.environ, {"XDG_STATE_HOME": directory}, clear=True):
                with self.assertRaisesRegex(
                    ApprovalConfigurationError,
                    rf"{key_path}.*chmod 600",
                ):
                    ApprovalAuthority()

    def test_retired_and_short_configured_secrets_are_refused(self) -> None:
        for value, message in (
            (REVOKED_DEV_SECRET, "retired public development"),
            ("short", "at least 32 bytes"),
        ):
            with self.subTest(value=value), patch.dict(
                os.environ,
                {"JUDIKT_APPROVAL_SECRET": value},
                clear=True,
            ):
                with self.assertRaisesRegex(ApprovalConfigurationError, message):
                    ApprovalAuthority()

    def test_concurrent_processes_create_and_use_one_install_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                **os.environ,
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "XDG_STATE_HOME": directory,
            }
            for name in (
                "JUDIKT_APPROVAL_SECRET",
                "JUDIKT_APPROVAL_SECRET_ARN",
                "JUDIKT_APPROVAL_SECRET_VAULT_PATH",
            ):
                environment.pop(name, None)
            code = (
                "import hashlib; "
                "from judikt.approval import ApprovalAuthority; "
                "print(hashlib.sha256(ApprovalAuthority().secret).hexdigest())"
            )
            processes = [
                subprocess.Popen(
                    [sys.executable, "-c", code],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(2)
            ]
            results = [process.communicate(timeout=10) for process in processes]

            self.assertEqual([process.returncode for process in processes], [0, 0])
            self.assertEqual(len({stdout.strip() for stdout, _ in results}), 1)
            self.assertEqual(
                hashlib.sha256((Path(directory) / "judikt" / "approval.key").read_text().strip().encode()).hexdigest(),
                results[0][0].strip(),
            )

    def test_remote_mode_requires_configured_shared_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"XDG_STATE_HOME": directory},
            clear=True,
        ):
            with self.assertRaisesRegex(
                ApprovalConfigurationError,
                "requires a configured shared approval secret",
            ):
                ApprovalAuthority(require_configured=True)
            self.assertFalse((Path(directory) / "judikt" / "approval.key").exists())

    def test_remote_server_startup_fails_cleanly_without_shared_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                **os.environ,
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "XDG_STATE_HOME": directory,
                "JUDIKT_HTTP_BEARER_TOKEN": "remote-auth-token",
                "JUDIKT_JWT_HS256_SECRET": "",
                "JUDIKT_JWT_JWKS_URL": "",
            }
            for name in (
                "JUDIKT_APPROVAL_SECRET",
                "JUDIKT_APPROVAL_SECRET_ARN",
                "JUDIKT_APPROVAL_SECRET_VAULT_PATH",
            ):
                environment.pop(name, None)
            started = subprocess.run(
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
                cwd=PROJECT_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(started.returncode, 0)
            self.assertIn("requires a configured shared approval secret", started.stderr)
            self.assertNotIn("Traceback", started.stderr)

    def test_cli_issued_token_verifies_with_same_install_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = {
                **os.environ,
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "XDG_STATE_HOME": str(root / "state"),
                "JUDIKT_AUDIT_HMAC_SECRET": "audit-test-secret-with-at-least-32-bytes",
                "JUDIKT_AUDIT_SINK": "none",
                "JUDIKT_TELEMETRY": "disabled",
                "JUDIKT_UPSTREAM_CONFIG": "",
            }
            for name in (
                "JUDIKT_APPROVAL_SECRET",
                "JUDIKT_APPROVAL_SECRET_ARN",
                "JUDIKT_APPROVAL_SECRET_VAULT_PATH",
            ):
                environment.pop(name, None)
            arguments = '{"service":"payments-api"}'
            issued = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "judikt.cli",
                    "--audit-db",
                    str(root / "audit.db"),
                    "issue-approval",
                    "--actor",
                    "operator",
                    "--reason",
                    "authorized test",
                    "--server",
                    "platform-ops",
                    "--tool",
                    "platform.restart_service",
                    "--arguments",
                    arguments,
                ],
                cwd=PROJECT_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(issued.returncode, 0, issued.stderr)
            with patch.dict(os.environ, environment, clear=True):
                claims = ApprovalAuthority().verify(
                    token=issued.stdout.strip(),
                    server="platform-ops",
                    tool="platform.restart_service",
                    arguments={"service": "payments-api"},
                )
            self.assertEqual(claims.actor, "operator")


if __name__ == "__main__":
    unittest.main()
