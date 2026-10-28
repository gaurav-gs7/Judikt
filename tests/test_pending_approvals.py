from __future__ import annotations

import argparse
import io
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path

from judikt import approve_command
from judikt.pending_approvals import PendingApprovalStore

CALL = {"server": "mail", "tool": "send_email", "arguments": {"to": "boss@corp.example", "body": "hi"}}


def held(store: PendingApprovalStore, **overrides: object) -> str:
    call = {**CALL, **overrides}
    return store.hold(actor="agent", rule="task_scope", reason="not declared", **call)  # type: ignore[arg-type]


def args(identifier: str | None = None, **flags: object) -> argparse.Namespace:
    return argparse.Namespace(id=identifier, yes=False, deny=False, reason="ok", **flags)


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class PendingApprovalStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = PendingApprovalStore(Path(self.directory.name) / "pending")

    def test_identical_calls_share_one_private_entry(self) -> None:
        first = held(self.store)
        self.assertEqual(held(self.store, arguments={**CALL["arguments"], "approval_token": "x"}), first)
        self.assertNotEqual(held(self.store, arguments={"to": "other@corp.example", "body": "hi"}), first)
        path = self.store.directory / f"{first}.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_an_approved_token_is_released_once_for_the_exact_call(self) -> None:
        identifier = held(self.store)
        self.assertIsNone(self.store.take_approved(actor="agent", **CALL))
        self.store.approve(identifier, "token", "local:me")
        self.assertIsNone(self.store.take_approved(actor="other", **CALL))
        self.assertIsNone(
            self.store.take_approved(actor="agent", server="mail", tool="send_email", arguments={"to": "x"})
        )
        self.assertEqual(self.store.take_approved(actor="agent", **CALL), "token")
        self.assertIsNone(self.store.take_approved(actor="agent", **CALL))

    def test_entries_expire_and_ids_are_validated(self) -> None:
        store = PendingApprovalStore(self.store.directory, ttl_seconds=-1)
        identifier = held(store)
        self.assertIsNone(store.get(identifier))
        self.assertEqual(store.entries(), [])
        with self.assertRaises(ValueError):
            store.get("../../etc/passwd")


class ApproveCommandTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.previous = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = str(self.state)
        self.addCleanup(self._restore)
        self.store = PendingApprovalStore(self.state / "pending")

    def _restore(self) -> None:
        if self.previous is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self.previous

    def test_lists_and_approves_after_confirmation(self) -> None:
        out = io.StringIO()
        self.assertEqual(approve_command.run(args(), store=self.store, out=out), 0)
        self.assertIn("No calls are waiting", out.getvalue())
        identifier = held(self.store)
        out = io.StringIO()
        approve_command.run(args(), store=self.store, out=out)
        self.assertIn(identifier, out.getvalue())
        out = io.StringIO()
        code = approve_command.run(args(identifier), store=self.store, stdin=TTY("y\n"), out=out)
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("boss@corp.example", out.getvalue())
        entry = self.store.get(identifier)
        assert entry is not None
        self.assertTrue(entry.approved)
        self.assertLessEqual(entry.expires_at, time.time() + 300)

    def test_refuses_without_a_terminal_or_yes_and_can_deny(self) -> None:
        identifier = held(self.store)
        self.assertEqual(approve_command.run(args(identifier), store=self.store, stdin=io.StringIO("y\n"), out=io.StringIO()), 2)
        self.assertEqual(approve_command.run(args(identifier), store=self.store, stdin=TTY("n\n"), out=io.StringIO()), 1)
        self.assertFalse(self.store.get(identifier).approved)  # type: ignore[union-attr]
        deny = args(identifier)
        deny.deny = True
        self.assertEqual(approve_command.run(deny, store=self.store, out=io.StringIO()), 0)
        self.assertIsNone(self.store.get(identifier))
        self.assertEqual(approve_command.run(args("0badf00d"), store=self.store, out=io.StringIO()), 1)


if __name__ == "__main__":
    unittest.main()
