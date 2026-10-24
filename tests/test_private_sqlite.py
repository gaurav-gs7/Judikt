from __future__ import annotations

import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from judikt.approval_replay import SQLiteApprovalReplayStore
from judikt.audit import AuditStore
from judikt.findings import FindingDispatcher
from judikt.kill_switch import SQLiteKillSwitchStore
from judikt.paths import connect_private_sqlite


AUDIT_SECRET = "private-sqlite-test-audit-secret-32-bytes"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class PrivateSQLiteTest(unittest.TestCase):
    """Judikt's databases hold audit evidence and control state: owner-only."""

    def setUp(self) -> None:
        self.previous_umask = os.umask(0o022)
        self.addCleanup(os.umask, self.previous_umask)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def assert_private(self, database: Path) -> None:
        for candidate in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
            if candidate.exists():
                self.assertEqual(_mode(candidate), 0o600, candidate.name)

    def test_new_database_and_wal_files_are_owner_only(self) -> None:
        database = self.root / "new.db"
        connection = connect_private_sqlite(database)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE t (x INTEGER)")
        connection.execute("INSERT INTO t VALUES (1)")
        connection.commit()
        self.assertTrue(Path(f"{database}-wal").exists())
        self.assert_private(database)
        connection.close()

    def test_existing_world_readable_database_is_tightened(self) -> None:
        database = self.root / "existing.db"
        connect_private_sqlite(database).close()
        database.chmod(0o644)
        connect_private_sqlite(database).close()
        self.assertEqual(_mode(database), 0o600)

    def test_every_store_creates_private_files(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "JUDIKT_AUDIT_HMAC_SECRET": AUDIT_SECRET,
                "XDG_STATE_HOME": str(self.root / "state"),
            },
            clear=False,
        ):
            audit = AuditStore(self.root / "audit.db")
            audit.record(
                correlation_id="c",
                server="s",
                tool="t",
                allowed=True,
                rule="allow",
                reason="ok",
                arguments={},
                result=None,
                duration_ms=1,
            )
            self.assert_private(self.root / "audit.db")
            audit.close()

            replay = SQLiteApprovalReplayStore(self.root / "replay.db")
            replay.consume("jti", int(time.time()) + 60)
            self.assert_private(self.root / "replay.db")
            replay.close()

            kill_switches = SQLiteKillSwitchStore(self.root / "control.db")
            self.assert_private(self.root / "control.db")
            kill_switches.close()

            findings = FindingDispatcher(self.root / "findings.db")
            self.assert_private(self.root / "findings.db")
            findings.close()


if __name__ == "__main__":
    unittest.main()
