from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Protocol


class ApprovalReplayStore(Protocol):
    def consume(self, jti: str, expires_at: int) -> bool: ...

    def close(self) -> None: ...


class SQLiteApprovalReplayStore:
    mode = "sqlite"

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._connection.execute("PRAGMA busy_timeout = 30000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_approvals (
                jti TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            )
            """
        )
        self._connection.commit()
        self._lock = threading.Lock()

    def consume(self, jti: str, expires_at: int) -> bool:
        digest = approval_jti_digest(jti)
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "DELETE FROM consumed_approvals WHERE expires_at < ?",
                    (int(time.time()),),
                )
                self._connection.execute(
                    "INSERT INTO consumed_approvals (jti, expires_at) VALUES (?, ?)",
                    (digest, expires_at),
                )
                self._connection.commit()
                return True
            except sqlite3.IntegrityError:
                self._connection.rollback()
                return False
            except Exception:
                self._connection.rollback()
                raise

    def close(self) -> None:
        self._connection.close()


class RedisApprovalReplayStore:
    mode = "redis"

    def __init__(self, url: str) -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Redis approval replay protection requires: python3 -m pip install -e '.[redis]'"
            ) from exc
        self._client = redis.Redis.from_url(url, decode_responses=True)

    def consume(self, jti: str, expires_at: int) -> bool:
        key = f"judikt:approval:jti:{approval_jti_digest(jti)}"
        return bool(self._client.set(key, "1", nx=True, pxat=expires_at * 1000))

    def close(self) -> None:
        self._client.close()


class DynamoDBApprovalReplayStore:
    mode = "dynamodb"

    def __init__(self, table: Any) -> None:
        if table is None:
            raise RuntimeError("serverless approval replay protection requires STATE_TABLE_NAME")
        self._table = table

    def consume(self, jti: str, expires_at: int) -> bool:
        digest = approval_jti_digest(jti)
        try:
            self._table.put_item(
                Item={
                    "pk": "APPROVAL_REPLAY",
                    "sk": digest,
                    "expires_at": expires_at,
                },
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
            return True
        except Exception as exc:
            if exc.__class__.__name__ == "ConditionalCheckFailedException":
                return False
            if "ConditionalCheckFailed" in str(exc):
                return False
            raise

    def close(self) -> None:
        return None


def build_approval_replay_store(
    path: Path,
    *,
    remote_mode: bool = False,
) -> ApprovalReplayStore:
    redis_url = os.getenv("JUDIKT_REDIS_URL", "")
    if redis_url:
        return RedisApprovalReplayStore(redis_url)
    distributed_required = remote_mode or _enabled("JUDIKT_PRODUCTION")
    if distributed_required and not _enabled("JUDIKT_SINGLE_INSTANCE"):
        raise RuntimeError(
            "remote or production mode requires Redis approval replay protection via "
            "JUDIKT_REDIS_URL; set JUDIKT_SINGLE_INSTANCE=true only for a single-instance deployment"
        )
    return SQLiteApprovalReplayStore(path)


def approval_jti_digest(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}
