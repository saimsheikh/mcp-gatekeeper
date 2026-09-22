"""SQLite access shared by the audit log and the approval queue.

Plain ``sqlite3`` rather than an ORM: the schema is two tables, and an ORM
would add a dependency, a migration framework, and a layer of typing that
pyright strict handles poorly, in exchange for nothing this project needs.

``sqlite3`` is synchronous, so every call is pushed to a worker thread. One
connection is shared behind a lock -- SQLite serialises writes regardless, and
a single connection keeps WAL mode and the busy timeout in one place.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import anyio

__all__ = ["MIGRATIONS", "Database"]


MIGRATIONS: Sequence[str] = (
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id        TEXT    NOT NULL UNIQUE,
        created_at      TEXT    NOT NULL,
        tool            TEXT    NOT NULL,
        upstream        TEXT    NOT NULL,
        arguments       TEXT    NOT NULL,
        action          TEXT    NOT NULL,
        decision_source TEXT    NOT NULL,
        decision_reason TEXT,
        rule_index      INTEGER,
        outcome         TEXT    NOT NULL,
        approval_id     TEXT,
        approver        TEXT,
        latency_ms      REAL,
        result_status   TEXT,
        client_name     TEXT,
        error           TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events (created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events (tool);",
    """
    CREATE TABLE IF NOT EXISTS approvals (
        id          TEXT PRIMARY KEY,
        created_at  TEXT NOT NULL,
        expires_at  TEXT NOT NULL,
        status      TEXT NOT NULL,
        tool        TEXT NOT NULL,
        upstream    TEXT NOT NULL,
        arguments   TEXT NOT NULL,
        reason      TEXT,
        client_name TEXT,
        decided_at  TEXT,
        approver    TEXT,
        note        TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status, created_at DESC);",
)


class Database:
    """A thread-offloaded SQLite handle.

    Open it with ``async with``; the schema is applied on entry, so a fresh
    file and an existing one behave the same.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._connection: sqlite3.Connection | None = None
        self._lock = anyio.Lock()

    @property
    def path(self) -> Path:
        return self._path

    async def __aenter__(self) -> Self:
        await anyio.to_thread.run_sync(self._connect)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await anyio.to_thread.run_sync(self._close)

    def _connect(self) -> None:
        if self._path.parent and str(self._path.parent) not in {"", "."}:
            self._path.parent.mkdir(parents=True, exist_ok=True)

        # check_same_thread is off because every call arrives on an arbitrary
        # worker thread; the lock provides the mutual exclusion instead.
        connection = sqlite3.connect(self._path, check_same_thread=False, timeout=30.0)
        connection.row_factory = sqlite3.Row
        # WAL lets the web UI read while a tool call is writing.
        connection.execute("PRAGMA journal_mode = WAL;")
        connection.execute("PRAGMA foreign_keys = ON;")
        for statement in MIGRATIONS:
            connection.execute(statement)
        connection.commit()
        self._connection = connection

    def _close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _require(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("database is not open; use 'async with Database(...)'")
        return self._connection

    async def execute(self, sql: str, parameters: Sequence[Any] = ()) -> None:
        """Run a writing statement and commit it."""

        def run() -> None:
            connection = self._require()
            connection.execute(sql, parameters)
            connection.commit()

        async with self._lock:
            await anyio.to_thread.run_sync(run)

    async def fetch_all(self, sql: str, parameters: Sequence[Any] = ()) -> list[sqlite3.Row]:
        def run() -> list[sqlite3.Row]:
            return self._require().execute(sql, parameters).fetchall()

        async with self._lock:
            return await anyio.to_thread.run_sync(run)

    async def fetch_one(self, sql: str, parameters: Sequence[Any] = ()) -> sqlite3.Row | None:
        def run() -> sqlite3.Row | None:
            return self._require().execute(sql, parameters).fetchone()

        async with self._lock:
            return await anyio.to_thread.run_sync(run)

    async def transact(self, work: Callable[[sqlite3.Connection], Any]) -> Any:
        """Run ``work`` inside a single transaction.

        Used where a read and a write must not interleave with another caller,
        such as claiming a pending approval exactly once.
        """

        def run() -> Any:
            connection = self._require()
            try:
                result = work(connection)
            except Exception:
                connection.rollback()
                raise
            connection.commit()
            return result

        async with self._lock:
            return await anyio.to_thread.run_sync(run)

    async def iterate(self, sql: str, parameters: Sequence[Any] = ()) -> Iterable[sqlite3.Row]:
        """Fetch rows for streaming export.

        Materialised rather than a live cursor: the connection is shared, so a
        long-lived cursor would hold the lock for the duration of the export.
        """
        return await self.fetch_all(sql, parameters)
