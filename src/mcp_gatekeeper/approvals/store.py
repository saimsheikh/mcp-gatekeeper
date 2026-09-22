"""Persistence for the approval queue.

Approvals live in SQLite rather than in memory for a reason specific to this
protocol: under the multi-round-trip pattern, an approved call arrives back as
a *fresh* request, so the decision must outlive the handler that created it.
It also means a restart mid-approval does not silently drop the request.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from mcp_gatekeeper.approvals.models import TIMEOUT_APPROVER, ApprovalRequest, ApprovalStatus
from mcp_gatekeeper.db import Database

__all__ = ["ApprovalStore", "SqliteApprovalStore"]

_COLUMNS = (
    "id, created_at, expires_at, status, tool, upstream, arguments, reason, "
    "client_name, decided_at, approver, note"
)


class ApprovalStore(Protocol):
    async def create(self, request: ApprovalRequest) -> None: ...

    async def get(self, approval_id: str) -> ApprovalRequest | None: ...

    async def resolve(
        self, approval_id: str, *, approved: bool, approver: str, note: str | None = None
    ) -> ApprovalRequest | None: ...

    async def pending(self) -> Sequence[ApprovalRequest]: ...

    async def expire_overdue(self, now: datetime | None = None) -> int: ...


def _row_to_request(row: sqlite3.Row) -> ApprovalRequest:
    decided = row["decided_at"]
    return ApprovalRequest(
        id=row["id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        expires_at=datetime.fromisoformat(row["expires_at"]),
        status=ApprovalStatus(row["status"]),
        tool=row["tool"],
        upstream=row["upstream"],
        arguments=json.loads(row["arguments"]),
        reason=row["reason"],
        client_name=row["client_name"],
        decided_at=datetime.fromisoformat(decided) if decided else None,
        approver=row["approver"],
        note=row["note"],
    )


@dataclass
class SqliteApprovalStore:
    """SQLite-backed approval queue."""

    database: Database

    async def create(self, request: ApprovalRequest) -> None:
        await self.database.execute(
            f"INSERT INTO approvals ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request.id,
                request.created_at.isoformat(),
                request.expires_at.isoformat(),
                request.status.value,
                request.tool,
                request.upstream,
                json.dumps(request.arguments, sort_keys=True, default=str),
                request.reason,
                request.client_name,
                None,
                None,
                None,
            ),
        )

    async def get(self, approval_id: str) -> ApprovalRequest | None:
        row = await self.database.fetch_one(
            f"SELECT {_COLUMNS} FROM approvals WHERE id = ?", (approval_id,)
        )
        return _row_to_request(row) if row else None

    async def resolve(
        self, approval_id: str, *, approved: bool, approver: str, note: str | None = None
    ) -> ApprovalRequest | None:
        """Record a decision, but only against a still-pending request.

        The read and the write share one transaction so two approvers clicking
        at once cannot both win: the second finds the row no longer pending and
        gets the first decision back instead of overwriting it.
        """
        status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        decided_at = datetime.now(UTC)

        def work(connection: sqlite3.Connection) -> sqlite3.Row | None:
            connection.execute("BEGIN IMMEDIATE;")
            current = connection.execute(
                f"SELECT {_COLUMNS} FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            if current is None:
                return None
            if current["status"] == ApprovalStatus.PENDING.value:
                connection.execute(
                    "UPDATE approvals SET status = ?, decided_at = ?, approver = ?, note = ? "
                    "WHERE id = ? AND status = ?",
                    (
                        status.value,
                        decided_at.isoformat(),
                        approver,
                        note,
                        approval_id,
                        ApprovalStatus.PENDING.value,
                    ),
                )
                return connection.execute(
                    f"SELECT {_COLUMNS} FROM approvals WHERE id = ?", (approval_id,)
                ).fetchone()
            return current

        row = await self.database.transact(work)
        return _row_to_request(row) if row is not None else None

    async def pending(self) -> Sequence[ApprovalRequest]:
        rows = await self.database.fetch_all(
            f"SELECT {_COLUMNS} FROM approvals WHERE status = ? ORDER BY created_at ASC",
            (ApprovalStatus.PENDING.value,),
        )
        return [_row_to_request(row) for row in rows]

    async def recent(self, limit: int = 50) -> Sequence[ApprovalRequest]:
        rows = await self.database.fetch_all(
            f"SELECT {_COLUMNS} FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        return [_row_to_request(row) for row in rows]

    async def expire_overdue(self, now: datetime | None = None) -> int:
        """Mark every pending request past its deadline as expired.

        Timeout is enforced here, in the database, rather than only by whoever
        is waiting. A call abandoned by its client still resolves to expired,
        so the queue does not fill with rows that stay pending forever.
        """
        moment = (now or datetime.now(UTC)).isoformat()

        def work(connection: sqlite3.Connection) -> int:
            cursor = connection.execute(
                "UPDATE approvals SET status = ?, decided_at = ?, approver = ? "
                "WHERE status = ? AND expires_at <= ?",
                (
                    ApprovalStatus.EXPIRED.value,
                    moment,
                    TIMEOUT_APPROVER,
                    ApprovalStatus.PENDING.value,
                    moment,
                ),
            )
            return cursor.rowcount

        return int(await self.database.transact(work))
