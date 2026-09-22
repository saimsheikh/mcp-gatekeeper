"""Persistence for audit events."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from mcp_gatekeeper.audit.models import AuditEvent, Outcome, ResultStatus
from mcp_gatekeeper.db import Database
from mcp_gatekeeper.policy.models import Action

__all__ = ["AuditStore", "NullAuditStore", "SqliteAuditStore"]

_COLUMNS = (
    "event_id, created_at, tool, upstream, arguments, action, decision_source, "
    "decision_reason, rule_index, outcome, approval_id, approver, latency_ms, "
    "result_status, client_name, error"
)


class AuditStore(Protocol):
    """Where governed calls are recorded."""

    async def record(self, event: AuditEvent) -> None: ...

    async def recent(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        tool: str | None = None,
        action: Action | None = None,
    ) -> Sequence[AuditEvent]: ...

    async def count(self) -> int: ...


@dataclass
class NullAuditStore:
    """Drops everything. Used when auditing is switched off in config."""

    async def record(self, event: AuditEvent) -> None:
        return None

    async def recent(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        tool: str | None = None,
        action: Action | None = None,
    ) -> Sequence[AuditEvent]:
        return []

    async def count(self) -> int:
        return 0


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    raw_status = row["result_status"]
    return AuditEvent(
        event_id=row["event_id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        tool=row["tool"],
        upstream=row["upstream"],
        arguments=json.loads(row["arguments"]),
        action=Action(row["action"]),
        decision_source=row["decision_source"],
        decision_reason=row["decision_reason"],
        rule_index=row["rule_index"],
        outcome=Outcome(row["outcome"]),
        approval_id=row["approval_id"],
        approver=row["approver"],
        latency_ms=row["latency_ms"],
        result_status=ResultStatus(raw_status) if raw_status else None,
        client_name=row["client_name"],
        error=row["error"],
    )


@dataclass
class SqliteAuditStore:
    """Writes the audit trail to SQLite."""

    database: Database

    async def record(self, event: AuditEvent) -> None:
        await self.database.execute(
            f"INSERT OR REPLACE INTO audit_events ({_COLUMNS}) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.created_at.isoformat(),
                event.tool,
                event.upstream,
                json.dumps(event.arguments, sort_keys=True, default=str),
                event.action.value,
                event.decision_source,
                event.decision_reason,
                event.rule_index,
                event.outcome.value,
                event.approval_id,
                event.approver,
                event.latency_ms,
                event.result_status.value if event.result_status else None,
                event.client_name,
                event.error,
            ),
        )

    async def recent(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        tool: str | None = None,
        action: Action | None = None,
    ) -> Sequence[AuditEvent]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if tool:
            clauses.append("tool LIKE ?")
            parameters.append(f"%{tool}%")
        if action:
            clauses.append("action = ?")
            parameters.append(action.value)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.extend([limit, offset])
        rows = await self.database.fetch_all(
            f"SELECT {_COLUMNS} FROM audit_events {where} "
            "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            parameters,
        )
        return [_row_to_event(row) for row in rows]

    async def count(self) -> int:
        row = await self.database.fetch_one("SELECT COUNT(*) AS total FROM audit_events")
        return int(row["total"]) if row else 0

    async def export_jsonl(self) -> AsyncIterator[str]:
        """Stream the whole log oldest-first, one JSON object per line.

        Oldest-first so an export reads as a chronological narrative and can be
        appended to by a later export without reordering.
        """
        rows = await self.database.fetch_all(
            f"SELECT {_COLUMNS} FROM audit_events ORDER BY created_at ASC, id ASC"
        )
        for row in rows:
            yield _row_to_event(row).to_jsonl()
