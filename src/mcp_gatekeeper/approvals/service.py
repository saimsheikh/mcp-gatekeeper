"""The approval workflow.

Two shapes of waiting, one queue behind both:

* **Elicit** -- the handler returns immediately, handing the client a link.
  The client retries the call later and we look the decision up by id.
* **Block** -- the handler holds the call open until someone decides or the
  deadline passes.

Blocking waits wake on an in-process event as soon as the UI records a
decision, and fall back to polling so that a decision written by another
process (or a deadline nobody is watching) is still noticed.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio

from mcp_gatekeeper.approvals.models import TIMEOUT_APPROVER, ApprovalRequest, ApprovalStatus
from mcp_gatekeeper.approvals.store import SqliteApprovalStore

__all__ = ["POLL_INTERVAL_SECONDS", "ApprovalService"]

POLL_INTERVAL_SECONDS = 0.5


def new_approval_id() -> str:
    """Generate an unguessable approval id.

    v0.1 has no authentication on the approval UI, so the id is the only thing
    standing between a pending request and anyone who can reach the port. It is
    a capability, and sized accordingly.
    """
    return secrets.token_urlsafe(24)


@dataclass
class ApprovalService:
    """Creates, resolves, and waits on approval requests."""

    store: SqliteApprovalStore
    timeout_seconds: float = 300.0
    approve_on_timeout: bool = False
    """``on_timeout: allow``. Off by default: silence must not read as consent."""

    _events: dict[str, anyio.Event] = field(default_factory=dict[str, anyio.Event])

    async def open(
        self,
        *,
        tool: str,
        upstream: str,
        arguments: Mapping[str, Any],
        reason: str | None = None,
        client_name: str | None = None,
    ) -> ApprovalRequest:
        """Park a call and return its pending request."""
        now = datetime.now(UTC)
        request = ApprovalRequest(
            id=new_approval_id(),
            created_at=now,
            expires_at=now + timedelta(seconds=self.timeout_seconds),
            status=ApprovalStatus.PENDING,
            tool=tool,
            upstream=upstream,
            arguments=dict(arguments),
            reason=reason,
            client_name=client_name,
        )
        await self.store.create(request)
        self._events[request.id] = anyio.Event()
        return request

    async def decide(
        self, approval_id: str, *, approved: bool, approver: str, note: str | None = None
    ) -> ApprovalRequest | None:
        """Record a human decision and wake anyone blocked on it."""
        resolved = await self.store.resolve(
            approval_id, approved=approved, approver=approver, note=note
        )
        event = self._events.get(approval_id)
        if event is not None:
            event.set()
        return resolved

    async def get(self, approval_id: str) -> ApprovalRequest | None:
        """Read a request, settling it first if its deadline has passed.

        Callers resuming an elicited call go through here, so a request that
        timed out while the client was away is reported as expired rather than
        as still pending.
        """
        request = await self.store.get(approval_id)
        if request is None:
            return None
        if request.is_expired_at(datetime.now(UTC)):
            await self.store.expire_overdue()
            return await self.store.get(approval_id)
        return request

    async def wait(self, approval_id: str) -> ApprovalRequest | None:
        """Block until the request resolves or its deadline passes.

        Returns the settled request. A deadline reached while waiting produces
        an ``EXPIRED`` request unless ``approve_on_timeout`` is set, because a
        human who never answered has not consented.
        """
        request = await self.store.get(approval_id)
        if request is None:
            return None
        if request.status.is_resolved:
            return request

        event = self._events.setdefault(approval_id, anyio.Event())
        deadline = request.expires_at

        while True:
            remaining = (deadline - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                break

            with anyio.move_on_after(min(POLL_INTERVAL_SECONDS, remaining)):
                await event.wait()

            current = await self.store.get(approval_id)
            if current is None:
                return None
            if current.status.is_resolved:
                self._events.pop(approval_id, None)
                return current

        return await self._settle_timeout(approval_id)

    async def _settle_timeout(self, approval_id: str) -> ApprovalRequest | None:
        self._events.pop(approval_id, None)

        if self.approve_on_timeout:
            # Opt-in fail-open. Recorded with the system actor so the audit
            # trail distinguishes it from a human clicking approve.
            return await self.store.resolve(
                approval_id,
                approved=True,
                approver=TIMEOUT_APPROVER,
                note="auto-approved on timeout",
            )

        await self.store.expire_overdue()
        return await self.store.get(approval_id)

    async def pending(self) -> list[ApprovalRequest]:
        await self.store.expire_overdue()
        return list(await self.store.pending())
