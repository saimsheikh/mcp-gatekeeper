"""Approval request types."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

__all__ = ["TIMEOUT_APPROVER", "ApprovalRequest", "ApprovalStatus"]

TIMEOUT_APPROVER = "system:timeout"
"""Recorded as the approver when a request expires, so the audit trail never
shows a decision without an actor."""

CLIENT_APPROVER = "system:client-dismissed"
"""Recorded when the requesting client came back without a human decision --
the prompt was dismissed, or it retried claiming one that was never made."""


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

    @property
    def is_resolved(self) -> bool:
        return self is not ApprovalStatus.PENDING

    @property
    def is_granted(self) -> bool:
        return self is ApprovalStatus.APPROVED


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """A tool call parked waiting for a human."""

    id: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    tool: str
    upstream: str
    arguments: Mapping[str, Any]
    reason: str | None = None
    client_name: str | None = None
    decided_at: datetime | None = None
    approver: str | None = None
    note: str | None = None

    def is_expired_at(self, now: datetime) -> bool:
        """Whether this request has outlived its window.

        Only meaningful while pending; a resolved request keeps its decision
        even if it is read back after the deadline.
        """
        return self.status is ApprovalStatus.PENDING and now >= self.expires_at

    def seconds_remaining(self, now: datetime) -> float:
        return max(0.0, (self.expires_at - now).total_seconds())
