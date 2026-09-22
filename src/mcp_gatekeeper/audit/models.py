"""Audit record types and argument redaction."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, cast

from mcp_gatekeeper.policy.glob import match_path
from mcp_gatekeeper.policy.models import Action, Decision

__all__ = ["REDACTED", "AuditEvent", "Outcome", "ResultStatus", "redact_arguments"]

REDACTED = "[redacted]"


class Outcome(StrEnum):
    """What ultimately happened to the call."""

    FORWARDED = "forwarded"
    DENIED_BY_POLICY = "denied_by_policy"
    DENIED_BY_APPROVER = "denied_by_approver"
    TIMED_OUT = "timed_out"
    AWAITING_APPROVAL = "awaiting_approval"
    ERROR = "error"
    UNKNOWN_TOOL = "unknown_tool"


class ResultStatus(StrEnum):
    OK = "ok"
    ERROR = "error"


def redact_arguments(arguments: Mapping[str, object], patterns: Sequence[str]) -> dict[str, object]:
    """Mask configured argument paths before anything is persisted.

    Redaction happens here, on the way in, rather than on the way out to a
    viewer: a secret that never reaches disk cannot leak from the database, a
    backup of it, or a JSONL export.

    Patterns are globs over dotted key paths, where a dot is a level boundary:

    * ``token`` -- a top-level key
    * ``auth.token`` -- that exact nested key
    * ``*.token`` -- ``token`` one level down, whatever the parent
    * ``credentials.**`` -- ``credentials`` and everything beneath it

    Levels are matched with the same globber the policy engine uses, which
    treats ``/`` as its boundary, so paths are joined with ``/`` internally and
    dots in patterns are translated to match. That keeps ``*`` meaning "one
    level" here just as it does in a policy rule.
    """
    if not patterns:
        return dict(arguments)

    translated = [pattern.replace(".", "/") for pattern in patterns]

    def redact(value: object, prefix: str) -> object:
        if prefix and any(match_path(pattern, prefix) for pattern in translated):
            return REDACTED
        if isinstance(value, Mapping):
            mapping = cast("Mapping[Any, Any]", value)
            return {
                str(key): redact(item, f"{prefix}/{key}" if prefix else str(key))
                for key, item in mapping.items()
            }
        if isinstance(value, list):
            items = cast("list[Any]", value)
            return [redact(item, f"{prefix}/{index}") for index, item in enumerate(items)]
        return value

    result = redact(dict(arguments), "")
    return cast("dict[str, object]", result) if isinstance(result, dict) else {}


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One governed tool call, start to finish."""

    event_id: str
    created_at: datetime
    tool: str
    upstream: str
    arguments: Mapping[str, Any]
    action: Action
    decision_source: str
    outcome: Outcome
    decision_reason: str | None = None
    rule_index: int | None = None
    approval_id: str | None = None
    approver: str | None = None
    latency_ms: float | None = None
    result_status: ResultStatus | None = None
    client_name: str | None = None
    error: str | None = None

    @classmethod
    def build(
        cls,
        *,
        event_id: str,
        tool: str,
        upstream: str,
        arguments: Mapping[str, object],
        decision: Decision,
        outcome: Outcome,
        redact: Sequence[str] = (),
        **extra: Any,
    ) -> AuditEvent:
        return cls(
            event_id=event_id,
            created_at=datetime.now(UTC),
            tool=tool,
            upstream=upstream,
            arguments=redact_arguments(arguments, redact),
            action=decision.action,
            decision_source=decision.source,
            decision_reason=decision.reason,
            rule_index=decision.rule_index,
            outcome=outcome,
            **extra,
        )

    def to_json(self) -> dict[str, Any]:
        """Render for JSONL export."""
        return {
            "event_id": self.event_id,
            "timestamp": self.created_at.isoformat(),
            "tool": self.tool,
            "upstream": self.upstream,
            "arguments": self.arguments,
            "action": self.action.value,
            "decision": {
                "source": self.decision_source,
                "reason": self.decision_reason,
                "rule_index": self.rule_index,
            },
            "outcome": self.outcome.value,
            "approval": {"id": self.approval_id, "approver": self.approver},
            "latency_ms": self.latency_ms,
            "result_status": self.result_status.value if self.result_status else None,
            "client": self.client_name,
            "error": self.error,
        }

    def to_jsonl(self) -> str:
        return json.dumps(self.to_json(), sort_keys=True, default=str)
