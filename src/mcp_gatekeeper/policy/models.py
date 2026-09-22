"""Value types for policy evaluation.

Everything here is frozen and free of I/O. The engine turns a
:class:`PolicyRequest` plus a :class:`Policy` into a :class:`Decision`, and
nothing in that path touches a clock, a socket, or a database.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Literal

__all__ = [
    "Action",
    "AnnotationView",
    "ArgumentCondition",
    "Decision",
    "Policy",
    "PolicyRequest",
    "Rule",
    "RuleCondition",
]


_NO_ARGUMENTS: Mapping[str, object] = MappingProxyType({})
"""Shared empty mapping; safe as a default because it cannot be mutated."""


class Action(StrEnum):
    """What the gatekeeper does with a call."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class AnnotationView:
    """The upstream tool's self-declared behaviour hints.

    These let policy key off what a tool *does* rather than only what it is
    called, so a destructive tool added upstream after the rules were written
    is still caught. Every field is optional because hints are advisory: an
    upstream may omit them, and ``None`` means "not stated", never "false".
    """

    read_only: bool | None = None
    destructive: bool | None = None
    idempotent: bool | None = None
    open_world: bool | None = None


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """A single tool call, as the policy engine sees it."""

    tool: str
    """Namespaced tool name, e.g. ``fs__write_file``."""

    upstream: str
    """Name of the upstream server the tool came from."""

    arguments: Mapping[str, object] = _NO_ARGUMENTS
    annotations: AnnotationView = field(default_factory=AnnotationView)


@dataclass(frozen=True, slots=True)
class ArgumentCondition:
    """Requires the argument at ``path`` to glob-match ``pattern``.

    ``path`` is dotted and may index into nested objects, e.g.
    ``options.target``. A missing argument never matches.
    """

    path: str
    pattern: str


@dataclass(frozen=True, slots=True)
class RuleCondition:
    """Extra requirements beyond the tool-name match.

    All present conditions must hold (AND). An empty condition matches any
    request whose tool name matched.
    """

    arguments: Sequence[ArgumentCondition] = ()
    read_only: bool | None = None
    destructive: bool | None = None
    idempotent: bool | None = None
    open_world: bool | None = None

    def is_empty(self) -> bool:
        return (
            not self.arguments
            and self.read_only is None
            and self.destructive is None
            and self.idempotent is None
            and self.open_world is None
        )


@dataclass(frozen=True, slots=True)
class Rule:
    """One line of policy: match a tool (and optionally its arguments), act."""

    tool: str
    action: Action
    condition: RuleCondition = field(default_factory=RuleCondition)
    reason: str | None = None
    upstream: str | None = None
    """Restrict the rule to one upstream. ``None`` means any."""


@dataclass(frozen=True, slots=True)
class Policy:
    """An ordered rule list plus the fallback for unmatched calls."""

    rules: Sequence[Rule] = ()
    default: Action = Action.REQUIRE_APPROVAL
    default_reason: str | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of evaluating a request, with enough detail to audit it."""

    action: Action
    source: Literal["rule", "default"]
    reason: str | None = None
    rule_index: int | None = None
    """Position of the matched rule in ``Policy.rules``; ``None`` for the default."""

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    def describe(self) -> str:
        """A short human-readable explanation, used in audit rows and denials."""
        where = f"rule #{self.rule_index}" if self.source == "rule" else "default policy"
        return (
            f"{self.action.value} ({where}): {self.reason}"
            if self.reason
            else f"{self.action.value} ({where})"
        )
