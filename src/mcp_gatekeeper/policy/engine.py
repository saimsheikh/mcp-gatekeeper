"""Policy evaluation. Pure functions only -- no I/O, no clock, no globals.

Rules are evaluated top to bottom and the first match wins. That is the whole
algorithm, and it is deliberate: "most specific wins" needs a specificity
metric that nobody can predict once patterns overlap, whereas an ordered list
can be read top to bottom and reasoned about locally.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from mcp_gatekeeper.policy.glob import canonical_value, match_path, match_tool
from mcp_gatekeeper.policy.models import (
    AnnotationView,
    ArgumentCondition,
    Decision,
    Policy,
    PolicyRequest,
    Rule,
    RuleCondition,
)

__all__ = ["evaluate", "resolve_argument"]


def resolve_argument(arguments: Mapping[str, object], path: str) -> object | None:
    """Look up a dotted ``path`` in a nested argument mapping.

    Returns ``None`` when any segment is missing or a non-object is traversed.
    A literal ``None`` argument value is indistinguishable from absent here;
    :func:`_argument_matches` treats both as "no match", so a rule can never
    fire on an argument the caller did not send.
    """
    current: object = arguments
    for segment in path.split("."):
        if not isinstance(current, Mapping):
            return None
        mapping = cast("Mapping[str, Any]", current)
        if segment not in mapping:
            return None
        current = mapping[segment]
    return current


def _argument_matches(arguments: Mapping[str, object], condition: ArgumentCondition) -> bool:
    value = resolve_argument(arguments, condition.path)
    if value is None:
        return False
    rendered = canonical_value(value)
    if rendered is None:
        # Lists and objects have no sensible glob representation.
        return False
    return match_path(condition.pattern, rendered)


def _annotations_match(view: AnnotationView, condition: RuleCondition) -> bool:
    """Check the annotation hints the rule asked about.

    A hint the upstream did not state is ``None`` and never satisfies a
    condition. Requiring ``destructive: true`` therefore does not fire on a
    tool that merely failed to declare itself, which keeps an unannotated
    upstream from silently widening a rule's reach.
    """
    wanted = (
        (condition.read_only, view.read_only),
        (condition.destructive, view.destructive),
        (condition.idempotent, view.idempotent),
        (condition.open_world, view.open_world),
    )
    return all(expected is None or actual is expected for expected, actual in wanted)


def _rule_matches(rule: Rule, request: PolicyRequest) -> bool:
    if rule.upstream is not None and rule.upstream != request.upstream:
        return False
    if not match_tool(rule.tool, request.tool):
        return False

    condition = rule.condition
    if condition.is_empty():
        return True
    if not _annotations_match(request.annotations, condition):
        return False
    return all(_argument_matches(request.arguments, arg) for arg in condition.arguments)


def evaluate(request: PolicyRequest, policy: Policy) -> Decision:
    """Decide what to do with ``request``.

    The first matching rule wins. When nothing matches, the policy default
    applies -- which is ``require_approval`` unless configured otherwise, so
    an unrecognised tool stops for a human rather than sailing through.
    """
    for index, rule in enumerate(policy.rules):
        if _rule_matches(rule, request):
            return Decision(
                action=rule.action,
                source="rule",
                reason=rule.reason,
                rule_index=index,
            )

    return Decision(
        action=policy.default,
        source="default",
        reason=policy.default_reason,
        rule_index=None,
    )
