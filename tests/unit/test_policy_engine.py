"""Tests for policy evaluation.

Covers first-match-wins ordering, argument conditions, annotation conditions,
the default fallback, and the fail-safe behaviours that make an unannotated or
malformed call stop for a human instead of sailing through.
"""

from __future__ import annotations

import pytest

from mcp_gatekeeper.policy.engine import evaluate, resolve_argument
from mcp_gatekeeper.policy.models import (
    Action,
    AnnotationView,
    ArgumentCondition,
    Policy,
    PolicyRequest,
    Rule,
    RuleCondition,
)


def request(
    tool: str = "fs__write_file",
    *,
    upstream: str = "fs",
    arguments: dict[str, object] | None = None,
    annotations: AnnotationView | None = None,
) -> PolicyRequest:
    return PolicyRequest(
        tool=tool,
        upstream=upstream,
        arguments=arguments or {},
        annotations=annotations or AnnotationView(),
    )


class TestDefaults:
    def test_empty_policy_requires_approval(self) -> None:
        decision = evaluate(request(), Policy())
        assert decision.action is Action.REQUIRE_APPROVAL
        assert decision.source == "default"
        assert decision.rule_index is None

    def test_unmatched_call_falls_through_to_the_default(self) -> None:
        policy = Policy(rules=(Rule(tool="github__*", action=Action.ALLOW),))
        assert evaluate(request("fs__write_file"), policy).source == "default"

    @pytest.mark.parametrize("action", list(Action))
    def test_default_is_configurable(self, action: Action) -> None:
        assert evaluate(request(), Policy(default=action)).action is action

    def test_default_reason_is_carried_through(self) -> None:
        policy = Policy(default=Action.DENY, default_reason="not on the allowlist")
        assert evaluate(request(), policy).reason == "not on the allowlist"


class TestOrdering:
    def test_first_match_wins(self) -> None:
        policy = Policy(
            rules=(
                Rule(tool="fs__*", action=Action.ALLOW),
                Rule(tool="fs__write_file", action=Action.DENY),
            )
        )
        decision = evaluate(request("fs__write_file"), policy)
        assert decision.action is Action.ALLOW
        assert decision.rule_index == 0

    def test_order_is_what_distinguishes_the_two_policies(self) -> None:
        specific = Rule(tool="fs__write_file", action=Action.DENY)
        broad = Rule(tool="fs__*", action=Action.ALLOW)

        assert evaluate(request(), Policy(rules=(specific, broad))).action is Action.DENY
        assert evaluate(request(), Policy(rules=(broad, specific))).action is Action.ALLOW

    def test_reports_the_index_of_the_matched_rule(self) -> None:
        policy = Policy(
            rules=(
                Rule(tool="a__x", action=Action.ALLOW),
                Rule(tool="b__x", action=Action.ALLOW),
                Rule(tool="fs__write_file", action=Action.DENY),
            )
        )
        assert evaluate(request(), policy).rule_index == 2


class TestUpstreamScoping:
    def test_rule_can_be_pinned_to_one_upstream(self) -> None:
        policy = Policy(rules=(Rule(tool="*", action=Action.ALLOW, upstream="fs"),))
        assert evaluate(request(upstream="fs"), policy).action is Action.ALLOW
        assert evaluate(request(upstream="github"), policy).source == "default"

    def test_unpinned_rule_matches_any_upstream(self) -> None:
        policy = Policy(rules=(Rule(tool="*", action=Action.ALLOW),))
        assert evaluate(request(upstream="anything"), policy).action is Action.ALLOW


class TestArgumentConditions:
    def _policy(self, path: str, pattern: str) -> Policy:
        return Policy(
            rules=(
                Rule(
                    tool="fs__write_file",
                    action=Action.DENY,
                    condition=RuleCondition(
                        arguments=(ArgumentCondition(path=path, pattern=pattern),)
                    ),
                ),
            )
        )

    def test_matching_argument_fires_the_rule(self) -> None:
        policy = self._policy("path", "/prod/**")
        decision = evaluate(request(arguments={"path": "/prod/db.yaml"}), policy)
        assert decision.action is Action.DENY

    def test_non_matching_argument_falls_through(self) -> None:
        policy = self._policy("path", "/prod/**")
        decision = evaluate(request(arguments={"path": "/tmp/scratch"}), policy)
        assert decision.source == "default"

    def test_absent_argument_never_matches(self) -> None:
        policy = self._policy("path", "**")
        assert evaluate(request(arguments={}), policy).source == "default"

    def test_null_argument_never_matches(self) -> None:
        # Explicit null and absent are treated alike: a rule must not fire on
        # an argument the caller did not meaningfully supply.
        policy = self._policy("path", "**")
        assert evaluate(request(arguments={"path": None}), policy).source == "default"

    def test_nested_argument_path(self) -> None:
        policy = self._policy("options.target", "/prod/**")
        decision = evaluate(request(arguments={"options": {"target": "/prod/x"}}), policy)
        assert decision.action is Action.DENY

    def test_all_argument_conditions_must_match(self) -> None:
        policy = Policy(
            rules=(
                Rule(
                    tool="*",
                    action=Action.DENY,
                    condition=RuleCondition(
                        arguments=(
                            ArgumentCondition(path="path", pattern="/prod/**"),
                            ArgumentCondition(path="mode", pattern="write"),
                        )
                    ),
                ),
            )
        )
        both = request(arguments={"path": "/prod/x", "mode": "write"})
        one = request(arguments={"path": "/prod/x", "mode": "read"})

        assert evaluate(both, policy).action is Action.DENY
        assert evaluate(one, policy).source == "default"

    def test_container_argument_is_unmatchable(self) -> None:
        policy = self._policy("paths", "**")
        assert evaluate(request(arguments={"paths": ["/prod/a"]}), policy).source == "default"

    def test_boolean_argument_matches_json_spelling(self) -> None:
        policy = self._policy("recursive", "true")
        assert evaluate(request(arguments={"recursive": True}), policy).action is Action.DENY

    def test_numeric_argument_matches(self) -> None:
        policy = self._policy("limit", "1*")
        assert evaluate(request(arguments={"limit": 100}), policy).action is Action.DENY


class TestAnnotationConditions:
    def _policy(
        self,
        *,
        read_only: bool | None = None,
        destructive: bool | None = None,
    ) -> Policy:
        return Policy(
            rules=(
                Rule(
                    tool="*",
                    action=Action.REQUIRE_APPROVAL,
                    condition=RuleCondition(read_only=read_only, destructive=destructive),
                ),
            ),
            default=Action.ALLOW,
        )

    def test_matches_a_declared_hint(self) -> None:
        policy = self._policy(destructive=True)
        decision = evaluate(request(annotations=AnnotationView(destructive=True)), policy)
        assert decision.action is Action.REQUIRE_APPROVAL

    def test_does_not_match_the_opposite_hint(self) -> None:
        policy = self._policy(destructive=True)
        decision = evaluate(request(annotations=AnnotationView(destructive=False)), policy)
        assert decision.action is Action.ALLOW

    def test_undeclared_hint_does_not_satisfy_a_condition(self) -> None:
        # An upstream that simply omits annotations must not widen a rule's
        # reach; 'None' means "not stated", never "false".
        policy = self._policy(destructive=True)
        assert evaluate(request(annotations=AnnotationView()), policy).action is Action.ALLOW

    def test_condition_on_false_matches_an_explicit_false(self) -> None:
        policy = self._policy(read_only=False)
        decision = evaluate(request(annotations=AnnotationView(read_only=False)), policy)
        assert decision.action is Action.REQUIRE_APPROVAL

    def test_all_hint_conditions_must_match(self) -> None:
        policy = self._policy(destructive=True, read_only=False)
        partial = AnnotationView(destructive=True)
        full = AnnotationView(destructive=True, read_only=False)

        assert evaluate(request(annotations=partial), policy).action is Action.ALLOW
        assert evaluate(request(annotations=full), policy).action is Action.REQUIRE_APPROVAL

    def test_argument_and_annotation_conditions_combine(self) -> None:
        policy = Policy(
            rules=(
                Rule(
                    tool="*",
                    action=Action.DENY,
                    condition=RuleCondition(
                        arguments=(ArgumentCondition(path="path", pattern="/prod/**"),),
                        destructive=True,
                    ),
                ),
            ),
            default=Action.ALLOW,
        )
        destructive = AnnotationView(destructive=True)

        matched = request(arguments={"path": "/prod/x"}, annotations=destructive)
        wrong_path = request(arguments={"path": "/tmp/x"}, annotations=destructive)
        no_hint = request(arguments={"path": "/prod/x"})

        assert evaluate(matched, policy).action is Action.DENY
        assert evaluate(wrong_path, policy).action is Action.ALLOW
        assert evaluate(no_hint, policy).action is Action.ALLOW


class TestResolveArgument:
    @pytest.mark.parametrize(
        ("arguments", "path", "expected"),
        [
            ({"a": 1}, "a", 1),
            ({"a": {"b": 2}}, "a.b", 2),
            ({"a": {"b": {"c": 3}}}, "a.b.c", 3),
            ({"a": 1}, "missing", None),
            ({"a": {"b": 1}}, "a.missing", None),
            ({"a": 1}, "a.b", None),
            ({}, "a", None),
            ({"a": [1, 2]}, "a.0", None),
        ],
    )
    def test_lookup(self, arguments: dict[str, object], path: str, expected: object) -> None:
        assert resolve_argument(arguments, path) == expected

    def test_dotted_key_is_not_confused_with_nesting(self) -> None:
        # A literal key containing a dot is not reachable; nesting wins. This
        # is a documented limitation of the dotted-path syntax.
        assert resolve_argument({"a.b": 1}, "a.b") is None


class TestDecisionReporting:
    def test_describe_names_the_matched_rule(self) -> None:
        policy = Policy(rules=(Rule(tool="*", action=Action.DENY, reason="blocked"),))
        assert evaluate(request(), policy).describe() == "deny (rule #0): blocked"

    def test_describe_without_a_reason(self) -> None:
        policy = Policy(rules=(Rule(tool="*", action=Action.DENY),))
        assert evaluate(request(), policy).describe() == "deny (rule #0)"

    def test_describe_names_the_default(self) -> None:
        assert evaluate(request(), Policy()).describe() == "require_approval (default policy)"

    def test_allowed_property(self) -> None:
        allow = Policy(rules=(Rule(tool="*", action=Action.ALLOW),))
        assert evaluate(request(), allow).allowed
        assert not evaluate(request(), Policy()).allowed


class TestPurity:
    def test_evaluation_does_not_mutate_its_inputs(self) -> None:
        arguments: dict[str, object] = {"path": "/prod/db.yaml"}
        policy = Policy(
            rules=(
                Rule(
                    tool="*",
                    action=Action.DENY,
                    condition=RuleCondition(
                        arguments=(ArgumentCondition(path="path", pattern="/prod/**"),)
                    ),
                ),
            )
        )
        evaluate(request(arguments=arguments), policy)
        assert arguments == {"path": "/prod/db.yaml"}

    def test_evaluation_is_deterministic(self) -> None:
        policy = Policy(rules=(Rule(tool="fs__*", action=Action.ALLOW),))
        subject = request()
        first = evaluate(subject, policy)
        assert all(evaluate(subject, policy) == first for _ in range(5))
