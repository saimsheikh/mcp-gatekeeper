"""Tests for audit records and argument redaction.

Redaction is the security-sensitive part: it runs before anything is written,
so a secret that matches a pattern never reaches the database, a backup of it,
or an export.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_gatekeeper.audit.models import (
    REDACTED,
    AuditEvent,
    Outcome,
    ResultStatus,
    redact_arguments,
)
from mcp_gatekeeper.policy.models import Action, Decision


class TestRedaction:
    def test_no_patterns_passes_everything_through(self) -> None:
        arguments = {"path": "/x", "token": "secret"}
        assert redact_arguments(arguments, []) == arguments

    def test_exact_path_is_masked(self) -> None:
        result = redact_arguments({"token": "secret", "path": "/x"}, ["token"])
        assert result == {"token": REDACTED, "path": "/x"}

    def test_nested_path_is_masked(self) -> None:
        result = redact_arguments({"auth": {"token": "secret", "user": "amy"}}, ["auth.token"])
        assert result == {"auth": {"token": REDACTED, "user": "amy"}}

    def test_wildcard_matches_any_leaf_key(self) -> None:
        result = redact_arguments({"auth": {"token": "a"}, "other": {"token": "b"}}, ["*.token"])
        assert result == {"auth": {"token": REDACTED}, "other": {"token": REDACTED}}

    def test_double_star_masks_a_whole_subtree(self) -> None:
        result = redact_arguments(
            {"credentials": {"user": "amy", "nested": {"key": "k"}}, "path": "/x"},
            ["credentials.**"],
        )
        # A trailing '**' covers the parent itself, so the whole subtree goes.
        assert result == {"credentials": REDACTED, "path": "/x"}

    def test_single_star_matches_exactly_one_level(self) -> None:
        result = redact_arguments(
            {"auth": {"token": "a"}, "deep": {"nested": {"token": "b"}}}, ["*.token"]
        )
        assert result["auth"] == {"token": REDACTED}
        # Two levels down is not one level down.
        assert result["deep"] == {"nested": {"token": "b"}}

    def test_leading_double_star_matches_any_depth(self) -> None:
        result = redact_arguments(
            {"auth": {"token": "a"}, "deep": {"nested": {"token": "b"}}}, ["**.token"]
        )
        assert result["auth"] == {"token": REDACTED}
        assert result["deep"] == {"nested": {"token": REDACTED}}

    def test_subtree_redaction_with_dotted_pattern(self) -> None:
        result = redact_arguments(
            {"credentials": {"user": "amy", "key": "k"}, "path": "/x"}, ["credentials"]
        )
        # Masking the parent masks everything beneath it.
        assert result == {"credentials": REDACTED, "path": "/x"}

    def test_list_items_are_reachable_by_index(self) -> None:
        result = redact_arguments({"items": ["a", "b"]}, ["items.1"])
        assert result == {"items": ["a", REDACTED]}

    def test_non_matching_pattern_changes_nothing(self) -> None:
        arguments = {"path": "/x"}
        assert redact_arguments(arguments, ["token"]) == arguments

    def test_original_arguments_are_not_mutated(self) -> None:
        arguments: dict[str, Any] = {"auth": {"token": "secret"}}
        redact_arguments(arguments, ["auth.token"])
        assert arguments == {"auth": {"token": "secret"}}

    def test_non_string_values_are_masked_too(self) -> None:
        result = redact_arguments({"pin": 1234}, ["pin"])
        assert result == {"pin": REDACTED}


def build_event(**overrides: Any) -> AuditEvent:
    defaults: dict[str, Any] = {
        "event_id": "abc",
        "tool": "fs__write_file",
        "upstream": "fs",
        "arguments": {"path": "/prod/db.yaml"},
        "decision": Decision(action=Action.DENY, source="rule", reason="nope", rule_index=2),
        "outcome": Outcome.DENIED_BY_POLICY,
    }
    return AuditEvent.build(**{**defaults, **overrides})


class TestAuditEvent:
    def test_carries_the_decision(self) -> None:
        event = build_event()
        assert event.action is Action.DENY
        assert event.decision_source == "rule"
        assert event.rule_index == 2
        assert event.decision_reason == "nope"

    def test_applies_redaction_on_build(self) -> None:
        event = build_event(arguments={"token": "secret"}, redact=["token"])
        assert event.arguments == {"token": REDACTED}

    def test_timestamp_is_timezone_aware(self) -> None:
        # Naive timestamps in an audit trail are ambiguous across hosts.
        assert build_event().created_at.tzinfo is not None

    def test_jsonl_round_trips(self) -> None:
        event = build_event(
            latency_ms=12.5, result_status=ResultStatus.ERROR, client_name="probe 1.0"
        )
        payload = json.loads(event.to_jsonl())

        assert payload["tool"] == "fs__write_file"
        assert payload["action"] == "deny"
        assert payload["outcome"] == "denied_by_policy"
        assert payload["decision"]["rule_index"] == 2
        assert payload["latency_ms"] == 12.5
        assert payload["result_status"] == "error"
        assert payload["client"] == "probe 1.0"

    def test_jsonl_is_a_single_line(self) -> None:
        assert "\n" not in build_event().to_jsonl()

    @pytest.mark.parametrize("outcome", list(Outcome))
    def test_every_outcome_serialises(self, outcome: Outcome) -> None:
        assert json.loads(build_event(outcome=outcome).to_jsonl())["outcome"] == outcome.value
