"""Integration tests for the proxy: aggregation, forwarding, and enforcement.

These run against a real MCP server over a real client, so what is exercised
is the production path rather than a stand-in for it.
"""

from __future__ import annotations

import json

import pytest
from mcp import types

from mcp_gatekeeper.audit.models import Outcome
from mcp_gatekeeper.policy.models import Action, ArgumentCondition, Rule, RuleCondition
from mcp_gatekeeper.proxy.registry import namespace, split_namespace

from .conftest import GatewayFactory

ALLOW_ALL = (Rule(tool="*", action=Action.ALLOW),)


def text_of(result: types.CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    return block.text


class TestNamespacing:
    def test_round_trip(self) -> None:
        assert split_namespace(namespace("fs", "write_file")) == ("fs", "write_file")

    def test_tool_name_containing_the_separator_survives(self) -> None:
        # Splits on the FIRST separator, so the upstream's own '__' is kept.
        assert split_namespace(namespace("fs", "odd__name")) == ("fs", "odd__name")

    @pytest.mark.parametrize("name", ["nonamespace", "__leading", "trailing__", "__"])
    def test_unnamespaced_names_are_rejected(self, name: str) -> None:
        assert split_namespace(name) is None


class TestToolAggregation:
    async def test_tools_are_namespaced(self, gateways: GatewayFactory) -> None:
        async with gateways.build(ALLOW_ALL) as gateway:
            names = [tool.name for tool in await gateway.list_tools()]
            assert "fake__read_file" in names
            assert "fake__write_file" in names

    async def test_listing_is_deterministic(self, gateways: GatewayFactory) -> None:
        # The spec asks for a stable order so clients can cache it.
        async with gateways.build(ALLOW_ALL) as gateway:
            first = [tool.name for tool in await gateway.list_tools()]
            second = [tool.name for tool in await gateway.list_tools()]
            assert first == second == sorted(first)

    async def test_schemas_and_annotations_survive(self, gateways: GatewayFactory) -> None:
        async with gateways.build(ALLOW_ALL) as gateway:
            tools = {tool.name: tool for tool in await gateway.list_tools()}

            write = tools["fake__write_file"]
            assert write.input_schema["properties"]["path"]["type"] == "string"
            assert write.annotations is not None
            assert write.annotations.destructive_hint is True
            assert write.description == "Write a file."

    async def test_tool_whose_name_contains_the_separator(self, gateways: GatewayFactory) -> None:
        async with gateways.build(ALLOW_ALL) as gateway:
            names = [tool.name for tool in await gateway.list_tools()]
            assert "fake__odd__name" in names

            result = await gateway.call_tool("fake__odd__name", {})
            assert isinstance(result, types.CallToolResult)
            # Proof it reached the upstream under its original name.
            assert json.loads(text_of(result))["tool"] == "odd__name"


class TestAllow:
    async def test_call_is_forwarded(self, gateways: GatewayFactory) -> None:
        async with gateways.build(ALLOW_ALL) as gateway:
            result = await gateway.call_tool("fake__read_file", {"path": "/data/x"})

            assert isinstance(result, types.CallToolResult)
            assert not result.is_error
            payload = json.loads(text_of(result))
            assert payload == {"tool": "read_file", "arguments": {"path": "/data/x"}}

    async def test_upstream_tool_error_is_passed_through(self, gateways: GatewayFactory) -> None:
        async with gateways.build(ALLOW_ALL) as gateway:
            result = await gateway.call_tool("fake__explode", {})

            assert isinstance(result, types.CallToolResult)
            assert result.is_error
            assert "upstream tool failed" in text_of(result)


class TestDeny:
    async def test_denied_call_is_not_forwarded(self, gateways: GatewayFactory) -> None:
        async with gateways.build(
            (Rule(tool="fake__write_file", action=Action.DENY, reason="no writes"),),
            default=Action.ALLOW,
        ) as gateway:
            result = await gateway.call_tool("fake__write_file", {"path": "/x"})

            assert isinstance(result, types.CallToolResult)
            assert result.is_error
            message = text_of(result)
            assert "no writes" in message
            # The model is told why, so it can adapt rather than retry blindly.
            assert "not forwarded" in message

    async def test_argument_rule_denies_only_matching_calls(self, gateways: GatewayFactory) -> None:
        async with gateways.build(
            (
                Rule(
                    tool="fake__write_file",
                    action=Action.DENY,
                    reason="production is off limits",
                    condition=RuleCondition(
                        arguments=(ArgumentCondition(path="path", pattern="/prod/**"),)
                    ),
                ),
                Rule(tool="*", action=Action.ALLOW),
            ),
            default=Action.DENY,
        ) as gateway:
            blocked = await gateway.call_tool("fake__write_file", {"path": "/prod/db.yaml"})
            assert isinstance(blocked, types.CallToolResult)
            assert blocked.is_error

            permitted = await gateway.call_tool("fake__write_file", {"path": "/tmp/db.yaml"})
            assert isinstance(permitted, types.CallToolResult)
            assert not permitted.is_error

    async def test_annotation_rule_catches_an_unnamed_tool(self, gateways: GatewayFactory) -> None:
        # No rule names delete_everything; it is caught on its own hint.
        async with gateways.build(
            (
                Rule(
                    tool="*",
                    action=Action.DENY,
                    reason="destructive",
                    condition=RuleCondition(destructive=True),
                ),
            ),
            default=Action.ALLOW,
        ) as gateway:
            blocked = await gateway.call_tool("fake__delete_everything", {})
            assert isinstance(blocked, types.CallToolResult)
            assert blocked.is_error

            # The unannotated tool is untouched by that rule.
            allowed = await gateway.call_tool("fake__mystery", {})
            assert isinstance(allowed, types.CallToolResult)
            assert not allowed.is_error


class TestUnknownTool:
    async def test_unknown_tool_is_refused(self, gateways: GatewayFactory) -> None:
        async with gateways.build(ALLOW_ALL) as gateway:
            result = await gateway.call_tool("fake__not_a_tool", {})

            assert isinstance(result, types.CallToolResult)
            assert result.is_error
            assert "Unknown tool" in text_of(result)

    async def test_unknown_tool_is_audited(
        self, gateways: GatewayFactory, audit_store: object
    ) -> None:
        from mcp_gatekeeper.audit.store import SqliteAuditStore

        assert isinstance(audit_store, SqliteAuditStore)
        async with gateways.build(ALLOW_ALL) as gateway:
            await gateway.call_tool("fake__not_a_tool", {})

            events = await audit_store.recent()
            assert events[0].outcome is Outcome.UNKNOWN_TOOL


class TestUpstreamFailure:
    async def test_call_to_disconnected_upstream_is_reported(
        self, gateways: GatewayFactory
    ) -> None:
        async with gateways.build(ALLOW_ALL) as gateway:
            gateway.deps.upstreams.connections.clear()

            result = await gateway.call_tool("fake__read_file", {"path": "/x"})
            assert isinstance(result, types.CallToolResult)
            assert result.is_error
            assert "not connected" in text_of(result)
