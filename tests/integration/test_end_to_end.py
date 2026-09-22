"""End-to-end tests: a real MCP client talking to the real gatekeeper server.

Everything else mounts the gateway directly. These tests go through the MCP
server layer as well, which is the only way to prove the parts that depend on
the wire: per-request client capabilities arriving in ``_meta``, the
multi-round-trip retry the SDK performs on the client's behalf, and the
``tools/list`` cache hints.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import types
from mcp.client import Client

from mcp_gatekeeper.approvals.service import ApprovalService
from mcp_gatekeeper.approvals.store import SqliteApprovalStore
from mcp_gatekeeper.audit.store import SqliteAuditStore
from mcp_gatekeeper.db import Database
from mcp_gatekeeper.policy.models import Action, Policy, Rule
from mcp_gatekeeper.proxy.gateway import ApprovalMode, Gateway, GatewayDeps
from mcp_gatekeeper.proxy.registry import ToolRegistry
from mcp_gatekeeper.proxy.server import TOOL_LIST_TTL_MS, build_server
from mcp_gatekeeper.proxy.upstream import UpstreamManager, UpstreamSession
from tests.fixtures.fake_upstream import build_fake_upstream


@asynccontextmanager
async def stack(
    tmp_path: Path,
    rules: Sequence[Rule] = (),
    *,
    default: Action = Action.REQUIRE_APPROVAL,
    approval_mode: ApprovalMode = "auto",
    timeout_seconds: float = 5.0,
) -> AsyncGenerator[tuple[Gateway, ApprovalService, SqliteAuditStore]]:
    """Stand up the whole chain: upstream, gateway, stores."""
    async with Database(tmp_path / "e2e.db") as database, Client(build_fake_upstream()) as up:
        manager = UpstreamManager(upstreams=[])
        manager.connections["fake"] = UpstreamSession("fake", up)

        approvals = ApprovalService(
            store=SqliteApprovalStore(database), timeout_seconds=timeout_seconds
        )
        audit = SqliteAuditStore(database)
        gateway = Gateway(
            GatewayDeps(
                policy=Policy(rules=tuple(rules), default=default),
                upstreams=manager,
                approvals=approvals,
                audit=audit,
                registry=ToolRegistry(tools={}),
                approval_mode=approval_mode,
            )
        )
        await gateway.refresh_registry()
        yield gateway, approvals, audit


def text_of(result: types.CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    return block.text


class TestThroughTheServer:
    async def test_client_sees_namespaced_tools(self, tmp_path: Path) -> None:
        async with stack(tmp_path, (Rule(tool="*", action=Action.ALLOW),)) as (gateway, _, _):
            async with Client(build_server(gateway)) as client:
                result = await client.list_tools()

        names = [tool.name for tool in result.tools]
        assert "fake__read_file" in names
        assert "fake__write_file" in names

    async def test_tool_list_carries_cache_hints(self, tmp_path: Path) -> None:
        # The revision requires these on list results; a client that caches
        # without them would be guessing.
        async with stack(tmp_path, (Rule(tool="*", action=Action.ALLOW),)) as (gateway, _, _):
            async with Client(build_server(gateway)) as client:
                result = await client.list_tools()

        assert result.ttl_ms == TOOL_LIST_TTL_MS
        # Policy can vary per caller, so a shared cache must not reuse this.
        assert result.cache_scope == "private"

    async def test_allowed_call_reaches_the_upstream(self, tmp_path: Path) -> None:
        async with stack(tmp_path, (Rule(tool="*", action=Action.ALLOW),)) as (gateway, _, _):
            async with Client(build_server(gateway)) as client:
                result = await client.call_tool("fake__read_file", {"path": "/data/x"})

        assert not result.is_error
        assert json.loads(text_of(result)) == {
            "tool": "read_file",
            "arguments": {"path": "/data/x"},
        }

    async def test_denied_call_is_refused_as_a_readable_result(self, tmp_path: Path) -> None:
        rules = (Rule(tool="fake__write_file", action=Action.DENY, reason="no writes"),)
        async with stack(tmp_path, rules, default=Action.ALLOW) as (gateway, _, _):
            async with Client(build_server(gateway)) as client:
                result = await client.call_tool("fake__write_file", {"path": "/x"})

        # A tool result, not a transport error, so the model can read the why.
        assert result.is_error
        assert "no writes" in text_of(result)

    async def test_client_identity_is_recorded(self, tmp_path: Path) -> None:
        async with stack(tmp_path, (Rule(tool="*", action=Action.ALLOW),)) as (
            gateway,
            _,
            audit,
        ):
            async with Client(
                build_server(gateway),
                client_info=types.Implementation(name="probe", version="9.9"),
            ) as client:
                await client.call_tool("fake__read_file", {"path": "/x"})

            events = await audit.recent()

        # Identity travels per request in _meta now, not from a handshake.
        assert events[0].client_name == "probe 9.9"


class TestElicitationOverTheWire:
    async def test_client_is_asked_and_the_call_completes(self, tmp_path: Path) -> None:
        """The full multi-round-trip loop, driven by the SDK.

        The client's elicitation callback stands in for a human opening the
        link; the SDK then retries the original call carrying the response,
        and the gateway resumes from the stored decision.
        """
        seen: list[str] = []

        async with stack(tmp_path, approval_mode="elicit") as (gateway, approvals, _):

            async def elicit(context: object, params: object) -> types.ElicitResult:
                url = getattr(params, "url", "")
                seen.append(url)
                # Approve out of band, exactly as the web UI would.
                approval_id = url.rsplit("/", 1)[-1]
                await approvals.decide(approval_id, approved=True, approver="alice")
                return types.ElicitResult(action="accept")

            async with Client(build_server(gateway), elicitation_callback=elicit) as client:
                result = await client.call_tool("fake__write_file", {"path": "/prod/db.yaml"})

        assert len(seen) == 1
        assert "/approvals/" in seen[0]
        assert not result.is_error
        assert json.loads(text_of(result))["tool"] == "write_file"

    async def test_denial_over_the_wire_blocks_the_call(self, tmp_path: Path) -> None:
        async with stack(tmp_path, approval_mode="elicit") as (gateway, approvals, _):

            async def elicit(context: object, params: object) -> types.ElicitResult:
                url = getattr(params, "url", "")
                approval_id = url.rsplit("/", 1)[-1]
                await approvals.decide(approval_id, approved=False, approver="bob")
                return types.ElicitResult(action="decline")

            async with Client(build_server(gateway), elicitation_callback=elicit) as client:
                result = await client.call_tool("fake__write_file", {"path": "/prod/db.yaml"})

        assert result.is_error
        assert "bob" in text_of(result)

    async def test_auto_mode_blocks_a_client_without_the_capability(self, tmp_path: Path) -> None:
        # No elicitation_callback means no advertised capability. Returning an
        # InputRequiredResult here would be a protocol error, so auto must fall
        # back to holding the call -- which then times out and denies.
        async with stack(tmp_path, approval_mode="auto", timeout_seconds=0.2) as (
            gateway,
            _,
            _audit,
        ):
            async with Client(build_server(gateway)) as client:
                result = await client.call_tool("fake__write_file", {"path": "/x"})

        assert result.is_error
        assert "in time" in text_of(result)


class TestAuditTrailEndToEnd:
    async def test_every_call_is_recorded_once(self, tmp_path: Path) -> None:
        rules = (
            Rule(tool="fake__read_file", action=Action.ALLOW),
            Rule(tool="fake__write_file", action=Action.DENY, reason="nope"),
        )
        async with stack(tmp_path, rules, default=Action.ALLOW) as (gateway, _, audit):
            async with Client(build_server(gateway)) as client:
                await client.call_tool("fake__read_file", {"path": "/a"})
                await client.call_tool("fake__write_file", {"path": "/b"})

            events = await audit.recent()
            total = await audit.count()

        assert total == 2
        by_tool = {event.tool: event for event in events}
        assert by_tool["fake__read_file"].action is Action.ALLOW
        assert by_tool["fake__write_file"].action is Action.DENY
        assert by_tool["fake__write_file"].decision_reason == "nope"

    async def test_latency_is_measured(self, tmp_path: Path) -> None:
        async with stack(tmp_path, (Rule(tool="*", action=Action.ALLOW),)) as (
            gateway,
            _,
            audit,
        ):
            async with Client(build_server(gateway)) as client:
                await client.call_tool("fake__read_file", {"path": "/a"})

            events = await audit.recent()

        latency = events[0].latency_ms
        assert latency is not None
        assert latency > 0

    @pytest.mark.parametrize(
        ("tool", "expect_error"),
        [("fake__read_file", False), ("fake__explode", True)],
    )
    async def test_result_status_reflects_the_upstream(
        self, tmp_path: Path, tool: str, expect_error: bool
    ) -> None:
        async with stack(tmp_path, (Rule(tool="*", action=Action.ALLOW),)) as (
            gateway,
            _,
            audit,
        ):
            async with Client(build_server(gateway)) as client:
                await client.call_tool(tool, {"path": "/a"})

            events = await audit.recent()

        status = events[0].result_status
        assert status is not None
        assert (status.value == "error") is expect_error
