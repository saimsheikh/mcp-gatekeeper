"""Shared fixtures for proxy integration tests.

Gateways are built inside an ``async with`` in the test body rather than handed
over by a fixture. The upstream client owns an anyio task group, and anyio
requires it to be entered and exited in the same task -- a fixture that yields
across that boundary trips "cancel scope in a different task".
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp.client import Client

from mcp_gatekeeper.approvals.service import ApprovalService
from mcp_gatekeeper.approvals.store import SqliteApprovalStore
from mcp_gatekeeper.audit.store import SqliteAuditStore
from mcp_gatekeeper.db import Database
from mcp_gatekeeper.policy.models import Action, Policy, Rule
from mcp_gatekeeper.proxy.gateway import ApprovalMode, Gateway, GatewayDeps
from mcp_gatekeeper.proxy.registry import ToolRegistry
from mcp_gatekeeper.proxy.upstream import UpstreamManager, UpstreamSession
from tests.fixtures.fake_upstream import build_fake_upstream


@pytest.fixture
async def database(tmp_path: Path) -> AsyncIterator[Database]:
    async with Database(tmp_path / "test.db") as db:
        yield db


@pytest.fixture
def audit_store(database: Database) -> SqliteAuditStore:
    return SqliteAuditStore(database)


@pytest.fixture
def approval_store(database: Database) -> SqliteApprovalStore:
    return SqliteApprovalStore(database)


class GatewayFactory:
    """Builds gateways wired to an in-process fake upstream.

    The upstream is a real MCP server reached over a real client, so the
    namespacing and forwarding paths under test are the production ones.
    """

    def __init__(self, audit: SqliteAuditStore, approvals: SqliteApprovalStore) -> None:
        self.audit = audit
        self.approvals = approvals

    @asynccontextmanager
    async def build(
        self,
        rules: Sequence[Rule] = (),
        *,
        default: Action = Action.REQUIRE_APPROVAL,
        approval_mode: ApprovalMode = "block",
        timeout_seconds: float = 5.0,
        approve_on_timeout: bool = False,
        upstream_name: str = "fake",
        redact: tuple[str, ...] = (),
    ) -> AsyncGenerator[Gateway]:
        async with Client(build_fake_upstream()) as client:
            manager = UpstreamManager(upstreams=[])
            manager.connections[upstream_name] = UpstreamSession(upstream_name, client)

            service = ApprovalService(
                store=self.approvals,
                timeout_seconds=timeout_seconds,
                approve_on_timeout=approve_on_timeout,
            )
            gateway = Gateway(
                GatewayDeps(
                    policy=Policy(rules=tuple(rules), default=default),
                    upstreams=manager,
                    approvals=service,
                    audit=self.audit,
                    registry=ToolRegistry(tools={}),
                    approval_mode=approval_mode,
                    redact=redact,
                )
            )
            await gateway.refresh_registry()
            yield gateway


@pytest.fixture
def gateways(audit_store: SqliteAuditStore, approval_store: SqliteApprovalStore) -> GatewayFactory:
    return GatewayFactory(audit_store, approval_store)
