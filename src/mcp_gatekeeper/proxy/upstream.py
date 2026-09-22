"""Connections to upstream MCP servers.

The gatekeeper is a client to every server it fronts. Connections are opened
once at startup and held for the process lifetime: a stdio upstream is a
subprocess, and re-launching it per tool call would be both slow and wrong for
servers that keep in-memory state between calls.

A failing upstream is isolated rather than fatal. One misconfigured server
should not take down a gatekeeper that is successfully governing three others.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Protocol, Self, runtime_checkable

from mcp import StdioServerParameters, types
from mcp.client import Client

from mcp_gatekeeper.config.models import HttpUpstream, StdioUpstream, Upstream

logger = logging.getLogger(__name__)

__all__ = [
    "UpstreamConnection",
    "UpstreamError",
    "UpstreamManager",
    "UpstreamSession",
]


class UpstreamError(Exception):
    """An upstream could not be reached or returned a protocol-level error."""


@runtime_checkable
class UpstreamConnection(Protocol):
    """What the gateway needs from an upstream.

    Narrow on purpose: tests substitute a fake without standing up a transport,
    and nothing downstream depends on the SDK's client type.
    """

    @property
    def name(self) -> str: ...

    async def list_tools(self) -> Sequence[types.Tool]: ...

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None
    ) -> types.CallToolResult: ...


@dataclass
class UpstreamSession:
    """A live connection to one upstream server."""

    _name: str
    _client: Client

    @property
    def name(self) -> str:
        return self._name

    async def list_tools(self) -> Sequence[types.Tool]:
        try:
            result = await self._client.list_tools()
        except Exception as error:
            raise UpstreamError(f"upstream {self._name!r} failed to list tools: {error}") from error
        return result.tools

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None
    ) -> types.CallToolResult:
        try:
            return await self._client.call_tool(name, dict(arguments) if arguments else None)
        except Exception as error:
            raise UpstreamError(
                f"upstream {self._name!r} failed to call {name!r}: {error}"
            ) from error


def _build_client(upstream: Upstream) -> Client:
    """Turn a config entry into an unconnected SDK client."""
    if isinstance(upstream, StdioUpstream):
        return Client(
            StdioServerParameters(
                command=upstream.command,
                args=list(upstream.args),
                env=dict(upstream.env) or None,
                cwd=upstream.cwd,
            )
        )

    http: HttpUpstream = upstream
    # The SDK resolves a bare URL string to Streamable HTTP.
    return Client(http.url)


@dataclass
class UpstreamManager:
    """Opens and owns every upstream connection.

    Used as an async context manager; connections close in reverse order on
    exit, which shuts stdio subprocesses down cleanly.
    """

    upstreams: Sequence[Upstream]
    connections: dict[str, UpstreamConnection] = field(
        default_factory=dict[str, UpstreamConnection]
    )
    failures: dict[str, str] = field(default_factory=dict[str, str])
    _stack: AsyncExitStack = field(default_factory=AsyncExitStack)

    async def __aenter__(self) -> Self:
        await self._stack.__aenter__()
        for upstream in self.upstreams:
            try:
                client = await self._stack.enter_async_context(_build_client(upstream))
            except Exception as error:
                # Isolate the failure: the remaining upstreams stay governed,
                # and `failures` lets the CLI report what did not come up.
                logger.error("upstream %r failed to connect: %s", upstream.name, error)
                self.failures[upstream.name] = str(error)
                continue
            self.connections[upstream.name] = UpstreamSession(upstream.name, client)
            logger.info("upstream %r connected", upstream.name)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        self.connections.clear()
        return await self._stack.__aexit__(exc_type, exc, tb)
