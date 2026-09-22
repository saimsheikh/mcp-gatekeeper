"""The MCP server the client talks to.

Thin by design: it translates between SDK request objects and the gateway's
plain arguments, and holds no policy logic of its own.

Everything the handlers need arrives per request. The 2026-07-28 revision
removed the initialize handshake, so client capabilities travel in each
request's ``_meta`` and must be read there rather than remembered from a
session that no longer exists.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from mcp import types
from mcp.server import ServerRequestContext
from mcp.server.lowlevel import Server

from mcp_gatekeeper.proxy.gateway import Gateway

logger = logging.getLogger(__name__)

__all__ = ["TOOL_LIST_TTL_MS", "build_server", "client_name", "supports_url_elicitation"]

TOOL_LIST_TTL_MS = 5_000
"""Freshness hint for tools/list.

Short, because the tool list reflects upstream servers that can change under
us, and a client caching a stale list would offer the model tools this
gatekeeper no longer fronts.
"""

CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"


def _meta_value(meta: object, key: str, attribute: str) -> object:
    """Read a ``_meta`` entry.

    The SDK hands handlers either a parsed model or the raw mapping depending
    on the transport, so both are accepted.
    """
    if meta is None:
        return None
    if isinstance(meta, dict):
        mapping = cast("dict[str, Any]", meta)
        return mapping.get(key)
    return getattr(meta, attribute, None)


def supports_url_elicitation(context: ServerRequestContext[Any, Any]) -> bool:
    """Whether this client can be handed an approval link.

    Returning an ``InputRequiredResult`` to a client that has not advertised
    URL elicitation is a protocol error, so this gates the elicit path.
    """
    raw = _meta_value(
        context.meta, CLIENT_CAPABILITIES_KEY, "io_modelcontextprotocol_client_capabilities"
    )
    if raw is None:
        return False

    capabilities = raw
    if isinstance(raw, dict):
        try:
            capabilities = types.ClientCapabilities.model_validate(raw)
        except Exception:
            return False

    elicitation = getattr(capabilities, "elicitation", None)
    return elicitation is not None and getattr(elicitation, "url", None) is not None


def client_name(context: ServerRequestContext[Any, Any]) -> str | None:
    """Best-effort identity of the calling client, for the audit trail."""
    raw = _meta_value(context.meta, CLIENT_INFO_KEY, "io_modelcontextprotocol_client_info")
    if raw is None:
        return None
    if isinstance(raw, dict):
        mapping = cast("dict[str, Any]", raw)
        name = mapping.get("name")
        version = mapping.get("version")
    else:
        name = getattr(raw, "name", None)
        version = getattr(raw, "version", None)
    if not name:
        return None
    return f"{name} {version}" if version else str(name)


def build_server(
    gateway: Gateway,
    *,
    name: str = "mcp-gatekeeper",
    version: str = "0.1.0",
    instructions: str | None = None,
) -> Server[object]:
    """Wire a gateway up as an MCP server."""

    async def on_list_tools(
        context: ServerRequestContext[object, Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        tools = await gateway.list_tools()
        return types.ListToolsResult(
            tools=tools,
            ttl_ms=TOOL_LIST_TTL_MS,
            # Policy can differ per caller, so a shared cache must not serve
            # one client's tool list to another.
            cache_scope="private",
        )

    async def on_call_tool(
        context: ServerRequestContext[object, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult | types.InputRequiredResult:
        responses: dict[str, Any] | None = None
        if params.input_responses is not None:
            responses = dict(params.input_responses)

        return await gateway.call_tool(
            params.name,
            params.arguments,
            client_name=client_name(context),
            supports_url_elicitation=supports_url_elicitation(context),
            request_state=params.request_state,
            input_responses=responses,
        )

    return Server(
        name,
        version=version,
        instructions=instructions,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
