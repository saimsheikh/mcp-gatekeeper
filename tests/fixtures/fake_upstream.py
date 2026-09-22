"""A tiny MCP server to proxy in tests.

Usable two ways: as an in-process ``Server`` handed straight to a client, and
as a real subprocess (``python -m tests.fixtures.fake_upstream``) so the stdio
transport is exercised rather than mocked.

The tools are chosen to cover what policy needs to see: an annotated read-only
tool, an annotated destructive one, a tool with no annotations at all, one that
returns a tool-level error, and one that echoes nested arguments.
"""

from __future__ import annotations

import json
from typing import Any

from mcp import types
from mcp.server import ServerRequestContext
from mcp.server.lowlevel import Server

__all__ = ["TOOLS", "build_fake_upstream", "main"]

TOOLS: list[types.Tool] = [
    types.Tool(
        name="read_file",
        description="Read a file.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False),
    ),
    types.Tool(
        name="write_file",
        description="Write a file.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}, "contents": {"type": "string"}},
            "required": ["path"],
        },
        annotations=types.ToolAnnotations(read_only_hint=False, destructive_hint=True),
    ),
    types.Tool(
        name="delete_everything",
        description="Destructive, and says so.",
        input_schema={"type": "object", "properties": {}},
        annotations=types.ToolAnnotations(destructive_hint=True),
    ),
    types.Tool(
        # Deliberately unannotated: policy must not infer anything from silence.
        name="mystery",
        description="No annotations at all.",
        input_schema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="explode",
        description="Always returns a tool-level error.",
        input_schema={"type": "object", "properties": {}},
    ),
    types.Tool(
        # Contains the namespace separator, to prove round-tripping is safe.
        name="odd__name",
        description="A tool whose own name contains the separator.",
        input_schema={"type": "object", "properties": {}},
    ),
]


def build_fake_upstream(name: str = "fake-upstream") -> Server[object]:
    """Construct the fake server."""

    async def on_list_tools(
        context: ServerRequestContext[object, Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=TOOLS, ttl_ms=1000, cache_scope="private")

    async def on_call_tool(
        context: ServerRequestContext[object, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        arguments: dict[str, Any] = dict(params.arguments or {})

        if params.name == "explode":
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="upstream tool failed")],
                is_error=True,
            )

        payload = json.dumps({"tool": params.name, "arguments": arguments}, sort_keys=True)
        return types.CallToolResult(content=[types.TextContent(type="text", text=payload)])

    return Server(name, version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def main() -> None:
    """Run over stdio, for tests that spawn a real subprocess."""
    import anyio
    from mcp.server.stdio import stdio_server

    async def run() -> None:
        server = build_fake_upstream()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(run)


if __name__ == "__main__":
    main()
