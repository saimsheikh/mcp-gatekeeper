"""The proxy: upstream connections, tool aggregation, and request orchestration."""

from __future__ import annotations

from mcp_gatekeeper.proxy.gateway import Gateway, GatewayDeps
from mcp_gatekeeper.proxy.registry import NamespacedTool, ToolRegistry, namespace, split_namespace
from mcp_gatekeeper.proxy.server import build_server
from mcp_gatekeeper.proxy.upstream import UpstreamError, UpstreamManager, UpstreamSession

__all__ = [
    "Gateway",
    "GatewayDeps",
    "NamespacedTool",
    "ToolRegistry",
    "UpstreamError",
    "UpstreamManager",
    "UpstreamSession",
    "build_server",
    "namespace",
    "split_namespace",
]
