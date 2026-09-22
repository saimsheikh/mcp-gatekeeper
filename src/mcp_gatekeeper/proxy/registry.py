"""Tool namespacing and aggregation.

Several upstreams are flattened into one tool list, so names must be made
unique. ``fs`` + ``write_file`` becomes ``fs__write_file``.

Splitting is unambiguous because upstream names may not themselves contain
``__`` (enforced in the config schema), so the *first* separator is always the
namespace boundary. An upstream tool called ``read__raw`` survives the round
trip intact.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from mcp import types

from mcp_gatekeeper.config.models import NAMESPACE_SEPARATOR
from mcp_gatekeeper.policy.models import AnnotationView

__all__ = [
    "NamespacedTool",
    "ToolRegistry",
    "annotation_view",
    "namespace",
    "split_namespace",
]


def namespace(upstream: str, tool: str) -> str:
    """Build the client-visible name for an upstream tool."""
    return f"{upstream}{NAMESPACE_SEPARATOR}{tool}"


def split_namespace(name: str) -> tuple[str, str] | None:
    """Recover ``(upstream, tool)`` from a namespaced name.

    Returns ``None`` when the name carries no namespace, which means a client
    asked for something this proxy never advertised.
    """
    upstream, separator, tool = name.partition(NAMESPACE_SEPARATOR)
    if not separator or not upstream or not tool:
        return None
    return upstream, tool


def annotation_view(tool: types.Tool) -> AnnotationView:
    """Project the SDK's annotations onto the policy engine's view.

    Keeps the MCP types out of the policy layer, so the engine stays testable
    without constructing protocol objects.
    """
    annotations = tool.annotations
    if annotations is None:
        return AnnotationView()
    return AnnotationView(
        read_only=annotations.read_only_hint,
        destructive=annotations.destructive_hint,
        idempotent=annotations.idempotent_hint,
        open_world=annotations.open_world_hint,
    )


@dataclass(frozen=True, slots=True)
class NamespacedTool:
    """One upstream tool, as the client sees it."""

    upstream: str
    remote_name: str
    """The name the upstream knows it by."""

    tool: types.Tool
    """The tool definition, renamed to its namespaced form."""

    @property
    def name(self) -> str:
        return self.tool.name

    @property
    def annotations(self) -> AnnotationView:
        return annotation_view(self.tool)


def _rename(tool: types.Tool, new_name: str) -> types.Tool:
    """Copy a tool under a new name, preserving every other field.

    Uses the SDK model's own copy so that schema fields this code does not know
    about still reach the client untouched.
    """
    return tool.model_copy(update={"name": new_name})


@dataclass(frozen=True, slots=True)
class ToolRegistry:
    """An immutable snapshot of every tool across every upstream."""

    tools: Mapping[str, NamespacedTool]

    @classmethod
    def build(cls, upstream_tools: Mapping[str, Sequence[types.Tool]]) -> ToolRegistry:
        """Aggregate per-upstream tool lists into one namespaced registry."""
        collected: dict[str, NamespacedTool] = {}
        for upstream, tools in upstream_tools.items():
            for tool in tools:
                new_name = namespace(upstream, tool.name)
                collected[new_name] = NamespacedTool(
                    upstream=upstream,
                    remote_name=tool.name,
                    tool=_rename(tool, new_name),
                )
        return cls(tools=collected)

    def get(self, name: str) -> NamespacedTool | None:
        return self.tools.get(name)

    def listing(self) -> list[types.Tool]:
        """Tools in deterministic order.

        The spec asks servers to return a stable order so clients can cache and
        so LLM prompt caches keep hitting.
        """
        return [self.tools[name].tool for name in sorted(self.tools)]

    def names(self) -> Iterable[str]:
        return sorted(self.tools)
