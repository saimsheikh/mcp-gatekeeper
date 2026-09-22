"""Request orchestration: policy, approval, forwarding, audit.

This is the only place the four concerns meet. Each of them is implemented
elsewhere and injected, so this module reads as the decision flow and nothing
else.

The approval path has two shapes because the protocol offers two. Under the
multi-round-trip pattern a client that supports URL elicitation is handed a
link and retries the call once a human has answered, which keeps nothing
blocked. A client without that capability gets the call held open instead.
Both resolve against the same queue, so the web UI does not know or care which
one is in play.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp import types

from mcp_gatekeeper.approvals.models import ApprovalRequest, ApprovalStatus
from mcp_gatekeeper.approvals.service import ApprovalService
from mcp_gatekeeper.audit.models import AuditEvent, Outcome, ResultStatus
from mcp_gatekeeper.audit.store import AuditStore
from mcp_gatekeeper.policy.models import Action, Decision, Policy, PolicyRequest
from mcp_gatekeeper.proxy.registry import NamespacedTool, ToolRegistry, split_namespace
from mcp_gatekeeper.proxy.upstream import UpstreamError, UpstreamManager

logger = logging.getLogger(__name__)

__all__ = ["ApprovalMode", "Gateway", "GatewayDeps"]

ApprovalMode = Literal["auto", "elicit", "block"]

APPROVAL_INPUT_KEY = "approval"
"""Key under which the elicitation request and its response travel."""


def _text_result(message: str, *, is_error: bool) -> types.CallToolResult:
    """Build a result the model can read.

    Denials come back as a tool result rather than a JSON-RPC error so the
    model is told *why* it was blocked and can adapt or explain, instead of
    seeing an opaque transport failure.
    """
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        is_error=is_error,
    )


@dataclass
class GatewayDeps:
    """Everything the gateway needs, passed in explicitly."""

    policy: Policy
    upstreams: UpstreamManager
    approvals: ApprovalService
    audit: AuditStore
    registry: ToolRegistry
    approval_mode: ApprovalMode = "auto"
    ui_base_url: str = "http://localhost:8765"
    redact: tuple[str, ...] = ()


@dataclass
class Gateway:
    """Applies policy to every tool call and forwards what survives it."""

    deps: GatewayDeps
    _registry: ToolRegistry | None = field(default=None, init=False)

    @property
    def registry(self) -> ToolRegistry:
        return self._registry or self.deps.registry

    async def refresh_registry(self) -> ToolRegistry:
        """Re-read tools from every connected upstream."""
        collected: dict[str, list[types.Tool]] = {}
        for name, connection in self.deps.upstreams.connections.items():
            try:
                collected[name] = list(await connection.list_tools())
            except UpstreamError as error:
                # A momentarily broken upstream should not blank the whole tool
                # list; keep serving what the others advertise.
                logger.error("%s", error)
                collected[name] = []
        self._registry = ToolRegistry.build(collected)
        return self._registry

    async def list_tools(self) -> list[types.Tool]:
        registry = await self.refresh_registry()
        return registry.listing()

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None,
        *,
        client_name: str | None = None,
        supports_url_elicitation: bool = False,
        request_state: str | None = None,
        input_responses: Mapping[str, Any] | None = None,
    ) -> types.CallToolResult | types.InputRequiredResult:
        """Run one tool call through the gate."""
        started = time.perf_counter()
        args: Mapping[str, Any] = arguments or {}

        entry = self.registry.get(name)
        if entry is None:
            return await self._unknown_tool(name, args, client_name, started)

        request = PolicyRequest(
            tool=name,
            upstream=entry.upstream,
            arguments=args,
            annotations=entry.annotations,
        )
        from mcp_gatekeeper.policy.engine import evaluate

        decision = evaluate(request, self.deps.policy)

        # A retry carrying approval state resumes an earlier decision rather
        # than opening a second one.
        if request_state and input_responses is not None:
            return await self._resume(entry, request, decision, request_state, client_name, started)

        if decision.action is Action.ALLOW:
            return await self._forward(entry, request, decision, None, client_name, started)

        if decision.action is Action.DENY:
            return await self._deny(entry, request, decision, client_name, started)

        return await self._require_approval(
            entry, request, decision, client_name, supports_url_elicitation, started
        )

    # -- outcomes ---------------------------------------------------------

    async def _unknown_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        client_name: str | None,
        started: float,
    ) -> types.CallToolResult:
        split = split_namespace(name)
        upstream = split[0] if split else "unknown"
        decision = Decision(action=Action.DENY, source="default", reason="tool is not registered")
        await self._record(
            tool=name,
            upstream=upstream,
            arguments=arguments,
            decision=decision,
            outcome=Outcome.UNKNOWN_TOOL,
            client_name=client_name,
            started=started,
            result_status=ResultStatus.ERROR,
        )
        known = ", ".join(self.registry.names()) or "none"
        return _text_result(
            f"Unknown tool {name!r}. This gatekeeper exposes: {known}.", is_error=True
        )

    async def _forward(
        self,
        entry: NamespacedTool,
        request: PolicyRequest,
        decision: Decision,
        approval: ApprovalRequest | None,
        client_name: str | None,
        started: float,
    ) -> types.CallToolResult:
        connection = self.deps.upstreams.connections.get(entry.upstream)
        if connection is None:
            decision_failed = Decision(
                action=Action.DENY, source=decision.source, reason="upstream unavailable"
            )
            await self._record(
                tool=request.tool,
                upstream=entry.upstream,
                arguments=request.arguments,
                decision=decision_failed,
                outcome=Outcome.ERROR,
                client_name=client_name,
                started=started,
                result_status=ResultStatus.ERROR,
                error=f"upstream {entry.upstream!r} is not connected",
            )
            return _text_result(f"Upstream {entry.upstream!r} is not connected.", is_error=True)

        try:
            result = await connection.call_tool(entry.remote_name, request.arguments)
        except UpstreamError as error:
            await self._record(
                tool=request.tool,
                upstream=entry.upstream,
                arguments=request.arguments,
                decision=decision,
                outcome=Outcome.ERROR,
                client_name=client_name,
                started=started,
                result_status=ResultStatus.ERROR,
                approval=approval,
                error=str(error),
            )
            return _text_result(str(error), is_error=True)

        await self._record(
            tool=request.tool,
            upstream=entry.upstream,
            arguments=request.arguments,
            decision=decision,
            outcome=Outcome.FORWARDED,
            client_name=client_name,
            started=started,
            result_status=ResultStatus.ERROR if result.is_error else ResultStatus.OK,
            approval=approval,
        )
        return result

    async def _deny(
        self,
        entry: NamespacedTool,
        request: PolicyRequest,
        decision: Decision,
        client_name: str | None,
        started: float,
    ) -> types.CallToolResult:
        await self._record(
            tool=request.tool,
            upstream=entry.upstream,
            arguments=request.arguments,
            decision=decision,
            outcome=Outcome.DENIED_BY_POLICY,
            client_name=client_name,
            started=started,
            result_status=ResultStatus.ERROR,
        )
        reason = decision.reason or "blocked by policy"
        return _text_result(
            f"Blocked by mcp-gatekeeper: {reason}. This call was not forwarded.",
            is_error=True,
        )

    async def _require_approval(
        self,
        entry: NamespacedTool,
        request: PolicyRequest,
        decision: Decision,
        client_name: str | None,
        supports_url_elicitation: bool,
        started: float,
    ) -> types.CallToolResult | types.InputRequiredResult:
        approval = await self.deps.approvals.open(
            tool=request.tool,
            upstream=entry.upstream,
            arguments=request.arguments,
            reason=decision.reason,
            client_name=client_name,
        )
        url = f"{self.deps.ui_base_url.rstrip('/')}/approvals/{approval.id}"

        if self._use_elicitation(supports_url_elicitation):
            await self._record(
                tool=request.tool,
                upstream=entry.upstream,
                arguments=request.arguments,
                decision=decision,
                outcome=Outcome.AWAITING_APPROVAL,
                client_name=client_name,
                started=started,
                approval=approval,
            )
            # Hand the client a link and let it retry. Returning this to a
            # client that has not advertised URL elicitation is a protocol
            # error, which is why the capability is checked per request.
            return types.InputRequiredResult(
                input_requests={
                    APPROVAL_INPUT_KEY: types.ElicitRequest(
                        params=types.ElicitRequestURLParams(
                            mode="url",
                            message=(
                                f"{request.tool} needs approval"
                                + (f": {decision.reason}" if decision.reason else "")
                            ),
                            url=url,
                        )
                    )
                },
                request_state=approval.id,
            )

        logger.info("holding %s for approval at %s", request.tool, url)
        settled = await self.deps.approvals.wait(approval.id)
        return await self._apply_approval(entry, request, decision, settled, client_name, started)

    async def _resume(
        self,
        entry: NamespacedTool,
        request: PolicyRequest,
        decision: Decision,
        request_state: str,
        client_name: str | None,
        started: float,
    ) -> types.CallToolResult:
        """Continue a call the client retried after visiting the approval page."""
        settled = await self.deps.approvals.get(request_state)
        if settled is None:
            return _text_result(
                "This approval request is no longer on file; the call was not forwarded.",
                is_error=True,
            )
        return await self._apply_approval(entry, request, decision, settled, client_name, started)

    async def _apply_approval(
        self,
        entry: NamespacedTool,
        request: PolicyRequest,
        decision: Decision,
        approval: ApprovalRequest | None,
        client_name: str | None,
        started: float,
    ) -> types.CallToolResult:
        if approval is None:
            return _text_result("Approval request vanished before it was decided.", is_error=True)

        if approval.status.is_granted:
            return await self._forward(entry, request, decision, approval, client_name, started)

        outcome = (
            Outcome.TIMED_OUT
            if approval.status is ApprovalStatus.EXPIRED
            else Outcome.DENIED_BY_APPROVER
        )
        await self._record(
            tool=request.tool,
            upstream=entry.upstream,
            arguments=request.arguments,
            decision=decision,
            outcome=outcome,
            client_name=client_name,
            started=started,
            result_status=ResultStatus.ERROR,
            approval=approval,
        )

        if approval.status is ApprovalStatus.EXPIRED:
            message = "No approver responded in time, so the call was denied."
        else:
            who = approval.approver or "an approver"
            note = f" Note: {approval.note}" if approval.note else ""
            message = f"Denied by {who}.{note}"
        return _text_result(f"Blocked by mcp-gatekeeper: {message}", is_error=True)

    # -- helpers ----------------------------------------------------------

    def _use_elicitation(self, supports_url_elicitation: bool) -> bool:
        mode = self.deps.approval_mode
        if mode == "elicit":
            return True
        if mode == "block":
            return False
        return supports_url_elicitation

    async def _record(
        self,
        *,
        tool: str,
        upstream: str,
        arguments: Mapping[str, Any],
        decision: Decision,
        outcome: Outcome,
        client_name: str | None,
        started: float,
        result_status: ResultStatus | None = None,
        approval: ApprovalRequest | None = None,
        error: str | None = None,
    ) -> None:
        event = AuditEvent.build(
            event_id=uuid.uuid4().hex,
            tool=tool,
            upstream=upstream,
            arguments=arguments,
            decision=decision,
            outcome=outcome,
            redact=self.deps.redact,
            client_name=client_name,
            latency_ms=(time.perf_counter() - started) * 1000,
            result_status=result_status,
            approval_id=approval.id if approval else None,
            approver=approval.approver if approval else None,
            error=error,
        )
        await self.deps.audit.record(event)
