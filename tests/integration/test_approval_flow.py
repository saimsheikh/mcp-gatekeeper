"""Integration tests for the approval workflow.

Covers both shapes: holding a call open until a human answers (block), and
handing the client a link to retry against (elicit). Both resolve through the
same queue, which is the property that lets one web UI serve either.
"""

from __future__ import annotations

import anyio
import pytest
from mcp import types

from mcp_gatekeeper.approvals.models import TIMEOUT_APPROVER, ApprovalStatus
from mcp_gatekeeper.approvals.store import SqliteApprovalStore
from mcp_gatekeeper.audit.models import Outcome
from mcp_gatekeeper.audit.store import SqliteAuditStore
from mcp_gatekeeper.policy.models import Action
from mcp_gatekeeper.proxy.gateway import APPROVAL_INPUT_KEY, Gateway

from .conftest import GatewayFactory
from .test_proxy import text_of

CALL = ("fake__write_file", {"path": "/prod/db.yaml"})


async def wait_for_pending(store: SqliteApprovalStore) -> str:
    """Poll until a request lands in the queue, then return its id."""
    with anyio.fail_after(5):
        while True:
            pending = await store.pending()
            if pending:
                return pending[0].id
            await anyio.sleep(0.01)


async def decide_when_pending(
    store: SqliteApprovalStore, gateway: Gateway, approved: bool, approver: str = "alice"
) -> None:
    """Wait for the call to park, then decide it. Positional args: start_soon
    does not forward keywords."""
    approval_id = await wait_for_pending(store)
    await gateway.deps.approvals.decide(approval_id, approved=approved, approver=approver)


class TestBlockingApproval:
    async def test_approved_call_is_forwarded(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        async with gateways.build(approval_mode="block") as gateway:
            result: types.CallToolResult | types.InputRequiredResult | None = None

            async def call() -> None:
                nonlocal result
                result = await gateway.call_tool(*CALL)

            async with anyio.create_task_group() as tg:
                tg.start_soon(call)
                tg.start_soon(decide_when_pending, approval_store, gateway, True)

            assert isinstance(result, types.CallToolResult)
            assert not result.is_error

    async def test_denied_call_is_not_forwarded(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        async with gateways.build(approval_mode="block") as gateway:
            result: types.CallToolResult | types.InputRequiredResult | None = None

            async def call() -> None:
                nonlocal result
                result = await gateway.call_tool(*CALL)

            async def deny() -> None:
                approval_id = await wait_for_pending(approval_store)
                await gateway.deps.approvals.decide(
                    approval_id, approved=False, approver="bob", note="wrong environment"
                )

            async with anyio.create_task_group() as tg:
                tg.start_soon(call)
                tg.start_soon(deny)

            assert isinstance(result, types.CallToolResult)
            assert result.is_error
            message = text_of(result)
            assert "bob" in message
            assert "wrong environment" in message

    async def test_timeout_denies(self, gateways: GatewayFactory) -> None:
        # Silence must not read as consent.
        async with gateways.build(approval_mode="block", timeout_seconds=0.2) as gateway:
            result = await gateway.call_tool(*CALL)

            assert isinstance(result, types.CallToolResult)
            assert result.is_error
            assert "in time" in text_of(result)

    async def test_timeout_can_be_configured_to_allow(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        async with gateways.build(
            approval_mode="block", timeout_seconds=0.2, approve_on_timeout=True
        ) as gateway:
            result = await gateway.call_tool(*CALL)

            assert isinstance(result, types.CallToolResult)
            assert not result.is_error

            # The system actor is recorded, so the trail never shows a decision
            # without an actor behind it.
            recent = await approval_store.recent()
            assert recent[0].approver == TIMEOUT_APPROVER


class TestElicitedApproval:
    async def test_returns_a_link_instead_of_blocking(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        async with gateways.build(approval_mode="elicit") as gateway:
            result = await gateway.call_tool(*CALL, supports_url_elicitation=True)

            assert isinstance(result, types.InputRequiredResult)
            assert result.request_state is not None

            assert result.input_requests is not None
            request = result.input_requests[APPROVAL_INPUT_KEY]
            assert isinstance(request, types.ElicitRequest)
            params = request.params
            assert isinstance(params, types.ElicitRequestURLParams)
            assert params.url.endswith(f"/approvals/{result.request_state}")

            # The call is parked, not decided.
            pending = await approval_store.pending()
            assert [item.id for item in pending] == [result.request_state]

    async def test_retry_after_approval_forwards(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        async with gateways.build(approval_mode="elicit") as gateway:
            first = await gateway.call_tool(*CALL, supports_url_elicitation=True)
            assert isinstance(first, types.InputRequiredResult)
            approval_id = first.request_state
            assert approval_id is not None

            await gateway.deps.approvals.decide(approval_id, approved=True, approver="alice")

            # The client retries the original call carrying the state back.
            second = await gateway.call_tool(
                *CALL,
                supports_url_elicitation=True,
                request_state=approval_id,
                input_responses={APPROVAL_INPUT_KEY: types.ElicitResult(action="accept")},
            )
            assert isinstance(second, types.CallToolResult)
            assert not second.is_error

    async def test_retry_after_denial_is_blocked(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        async with gateways.build(approval_mode="elicit") as gateway:
            first = await gateway.call_tool(*CALL, supports_url_elicitation=True)
            assert isinstance(first, types.InputRequiredResult)
            approval_id = first.request_state
            assert approval_id is not None

            await gateway.deps.approvals.decide(approval_id, approved=False, approver="bob")

            second = await gateway.call_tool(
                *CALL,
                supports_url_elicitation=True,
                request_state=approval_id,
                input_responses={APPROVAL_INPUT_KEY: types.ElicitResult(action="decline")},
            )
            assert isinstance(second, types.CallToolResult)
            assert second.is_error
            assert "bob" in text_of(second)

    async def test_the_client_cannot_approve_itself(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        # The elicitation response is only a signal to re-check; the decision
        # of record lives in the queue. A client claiming "accept" for a request
        # no human approved must still be refused.
        async with gateways.build(approval_mode="elicit") as gateway:
            first = await gateway.call_tool(*CALL, supports_url_elicitation=True)
            assert isinstance(first, types.InputRequiredResult)
            approval_id = first.request_state
            assert approval_id is not None

            second = await gateway.call_tool(
                *CALL,
                supports_url_elicitation=True,
                request_state=approval_id,
                input_responses={APPROVAL_INPUT_KEY: types.ElicitResult(action="accept")},
            )
            assert isinstance(second, types.CallToolResult)
            assert second.is_error

    async def test_unknown_request_state_is_refused(self, gateways: GatewayFactory) -> None:
        async with gateways.build(approval_mode="elicit") as gateway:
            result = await gateway.call_tool(
                *CALL,
                supports_url_elicitation=True,
                request_state="not-a-real-id",
                input_responses={APPROVAL_INPUT_KEY: types.ElicitResult(action="accept")},
            )
            assert isinstance(result, types.CallToolResult)
            assert result.is_error
            assert "no longer on file" in text_of(result)


class TestAutoMode:
    async def test_elicits_when_the_client_supports_it(self, gateways: GatewayFactory) -> None:
        async with gateways.build(approval_mode="auto") as gateway:
            result = await gateway.call_tool(*CALL, supports_url_elicitation=True)
            assert isinstance(result, types.InputRequiredResult)

    async def test_blocks_when_the_client_does_not(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        # Returning InputRequiredResult to a client without the capability is a
        # protocol error, so auto must fall back rather than guess.
        async with gateways.build(approval_mode="auto", timeout_seconds=0.2) as gateway:
            result = await gateway.call_tool(*CALL, supports_url_elicitation=False)
            assert isinstance(result, types.CallToolResult)
            assert result.is_error

    async def test_forced_block_ignores_the_capability(self, gateways: GatewayFactory) -> None:
        async with gateways.build(approval_mode="block", timeout_seconds=0.2) as gateway:
            result = await gateway.call_tool(*CALL, supports_url_elicitation=True)
            assert isinstance(result, types.CallToolResult)


class TestConcurrency:
    async def test_only_the_first_decision_counts(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore
    ) -> None:
        async with gateways.build(approval_mode="elicit") as gateway:
            first = await gateway.call_tool(*CALL, supports_url_elicitation=True)
            assert isinstance(first, types.InputRequiredResult)
            approval_id = first.request_state
            assert approval_id is not None

            approved = await gateway.deps.approvals.decide(
                approval_id, approved=True, approver="alice"
            )
            # A second approver arriving late gets the standing decision back
            # rather than overwriting it.
            second = await gateway.deps.approvals.decide(
                approval_id, approved=False, approver="bob"
            )

            assert approved is not None and approved.status is ApprovalStatus.APPROVED
            assert second is not None
            assert second.status is ApprovalStatus.APPROVED
            assert second.approver == "alice"


class TestApprovalAuditing:
    async def test_approved_call_records_the_approver(
        self,
        gateways: GatewayFactory,
        approval_store: SqliteApprovalStore,
        audit_store: SqliteAuditStore,
    ) -> None:
        async with gateways.build(approval_mode="elicit") as gateway:
            first = await gateway.call_tool(*CALL, supports_url_elicitation=True)
            assert isinstance(first, types.InputRequiredResult)
            approval_id = first.request_state
            assert approval_id is not None

            await gateway.deps.approvals.decide(approval_id, approved=True, approver="alice")
            await gateway.call_tool(
                *CALL,
                supports_url_elicitation=True,
                request_state=approval_id,
                input_responses={APPROVAL_INPUT_KEY: types.ElicitResult(action="accept")},
            )

            events = await audit_store.recent()
            forwarded = [e for e in events if e.outcome is Outcome.FORWARDED]
            assert forwarded
            assert forwarded[0].approver == "alice"
            assert forwarded[0].approval_id == approval_id

    async def test_timeout_is_recorded_as_such(
        self, gateways: GatewayFactory, audit_store: SqliteAuditStore
    ) -> None:
        async with gateways.build(approval_mode="block", timeout_seconds=0.2) as gateway:
            await gateway.call_tool(*CALL)

            events = await audit_store.recent()
            assert events[0].outcome is Outcome.TIMED_OUT


class TestPolicyStillApplies:
    @pytest.mark.parametrize("mode", ["block", "elicit"])
    async def test_allowed_calls_never_reach_the_queue(
        self, gateways: GatewayFactory, approval_store: SqliteApprovalStore, mode: str
    ) -> None:
        from mcp_gatekeeper.policy.models import Rule

        async with gateways.build(
            (Rule(tool="*", action=Action.ALLOW),),
            approval_mode=mode,  # type: ignore[arg-type]
        ) as gateway:
            result = await gateway.call_tool(*CALL, supports_url_elicitation=True)
            assert isinstance(result, types.CallToolResult)
            assert not result.is_error
            assert await approval_store.pending() == []
