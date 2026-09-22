"""Tests for the approval and audit web UI.

The UI is how a human actually uses this tool, so the paths that matter are
the ones an approver walks: open the link from the elicitation, read the
arguments, click a button, and have the waiting call learn the answer.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mcp_gatekeeper.approvals.service import ApprovalService
from mcp_gatekeeper.approvals.store import SqliteApprovalStore
from mcp_gatekeeper.audit.models import AuditEvent, Outcome, ResultStatus
from mcp_gatekeeper.audit.store import SqliteAuditStore
from mcp_gatekeeper.db import Database
from mcp_gatekeeper.policy.models import Action, Decision
from mcp_gatekeeper.ui.app import build_ui


@pytest.fixture
async def service(approval_store: SqliteApprovalStore) -> ApprovalService:
    return ApprovalService(store=approval_store, timeout_seconds=300.0)


@pytest.fixture
def client(service: ApprovalService, audit_store: SqliteAuditStore) -> Iterator[TestClient]:
    app = build_ui(approvals=service, audit=audit_store)
    with TestClient(app) as test_client:
        yield test_client


async def open_approval(service: ApprovalService, **overrides: object) -> str:
    request = await service.open(
        tool=str(overrides.get("tool", "fs__write_file")),
        upstream=str(overrides.get("upstream", "fs")),
        arguments={"path": "/prod/db.yaml", "contents": "x"},
        reason="Writes need a human",
        client_name="probe 1.0",
    )
    return request.id


class TestDashboard:
    def test_renders_when_empty(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "Nothing waiting" in response.text

    async def test_lists_a_pending_approval(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        await open_approval(service)
        response = client.get("/")
        assert "fs__write_file" in response.text
        assert "/prod/db.yaml" in response.text

    async def test_pending_fragment_is_servable_on_its_own(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        # This is what HTMX polls; it must render without the page chrome.
        await open_approval(service)
        response = client.get("/approvals/pending")
        assert response.status_code == 200
        assert "fs__write_file" in response.text
        assert "<html" not in response.text


class TestDecidingFromTheQueue:
    """The dashboard is where an approver lives; it must be actionable there."""

    async def test_queue_offers_approve_and_deny_buttons(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        await open_approval(service)
        page = client.get("/").text
        assert 'value="approve"' in page
        assert 'value="deny"' in page

    async def test_polled_fragment_also_carries_the_buttons(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        # The fragment replaces the list every few seconds; if the buttons only
        # existed in the initial render they would vanish on first refresh.
        await open_approval(service)
        fragment = client.get("/approvals/pending").text
        assert 'value="approve"' in fragment
        assert 'value="deny"' in fragment

    async def test_approving_from_the_queue_returns_to_the_queue(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        approval_id = await open_approval(service)
        response = client.post(
            f"/approvals/{approval_id}/decide",
            data={"decision": "approve", "approver": "alice", "redirect_to": "/"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/"

        settled = await service.get(approval_id)
        assert settled is not None
        assert settled.status.is_granted
        assert settled.approver == "alice"

    async def test_deciding_without_redirect_stays_on_the_detail_page(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        approval_id = await open_approval(service)
        response = client.post(
            f"/approvals/{approval_id}/decide",
            data={"decision": "deny", "approver": "bob"},
            follow_redirects=False,
        )
        assert response.headers["location"] == f"/approvals/{approval_id}"

    async def test_redirect_target_cannot_be_hijacked(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        # Only the queue and the request's own page are reachable targets.
        approval_id = await open_approval(service)
        response = client.post(
            f"/approvals/{approval_id}/decide",
            data={
                "decision": "approve",
                "approver": "alice",
                "redirect_to": "https://evil.example.com",
            },
            follow_redirects=False,
        )
        assert response.headers["location"] == f"/approvals/{approval_id}"

    async def test_decided_request_leaves_the_queue(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        approval_id = await open_approval(service)
        client.post(
            f"/approvals/{approval_id}/decide",
            data={"decision": "approve", "approver": "alice", "redirect_to": "/"},
            follow_redirects=False,
        )
        assert "Nothing waiting" in client.get("/approvals/pending").text


class TestApprovalPage:
    async def test_shows_the_call_being_decided(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        approval_id = await open_approval(service)
        response = client.get(f"/approvals/{approval_id}")

        assert response.status_code == 200
        assert "fs__write_file" in response.text
        # The approver must be able to see exactly what they are approving.
        assert "/prod/db.yaml" in response.text
        assert "Writes need a human" in response.text
        assert "probe 1.0" in response.text

    def test_unknown_id_returns_404(self, client: TestClient) -> None:
        response = client.get("/approvals/does-not-exist")
        assert response.status_code == 404
        assert "Not found" in response.text

    async def test_approving_records_the_decision(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        approval_id = await open_approval(service)
        response = client.post(
            f"/approvals/{approval_id}/decide",
            data={"decision": "approve", "approver": "alice", "note": "looks fine"},
            follow_redirects=False,
        )
        # Post/redirect/get, so refreshing does not resubmit.
        assert response.status_code == 303

        settled = await service.get(approval_id)
        assert settled is not None
        assert settled.status.is_granted
        assert settled.approver == "alice"
        assert settled.note == "looks fine"

    async def test_denying_records_the_decision(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        approval_id = await open_approval(service)
        client.post(
            f"/approvals/{approval_id}/decide",
            data={"decision": "deny", "approver": "bob"},
            follow_redirects=False,
        )
        settled = await service.get(approval_id)
        assert settled is not None
        assert not settled.status.is_granted

    async def test_missing_approver_falls_back_to_anonymous(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        # An unnamed decision is still attributable to *something*; the audit
        # trail should never show an empty actor.
        approval_id = await open_approval(service)
        client.post(
            f"/approvals/{approval_id}/decide",
            data={"decision": "approve", "approver": "   "},
            follow_redirects=False,
        )
        settled = await service.get(approval_id)
        assert settled is not None
        assert settled.approver == "anonymous"

    async def test_decided_page_shows_the_outcome(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        approval_id = await open_approval(service)
        await service.decide(approval_id, approved=True, approver="alice")

        response = client.get(f"/approvals/{approval_id}")
        assert "approved" in response.text
        assert "alice" in response.text
        # The decision form is gone once decided.
        assert 'value="approve"' not in response.text

    async def test_a_second_decision_does_not_overwrite_the_first(
        self, client: TestClient, service: ApprovalService
    ) -> None:
        approval_id = await open_approval(service)
        client.post(
            f"/approvals/{approval_id}/decide",
            data={"decision": "approve", "approver": "alice"},
            follow_redirects=False,
        )
        client.post(
            f"/approvals/{approval_id}/decide",
            data={"decision": "deny", "approver": "bob"},
            follow_redirects=False,
        )
        settled = await service.get(approval_id)
        assert settled is not None
        assert settled.status.is_granted
        assert settled.approver == "alice"


async def record_event(store: SqliteAuditStore, tool: str, action: Action) -> None:
    await store.record(
        AuditEvent.build(
            event_id=f"id-{tool}-{action.value}",
            tool=tool,
            upstream="fs",
            arguments={"path": "/prod/db.yaml", "token": "shh"},
            decision=Decision(action=action, source="rule", reason="because", rule_index=0),
            outcome=Outcome.FORWARDED if action is Action.ALLOW else Outcome.DENIED_BY_POLICY,
            latency_ms=4.2,
            result_status=ResultStatus.OK,
        )
    )


class TestAuditView:
    def test_renders_when_empty(self, client: TestClient) -> None:
        response = client.get("/audit")
        assert response.status_code == 200
        assert "No matching calls" in response.text

    async def test_lists_events(self, client: TestClient, audit_store: SqliteAuditStore) -> None:
        await record_event(audit_store, "fs__write_file", Action.DENY)
        response = client.get("/audit")
        assert "fs__write_file" in response.text
        assert "deny" in response.text

    async def test_filters_by_tool(self, client: TestClient, audit_store: SqliteAuditStore) -> None:
        await record_event(audit_store, "fs__write_file", Action.DENY)
        await record_event(audit_store, "gh__create_issue", Action.ALLOW)

        response = client.get("/audit", params={"tool": "write"})
        assert "fs__write_file" in response.text
        assert "gh__create_issue" not in response.text

    async def test_filters_by_action(
        self, client: TestClient, audit_store: SqliteAuditStore
    ) -> None:
        await record_event(audit_store, "fs__write_file", Action.DENY)
        await record_event(audit_store, "gh__create_issue", Action.ALLOW)

        response = client.get("/audit", params={"action": "allow"})
        assert "gh__create_issue" in response.text
        assert "fs__write_file" not in response.text

    def test_invalid_action_filter_is_ignored(self, client: TestClient) -> None:
        assert client.get("/audit", params={"action": "bogus"}).status_code == 200


class TestExport:
    async def test_exports_jsonl(self, client: TestClient, audit_store: SqliteAuditStore) -> None:
        await record_event(audit_store, "fs__write_file", Action.DENY)
        await record_event(audit_store, "gh__create_issue", Action.ALLOW)

        response = client.get("/audit/export.jsonl")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/x-ndjson")

        lines = [line for line in response.text.splitlines() if line]
        assert len(lines) == 2
        payloads = [json.loads(line) for line in lines]
        assert {p["tool"] for p in payloads} == {"fs__write_file", "gh__create_issue"}
        assert payloads[0]["decision"]["reason"] == "because"

    async def test_export_is_a_download(
        self, client: TestClient, audit_store: SqliteAuditStore
    ) -> None:
        await record_event(audit_store, "fs__write_file", Action.DENY)
        response = client.get("/audit/export.jsonl")
        assert "attachment" in response.headers["content-disposition"]


class TestRedactionReachesTheUi:
    async def test_redacted_values_are_never_rendered(self, tmp_path: Path) -> None:
        # Redaction happens on write, so the UI cannot leak what was masked
        # even though it renders arguments verbatim.
        async with Database(tmp_path / "redact.db") as database:
            store = SqliteAuditStore(database)
            await store.record(
                AuditEvent.build(
                    event_id="secret-1",
                    tool="fs__write_file",
                    upstream="fs",
                    arguments={"path": "/x", "token": "super-secret-value"},
                    decision=Decision(action=Action.ALLOW, source="rule"),
                    outcome=Outcome.FORWARDED,
                    redact=["token"],
                )
            )
            app = build_ui(
                approvals=ApprovalService(store=SqliteApprovalStore(database)), audit=store
            )
            with TestClient(app) as test_client:
                assert "super-secret-value" not in test_client.get("/audit").text
                assert "super-secret-value" not in test_client.get("/audit/export.jsonl").text


class TestHealth:
    def test_healthz(self, client: TestClient) -> None:
        assert client.get("/healthz").json() == {"status": "ok"}
