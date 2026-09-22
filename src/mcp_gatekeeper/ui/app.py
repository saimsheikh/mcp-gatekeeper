"""The approval and audit web UI.

FastAPI with server-rendered Jinja templates and HTMX for the live bits. No
build step, no bundler, no npm: an approver opens a link and clicks a button,
and that should not require a frontend toolchain to ship.

Forms post normally, so approving works even with JavaScript disabled; HTMX
only upgrades the pending list to refresh itself.

**No authentication.** v0.1 binds to loopback and relies on unguessable
approval ids. See the README's security note before exposing this port.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from mcp_gatekeeper.approvals.service import ApprovalService
from mcp_gatekeeper.audit.store import SqliteAuditStore
from mcp_gatekeeper.policy.models import Action

__all__ = ["build_ui"]

TEMPLATES = Path(__file__).parent / "templates"
ANONYMOUS = "anonymous"


def _pretty_arguments(arguments: dict[str, Any]) -> str:
    import json

    return json.dumps(arguments, indent=2, sort_keys=True, default=str)


def build_ui(
    *,
    approvals: ApprovalService,
    audit: SqliteAuditStore,
    title: str = "mcp-gatekeeper",
) -> FastAPI:
    """Construct the web app with its dependencies bound in.

    Dependencies are closed over rather than read from module state, so tests
    can stand up an app against a temporary database.
    """
    app = FastAPI(title=title, docs_url=None, redoc_url=None)
    templates = Jinja2Templates(directory=str(TEMPLATES))
    templates.env.filters["pretty_json"] = _pretty_arguments

    def context(request: Request, **extra: Any) -> dict[str, Any]:
        return {"request": request, "title": title, "now": datetime.now(UTC), **extra}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> Any:
        pending = await approvals.pending()
        events = await audit.recent(limit=20)
        return templates.TemplateResponse(
            request, "index.html", context(request, pending=pending, events=events)
        )

    @app.get("/approvals/pending", response_class=HTMLResponse)
    async def pending_fragment(request: Request) -> Any:
        """The HTMX-polled fragment behind the live queue."""
        pending = await approvals.pending()
        return templates.TemplateResponse(
            request, "_pending.html", context(request, pending=pending)
        )

    @app.get("/approvals/{approval_id}", response_class=HTMLResponse)
    async def approval_detail(request: Request, approval_id: str) -> Any:
        """The page an elicitation link points at."""
        approval = await approvals.get(approval_id)
        status_code = 200 if approval else 404
        return templates.TemplateResponse(
            request,
            "approval.html",
            context(request, approval=approval, approval_id=approval_id),
            status_code=status_code,
        )

    @app.post("/approvals/{approval_id}/decide")
    async def decide(
        approval_id: str,
        decision: Annotated[str, Form()],
        approver: Annotated[str, Form()] = ANONYMOUS,
        note: Annotated[str, Form()] = "",
        redirect_to: Annotated[str, Form()] = "",
    ) -> RedirectResponse:
        await approvals.decide(
            approval_id,
            approved=decision == "approve",
            approver=approver.strip() or ANONYMOUS,
            note=note.strip() or None,
        )
        # Deciding from the queue returns to the queue; deciding from a detail
        # page stays there. Only known-safe local targets, so a crafted form
        # cannot turn this into an open redirect.
        target = "/" if redirect_to == "/" else f"/approvals/{approval_id}"
        # PRG, so a refresh does not resubmit the decision.
        return RedirectResponse(target, status_code=303)

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_log(
        request: Request,
        tool: str | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Any:
        parsed_action = Action(action) if action in {a.value for a in Action} else None
        events = await audit.recent(
            limit=min(limit, 500), offset=max(offset, 0), tool=tool, action=parsed_action
        )
        total = await audit.count()
        return templates.TemplateResponse(
            request,
            "audit.html",
            context(
                request,
                events=events,
                total=total,
                tool=tool or "",
                action=action or "",
                limit=limit,
                offset=offset,
                actions=[a.value for a in Action],
            ),
        )

    @app.get("/audit/export.jsonl")
    async def export_jsonl() -> StreamingResponse:
        async def lines() -> AsyncIterator[str]:
            async for line in audit.export_jsonl():
                yield line + "\n"

        return StreamingResponse(
            lines(),
            media_type="application/x-ndjson",
            headers={"Content-Disposition": 'attachment; filename="audit.jsonl"'},
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
