#!/usr/bin/env python
"""Drive a running mcp-gatekeeper with a real MCP client.

Start the gatekeeper first, in another terminal:

    cd examples/filesystem
    mcp-gatekeeper run --config gatekeeper.yaml --transport http --port 8810

Then:

    python examples/try_it.py            # you approve, by hand, in the web UI
    python examples/try_it.py --auto     # approve automatically, for a quick check

The default mode is the one worth watching. The write call parks, this script
waits, and nothing moves until you click Approve at http://localhost:8765.

Why the waiting matters: under the multi-round-trip pattern the gatekeeper
hands the client a link and returns. It is the *client* that decides how long
to leave the prompt open -- Claude Desktop keeps its dialog up until you
dismiss it. So a client that returns immediately, without a human having
decided, is telling the gatekeeper the prompt was dismissed. The call is then
refused and the queue entry settled, which is correct but looks like nothing
happened. This script waits properly.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import anyio
from mcp import types
from mcp.client import Client

MCP_URL = "http://127.0.0.1:8810/mcp"
UI_URL = "http://127.0.0.1:8765"
POLL_SECONDS = 1.0


def approval_status(approval_id: str) -> str | None:
    """Read a request's status straight from the audit export.

    Uses only public endpoints, so this works against any running instance.
    """
    try:
        raw = urllib.request.urlopen(f"{UI_URL}/approvals/{approval_id}", timeout=5).read()
    except urllib.error.URLError:
        return None
    page = raw.decode("utf-8", "replace")
    for status in ("approved", "denied", "expired"):
        if f'class="pill {status}"' in page:
            return status
    return "pending" if 'class="pill pending"' in page else None


def click_approve(approval_id: str, who: str) -> int:
    """Post the decision form exactly as the browser does."""
    body = urllib.parse.urlencode({"decision": "approve", "approver": who}).encode()
    request = urllib.request.Request(
        f"{UI_URL}/approvals/{approval_id}/decide", data=body, method="POST"
    )
    try:
        return urllib.request.urlopen(request).status
    except urllib.error.HTTPError as error:
        return error.code


def banner(text: str) -> None:
    print(f"\n{text}\n{'-' * len(text)}", flush=True)


async def wait_for_human(approval_id: str, timeout: float) -> str:
    """Poll until somebody decides, or the request runs out of time."""
    waited = 0.0
    last = ""
    while waited < timeout:
        status = approval_status(approval_id) or "pending"
        if status != "pending":
            print()
            return status
        if status != last:
            print("   still waiting", end="", flush=True)
            last = status
        else:
            print(".", end="", flush=True)
        await anyio.sleep(POLL_SECONDS)
        waited += POLL_SECONDS
    print()
    return "timeout"


def make_elicitation_callback(auto: bool, approver: str):  # noqa: ANN201 - SDK callback shape
    async def elicit(context: object, params: object) -> types.ElicitResult:
        url = str(getattr(params, "url", ""))
        approval_id = url.rsplit("/", 1)[-1]

        if auto:
            status = click_approve(approval_id, approver)
            print(f"   approving automatically as {approver!r} -> HTTP {status}")
            return types.ElicitResult(action="accept")

        print(f"   >>> OPEN THIS AND CLICK APPROVE: {url}")
        outcome = await wait_for_human(approval_id, timeout=280.0)
        print(f"   decision recorded: {outcome}")
        # 'accept' only tells the gatekeeper to re-check the queue; the decision
        # of record is the one a human made there, so this cannot self-approve.
        return types.ElicitResult(action="accept" if outcome == "approved" else "decline")

    return elicit


async def run(auto: bool, approver: str) -> int:
    callback = make_elicitation_callback(auto, approver)
    async with Client(
        MCP_URL,
        elicitation_callback=callback,
        client_info=types.Implementation(name="mcp-gatekeeper-demo", version="1.0"),
    ) as client:
        listing = await client.list_tools()
        names = sorted(tool.name for tool in listing.tools)
        banner(f"{len(names)} tools behind the gate")
        print(", ".join(names))

        banner("1. Reading a file  (policy: allow -> straight through)")
        read = await client.call_tool("fs__read_text_file", {"path": "notes.txt"})
        print(f"   {text_of(read)!r}   error={read.is_error}")

        banner("2. Writing a file  (policy: require_approval -> stops for a human)")
        write = await client.call_tool(
            "fs__write_file",
            {"path": "approved.txt", "content": "written only after a human approved"},
        )
        print(f"   {text_of(write)}\n   error={write.is_error}")

        banner("Audit trail")
        for event in recent_events():
            print(
                f"   {event['tool']:<22} {event['action']:<18} "
                f"{event['outcome']:<20} approver={event['approval']['approver']}"
            )

        return 1 if write.is_error else 0


def text_of(result: types.CallToolResult) -> str:
    block = result.content[0]
    return block.text.strip() if isinstance(block, types.TextContent) else str(block)


def recent_events() -> list[dict[str, Any]]:
    try:
        raw = urllib.request.urlopen(f"{UI_URL}/audit/export.jsonl", timeout=5).read()
    except urllib.error.URLError:
        return []
    return [json.loads(line) for line in raw.decode().splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--auto", action="store_true", help="Approve automatically instead of waiting for you."
    )
    parser.add_argument("--approver", default="demo-user", help="Name recorded on the decision.")
    args = parser.parse_args()

    try:
        urllib.request.urlopen(f"{UI_URL}/healthz", timeout=3)
    except urllib.error.URLError:
        print(
            f"Cannot reach the gatekeeper UI at {UI_URL}.\n"
            "Start it first:\n"
            "  cd examples/filesystem\n"
            "  mcp-gatekeeper run --config gatekeeper.yaml --transport http --port 8810",
            file=sys.stderr,
        )
        return 2

    return anyio.run(run, args.auto, args.approver)


if __name__ == "__main__":
    raise SystemExit(main())
