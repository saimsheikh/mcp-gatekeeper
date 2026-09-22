# CLAUDE.md

Conventions for working in this repository. Read before making changes.

## What this is

A proxy between MCP clients and upstream MCP servers that applies policy,
requests human approval, and writes an audit trail. It impersonates a server
to the client and a client to the upstreams.

## Protocol: check before you assume

This targets the **2026-07-28** MCP revision via the `mcp` Python SDK (2.x).
That revision changed things that older material still describes wrongly:

- MCP is **stateless**. There is no `initialize` handshake and no session id.
- Client capabilities and identity arrive in **each request's `_meta`**
  (`io.modelcontextprotocol/clientCapabilities`, `.../clientInfo`). Read them
  per request; never cache them across calls.
- Server-initiated requests are replaced by **MRTR**: a handler returns
  `InputRequiredResult` and the client retries carrying `inputResponses`.
- `tools/list` results must carry `ttlMs` and `cacheScope`.
- **Roots, Sampling, and Logging are deprecated.** Do not build on them.

**Before using an SDK API, verify it against the installed version** —
`uv run python -c "import mcp; help(mcp.X)"` or read
`.venv/Lib/site-packages/mcp/`. Do not rely on memory of pre-2.x SDKs.

Construct SDK models with **snake_case field names** (`input_schema`,
`is_error`, `ttl_ms`), not the camelCase wire aliases. Both work at runtime;
only snake_case type-checks.

## Non-negotiables

- **`src/` layout.** Small modules, one responsibility each.
- **Full type hints. `pyright` strict must pass with zero errors.** Prefer
  restructuring over `Any`; use explicit `cast` at untyped boundaries (YAML
  documents, SDK `_meta`) and never `# type: ignore` without a reason beside it.
- **`ruff check` and `ruff format` must pass.**
- **Policy evaluation stays pure.** No I/O, no clock, no globals in
  `policy/`. This is what makes it exhaustively testable; do not erode it.
- **No global state.** Dependencies are constructor-injected. If you reach for
  a module-level singleton, pass it instead.
- **Conventional commits, one logical change per commit.**

## Fail-safe rules

Security defaults are load-bearing. Changing any of these is a decision, not a
cleanup:

- The default policy action is `require_approval`.
- A timeout denies. Silence is never consent.
- An absent or unstated value never satisfies a condition. `None` means
  "not stated", never "false".
- A container argument is unmatchable rather than stringified.
- The client cannot approve its own call; the queue holds the decision of
  record.
- Redaction happens before the write, not before the render.

## Testing

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run pyright
```

- Policy and glob matching are **exhaustively** unit-tested. Add cases when
  you touch them.
- The proxy is tested against a real MCP server (`tests/fixtures/fake_upstream.py`)
  over a real client, not a mock. Keep it that way — mocking the SDK would
  hide exactly the breakage that matters.
- Build gateways inside `async with` **in the test body**, via the
  `gateways` factory. The upstream client owns an anyio task group, and anyio
  requires it entered and exited in the same task; a fixture that yields across
  that boundary trips "cancel scope in a different task".
- `anyio` `start_soon` passes arguments positionally only.

## Gotchas

- **stdout belongs to the protocol** when serving over stdio. All CLI output
  and logging goes to stderr via `cli.echo` or `logging`. A stray `print`
  breaks the session.
- Upstream names may not contain `__`; it is the namespace separator, and
  names split on the **first** occurrence so upstream tools containing `__`
  survive.
- Redaction patterns are dotted key paths translated to `/` internally so the
  policy globber's boundary rules apply.
- A trailing `/**` deliberately matches the parent directory too.

## Layout

```
src/mcp_gatekeeper/
  policy/      glob.py, models.py, engine.py   -- pure
  config/      models.py (Pydantic), loader.py
  proxy/       upstream.py, registry.py, gateway.py, server.py
  approvals/   models.py, store.py, service.py
  audit/       models.py, store.py
  ui/          app.py, templates/
  db.py        shared SQLite
  cli.py
```

`gateway.py` is the only place policy, approvals, audit, and forwarding meet.
Keep the others unaware of each other.
