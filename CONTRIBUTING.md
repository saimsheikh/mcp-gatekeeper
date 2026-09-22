# Contributing

Thanks for taking a look. This is a young project and the surface area is
small, so a first contribution is realistically a weekend afternoon.

## Getting set up

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/saimsheikh/mcp-gatekeeper
cd mcp-gatekeeper
uv sync --all-groups
uv run pytest
```

If the tests pass, you have a working environment.

To see the thing actually run:

```bash
# terminal 1
cd examples/filesystem
uv run mcp-gatekeeper run --config gatekeeper.yaml --transport http --port 8810

# terminal 2
uv run python examples/try_it.py
```

The write call parks until you click **Approve** at http://localhost:8765.

## Before you open a PR

Four commands, the same ones CI runs:

```bash
uv run pytest
uv run ruff check .
uv run ruff format .
uv run pyright
```

All four must be clean. `pyright` runs in strict mode and there is currently a
zero-error baseline — please keep it there. Prefer restructuring over `Any`;
where a boundary really is untyped (YAML documents, SDK `_meta`), use an
explicit `cast` with a comment saying why.

## Conventions

[`CLAUDE.md`](CLAUDE.md) has the full set. The ones that trip people up:

- **Policy evaluation is pure.** No I/O, no clock, no globals anywhere in
  `policy/`. This is what makes it exhaustively testable — please don't erode
  it. If your feature needs I/O, it belongs in `gateway.py`.
- **Dependencies are passed explicitly.** No module-level singletons.
- **stdout belongs to the protocol** when serving over stdio. All output goes
  to stderr via `cli.echo` or `logging`. A stray `print` breaks the session.
- **Verify SDK APIs against the installed version.** This targets the
  2026-07-28 MCP revision and SDK 2.x, which changed a lot. Don't trust older
  tutorials, or an LLM's memory of the pre-2.x SDK.

## The fail-safe rules

Some defaults are load-bearing rather than incidental. Changing one is a design
decision to raise in an issue first, not a cleanup to slip into a PR:

- The default policy action is `require_approval`.
- A timeout denies. Silence is never consent.
- An unstated value never satisfies a condition — `None` means "not stated",
  never "false".
- The client cannot approve its own call.
- Redaction happens before the write, not before the render.

If your change makes any of these weaker, say so explicitly in the PR
description. That's not a blocker, it's just something that needs to be a
conscious choice.

## Tests

- **Policy and glob matching are exhaustively tested.** If you touch
  `policy/`, add cases — including the ones that should *not* match.
- **The proxy is tested against a real MCP server**
  (`tests/fixtures/fake_upstream.py`) over a real client, not a mock. Please
  keep it that way; mocking the SDK would hide exactly the breakage that
  matters.
- Build gateways inside `async with` **in the test body**, via the `gateways`
  factory. The upstream client owns an anyio task group and anyio requires it
  entered and exited in the same task, so a fixture that yields across that
  boundary trips "cancel scope in a different task".

A bug fix should come with a test that fails without it.

## Commits

Conventional commits, one logical change each:

```
feat(policy): match rules on tool annotations
fix(approvals): settle the queue entry when a client dismisses
docs: explain the multi-round-trip approval flow
```

Say *why* in the body, not just what. The diff already shows what.

## Good first issues

Issues tagged [`good first issue`](https://github.com/saimsheikh/mcp-gatekeeper/labels/good%20first%20issue)
are scoped to be self-contained. If one is unclear, ask in the issue — a
question that improves the description is a contribution.

## Security

The approval UI has **no authentication** in v0.1: it binds to loopback and
treats the approval id as a capability. That is a known, documented limitation
rather than an oversight.

If you find something that undermines a fail-safe rule above — a way to bypass
policy, approve without a human, or leak a redacted value — please open a
regular issue for now, since the project has no private disclosure channel yet.
Don't include real credentials in the report.

## Scope

v0.1 deliberately leaves out OAuth, rate limiting, a heavy frontend, and cloud
deployment, with extension points in place for each. The roadmap in the README
tracks what's next. A PR that adds a big new subsystem is more likely to land
if it starts as an issue describing the shape first.
