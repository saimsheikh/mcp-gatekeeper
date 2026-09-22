"""Command line interface.

``run`` starts the gatekeeper; ``validate`` checks a config without starting
anything; ``export`` writes the audit trail out as JSONL.

One rule shapes this module: when serving over stdio, **stdout belongs to the
protocol**. Every log line, banner, and error message goes to stderr, because a
stray print would be parsed as a JSON-RPC frame and break the session.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Annotated, Any

import anyio
import typer

from mcp_gatekeeper import __version__
from mcp_gatekeeper.approvals.service import ApprovalService
from mcp_gatekeeper.approvals.store import SqliteApprovalStore
from mcp_gatekeeper.audit.store import NullAuditStore, SqliteAuditStore
from mcp_gatekeeper.config.loader import ConfigError, load_config
from mcp_gatekeeper.config.models import GatekeeperConfig
from mcp_gatekeeper.db import Database
from mcp_gatekeeper.policy.models import Action
from mcp_gatekeeper.proxy.gateway import Gateway, GatewayDeps
from mcp_gatekeeper.proxy.registry import ToolRegistry
from mcp_gatekeeper.proxy.server import build_server
from mcp_gatekeeper.proxy.upstream import UpstreamManager
from mcp_gatekeeper.ui.app import build_ui

app = typer.Typer(
    name="mcp-gatekeeper",
    help="Policy, approval, and audit for MCP tool calls.",
    no_args_is_help=True,
    add_completion=False,
)

CONFIG_OPTION = typer.Option("--config", "-c", help="Path to gatekeeper.yaml.", show_default=True)


def echo(message: str) -> None:
    """Write to stderr, never stdout."""
    typer.echo(message, err=True)


def _load(path: Path) -> GatekeeperConfig:
    try:
        return load_config(path)
    except ConfigError as error:
        echo(typer.style("Configuration error", fg=typer.colors.RED, bold=True))
        echo(str(error))
        raise typer.Exit(code=1) from error


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )


@app.command()
def validate(
    config: Annotated[Path, CONFIG_OPTION] = Path("gatekeeper.yaml"),
) -> None:
    """Check a config file and summarise what it would do."""
    parsed = _load(config)
    policy = parsed.build_policy()

    echo(typer.style(f"{config} is valid.", fg=typer.colors.GREEN, bold=True))
    echo("")

    echo(f"Upstreams ({len(parsed.upstreams)}):")
    for upstream in parsed.upstreams:
        if upstream.transport == "stdio":
            target = f"{upstream.command} {' '.join(upstream.args)}".strip()
        else:
            target = upstream.url
        echo(f"  {upstream.name:<16} {upstream.transport:<6} {target}")
    if not parsed.upstreams:
        echo("  (none -- the gatekeeper would expose no tools)")

    echo("")
    echo(f"Policy rules ({len(policy.rules)}), first match wins:")
    for index, rule in enumerate(policy.rules):
        bits: list[str] = []
        if rule.upstream:
            bits.append(f"upstream={rule.upstream}")
        for argument in rule.condition.arguments:
            bits.append(f"{argument.path}~{argument.pattern}")
        for label, value in (
            ("read_only", rule.condition.read_only),
            ("destructive", rule.condition.destructive),
            ("idempotent", rule.condition.idempotent),
            ("open_world", rule.condition.open_world),
        ):
            if value is not None:
                bits.append(f"{label}={str(value).lower()}")
        suffix = f"  [{', '.join(bits)}]" if bits else ""
        echo(f"  {index:>2}. {rule.tool:<28} -> {rule.action.value}{suffix}")

    echo(f"  default: {policy.default.value}")

    if policy.default is Action.ALLOW:
        echo("")
        echo(
            typer.style(
                "Warning: default is 'allow', so any tool without a matching rule "
                "is forwarded unchecked.",
                fg=typer.colors.YELLOW,
            )
        )
    if parsed.approvals.on_timeout == "allow":
        echo(
            typer.style(
                "Warning: on_timeout is 'allow', so calls nobody answers are forwarded.",
                fg=typer.colors.YELLOW,
            )
        )


@app.command()
def run(
    config: Annotated[Path, CONFIG_OPTION] = Path("gatekeeper.yaml"),
    transport: Annotated[
        str, typer.Option(help="How clients reach the gatekeeper: 'stdio' or 'http'.")
    ] = "stdio",
    host: Annotated[str, typer.Option(help="Bind host when transport is http.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port when transport is http.")] = 8000,
    no_ui: Annotated[bool, typer.Option("--no-ui", help="Do not start the approval UI.")] = False,
    log_level: Annotated[str, typer.Option(help="Logging verbosity.")] = "info",
) -> None:
    """Start the gatekeeper."""
    _configure_logging(log_level)
    parsed = _load(config)

    if transport not in {"stdio", "http"}:
        echo(f"Unknown transport {transport!r}; expected 'stdio' or 'http'.")
        raise typer.Exit(code=2)

    try:
        anyio.run(
            _serve,
            parsed,
            transport,
            host,
            port,
            no_ui,
        )
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        echo("Shutting down.")


async def _serve(
    config: GatekeeperConfig,
    transport: str,
    host: str,
    port: int,
    no_ui: bool,
) -> None:
    """Wire everything together and run until interrupted."""
    import uvicorn
    from mcp.server.stdio import stdio_server

    async with Database(config.audit.database) as database:
        audit = SqliteAuditStore(database) if config.audit.enabled else NullAuditStore()
        approvals = ApprovalService(
            store=SqliteApprovalStore(database),
            timeout_seconds=config.approvals.timeout_seconds,
            approve_on_timeout=config.approvals.on_timeout == "allow",
        )

        async with UpstreamManager(upstreams=config.upstreams) as upstreams:
            for name, reason in upstreams.failures.items():
                echo(
                    typer.style(
                        f"Upstream {name!r} did not start: {reason}", fg=typer.colors.YELLOW
                    )
                )
            if not upstreams.connections:
                echo(
                    typer.style(
                        "No upstreams connected; the gatekeeper will expose no tools.",
                        fg=typer.colors.YELLOW,
                    )
                )

            gateway = Gateway(
                GatewayDeps(
                    policy=config.build_policy(),
                    upstreams=upstreams,
                    approvals=approvals,
                    audit=audit,
                    registry=ToolRegistry(tools={}),
                    approval_mode=config.approvals.mode,
                    ui_base_url=config.approvals.ui.base_url,
                    redact=tuple(config.audit.redact),
                )
            )
            await gateway.refresh_registry()

            server = build_server(
                gateway,
                name=config.server.name,
                version=config.server.version,
                instructions=config.server.instructions,
            )

            async with anyio.create_task_group() as tg:
                if not no_ui:
                    ui = build_ui(
                        approvals=approvals,
                        audit=SqliteAuditStore(database),
                        title=config.server.name,
                    )
                    ui_config = uvicorn.Config(
                        ui,
                        host=config.approvals.ui.host,
                        port=config.approvals.ui.port,
                        log_level="warning",
                        access_log=False,
                    )
                    tg.start_soon(uvicorn.Server(ui_config).serve)
                    echo(f"Approval UI: {config.approvals.ui.base_url}")

                tools = len(gateway.registry.tools)
                echo(
                    f"mcp-gatekeeper {__version__} ready: "
                    f"{tools} tool{'' if tools == 1 else 's'} from "
                    f"{len(upstreams.connections)} upstream(s), "
                    f"default policy '{config.policy.default.value}'."
                )

                if transport == "stdio":
                    async with stdio_server() as (read_stream, write_stream):
                        await server.run(
                            read_stream, write_stream, server.create_initialization_options()
                        )
                else:
                    http_config = uvicorn.Config(
                        server.streamable_http_app(),
                        host=host,
                        port=port,
                        log_level="warning",
                    )
                    echo(f"MCP endpoint: http://{host}:{port}/mcp")
                    await uvicorn.Server(http_config).serve()

                tg.cancel_scope.cancel()


@app.command()
def export(
    config: Annotated[Path, CONFIG_OPTION] = Path("gatekeeper.yaml"),
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write here instead of stdout.")
    ] = None,
) -> None:
    """Write the audit log as JSONL, oldest first."""
    parsed = _load(config)

    async def dump() -> int:
        written = 0
        async with Database(parsed.audit.database) as database:
            store = SqliteAuditStore(database)
            handle = output.open("w", encoding="utf-8") if output else sys.stdout
            try:
                async for line in store.export_jsonl():
                    handle.write(line + "\n")
                    written += 1
            finally:
                if output:
                    handle.close()
        return written

    count = anyio.run(dump)
    if output:
        echo(f"Wrote {count} event(s) to {output}.")


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


def main() -> Any:  # pragma: no cover - console script entry point
    return app()


if __name__ == "__main__":  # pragma: no cover
    main()
