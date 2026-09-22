"""Tests for the command line interface.

``run`` is covered by the integration tests rather than here; what matters at
this level is that bad input fails loudly with a message a human can act on,
and that ``validate`` tells the truth about what a config would do.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from mcp_gatekeeper import __version__
from mcp_gatekeeper.cli import app

runner = CliRunner()


def write_config(path: Path, **overrides: Any) -> Path:
    document: dict[str, Any] = {
        "version": 1,
        "upstreams": [{"name": "fs", "command": "npx", "args": ["-y", "server"]}],
        "policy": {
            "default": "require_approval",
            "rules": [
                {"tool": "fs__read_*", "action": "allow", "reason": "reads are safe"},
                {
                    "tool": "fs__write_file",
                    "action": "deny",
                    "when": {"args": {"path": "/prod/**"}},
                },
            ],
        },
        **overrides,
    }
    config = path / "gatekeeper.yaml"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    return config


class TestValidate:
    def test_accepts_a_good_config(self, tmp_path: Path) -> None:
        config = write_config(tmp_path)
        result = runner.invoke(app, ["validate", "--config", str(config)])

        assert result.exit_code == 0
        assert "is valid" in result.output

    def test_summarises_upstreams_and_rules(self, tmp_path: Path) -> None:
        config = write_config(tmp_path)
        result = runner.invoke(app, ["validate", "--config", str(config)])

        assert "fs" in result.output
        assert "fs__read_*" in result.output
        assert "first match wins" in result.output
        # Argument conditions are shown, so a rule's real scope is visible.
        assert "path~/prod/**" in result.output

    def test_reports_the_default(self, tmp_path: Path) -> None:
        config = write_config(tmp_path)
        result = runner.invoke(app, ["validate", "--config", str(config)])
        assert "default: require_approval" in result.output

    def test_rejects_an_invalid_config(self, tmp_path: Path) -> None:
        config = tmp_path / "gatekeeper.yaml"
        config.write_text(yaml.safe_dump({"version": 1, "nope": True}), encoding="utf-8")

        result = runner.invoke(app, ["validate", "--config", str(config)])
        assert result.exit_code == 1
        assert "Configuration error" in result.output

    def test_missing_file_is_reported_clearly(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["validate", "--config", str(tmp_path / "absent.yaml")])
        assert result.exit_code == 1
        assert "config file not found" in result.output

    def test_warns_when_the_default_is_allow(self, tmp_path: Path) -> None:
        # Fail-open is permitted but must never be silent.
        config = write_config(tmp_path, policy={"default": "allow", "rules": []})
        result = runner.invoke(app, ["validate", "--config", str(config)])

        assert result.exit_code == 0
        assert "Warning" in result.output
        assert "forwarded unchecked" in result.output

    def test_warns_when_timeout_allows(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, approvals={"on_timeout": "allow"})
        result = runner.invoke(app, ["validate", "--config", str(config)])

        assert "Warning" in result.output
        assert "nobody answers" in result.output

    def test_no_warning_for_safe_defaults(self, tmp_path: Path) -> None:
        config = write_config(tmp_path)
        result = runner.invoke(app, ["validate", "--config", str(config)])
        assert "Warning" not in result.output

    def test_notes_when_there_are_no_upstreams(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, upstreams=[])
        result = runner.invoke(app, ["validate", "--config", str(config)])
        assert "no tools" in result.output


class TestRun:
    def test_rejects_an_unknown_transport(self, tmp_path: Path) -> None:
        config = write_config(tmp_path)
        result = runner.invoke(
            app, ["run", "--config", str(config), "--transport", "carrier-pigeon"]
        )
        assert result.exit_code == 2
        assert "Unknown transport" in result.output

    def test_bad_config_fails_before_anything_starts(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["run", "--config", str(tmp_path / "absent.yaml")])
        assert result.exit_code == 1


class TestExport:
    def test_writes_jsonl_to_a_file(self, tmp_path: Path) -> None:
        import anyio

        from mcp_gatekeeper.audit.models import AuditEvent, Outcome
        from mcp_gatekeeper.audit.store import SqliteAuditStore
        from mcp_gatekeeper.db import Database
        from mcp_gatekeeper.policy.models import Action, Decision

        database_path = tmp_path / "audit.db"

        async def seed() -> None:
            async with Database(database_path) as database:
                await SqliteAuditStore(database).record(
                    AuditEvent.build(
                        event_id="one",
                        tool="fs__write_file",
                        upstream="fs",
                        arguments={"path": "/prod/db.yaml"},
                        decision=Decision(action=Action.DENY, source="rule", rule_index=0),
                        outcome=Outcome.DENIED_BY_POLICY,
                    )
                )

        anyio.run(seed)

        config = write_config(tmp_path, audit={"database": str(database_path)})
        output = tmp_path / "audit.jsonl"
        result = runner.invoke(app, ["export", "--config", str(config), "--output", str(output)])

        assert result.exit_code == 0
        lines = [line for line in output.read_text(encoding="utf-8").splitlines() if line]
        assert len(lines) == 1
        assert json.loads(lines[0])["tool"] == "fs__write_file"

    def test_empty_log_exports_nothing(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, audit={"database": str(tmp_path / "empty.db")})
        output = tmp_path / "out.jsonl"
        result = runner.invoke(app, ["export", "--config", str(config), "--output", str(output)])

        assert result.exit_code == 0
        assert output.read_text(encoding="utf-8").strip() == ""


class TestVersion:
    def test_prints_the_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in result.output


class TestHelp:
    @pytest.mark.parametrize("command", ["validate", "run", "export"])
    def test_every_command_has_help(self, command: str) -> None:
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0

    def test_bare_invocation_shows_help(self) -> None:
        result = runner.invoke(app, [])
        assert "Policy, approval, and audit" in result.output
