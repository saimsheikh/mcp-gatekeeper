"""Tests for config parsing, validation, and compilation into a policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from mcp_gatekeeper.config.loader import ConfigError, load_config, parse_config
from mcp_gatekeeper.config.models import HttpUpstream, StdioUpstream
from mcp_gatekeeper.policy.models import Action

MINIMAL: dict[str, Any] = {"version": 1}


def config(**overrides: Any) -> dict[str, Any]:
    return {**MINIMAL, **overrides}


class TestDefaults:
    def test_minimal_config_is_valid(self) -> None:
        parsed = parse_config(MINIMAL)
        assert parsed.version == 1
        assert parsed.upstreams == []

    def test_default_policy_is_require_approval(self) -> None:
        # The safe default is the headline promise of the tool; pin it.
        assert parse_config(MINIMAL).policy.default is Action.REQUIRE_APPROVAL

    def test_default_approval_mode_is_auto(self) -> None:
        assert parse_config(MINIMAL).approvals.mode == "auto"

    def test_default_timeout_denies(self) -> None:
        approvals = parse_config(MINIMAL).approvals
        assert approvals.on_timeout == "deny"
        assert approvals.timeout_seconds == 300.0

    def test_ui_binds_to_loopback_by_default(self) -> None:
        # v0.1 has no authentication, so the default must not be 0.0.0.0.
        assert parse_config(MINIMAL).approvals.ui.host == "127.0.0.1"


class TestUpstreams:
    def test_stdio_upstream(self) -> None:
        parsed = parse_config(
            config(upstreams=[{"name": "fs", "command": "npx", "args": ["-y", "server"]}])
        )
        upstream = parsed.upstreams[0]
        assert isinstance(upstream, StdioUpstream)
        assert upstream.command == "npx"
        assert upstream.args == ["-y", "server"]

    def test_stdio_is_the_default_transport(self) -> None:
        parsed = parse_config(config(upstreams=[{"name": "fs", "command": "npx"}]))
        assert parsed.upstreams[0].transport == "stdio"

    def test_http_upstream(self) -> None:
        parsed = parse_config(
            config(
                upstreams=[{"name": "gh", "transport": "http", "url": "https://example.com/mcp"}]
            )
        )
        upstream = parsed.upstreams[0]
        assert isinstance(upstream, HttpUpstream)
        assert upstream.url == "https://example.com/mcp"

    def test_http_upstream_requires_a_url(self) -> None:
        with pytest.raises(ConfigError, match="url"):
            parse_config(config(upstreams=[{"name": "gh", "transport": "http"}]))

    def test_http_url_must_be_http(self) -> None:
        with pytest.raises(ConfigError, match="http://"):
            parse_config(
                config(upstreams=[{"name": "gh", "transport": "http", "url": "ftp://x/mcp"}])
            )

    def test_duplicate_upstream_names_are_rejected(self) -> None:
        with pytest.raises(ConfigError, match="duplicate upstream name"):
            parse_config(
                config(
                    upstreams=[
                        {"name": "fs", "command": "a"},
                        {"name": "fs", "command": "b"},
                    ]
                )
            )

    def test_upstream_name_cannot_contain_the_separator(self) -> None:
        # Otherwise 'a__b__tool' would be ambiguous to split.
        with pytest.raises(ConfigError, match="namespace separator"):
            parse_config(config(upstreams=[{"name": "a__b", "command": "x"}]))

    @pytest.mark.parametrize("name", ["has space", "has/slash", "has.dot", "has:colon"])
    def test_upstream_name_charset_is_restricted(self, name: str) -> None:
        with pytest.raises(ConfigError):
            parse_config(config(upstreams=[{"name": name, "command": "x"}]))

    @pytest.mark.parametrize("name", ["fs", "my-server", "my_server", "srv2"])
    def test_valid_upstream_names(self, name: str) -> None:
        assert parse_config(config(upstreams=[{"name": name, "command": "x"}]))


class TestPolicySection:
    def test_rules_compile_in_order(self) -> None:
        parsed = parse_config(
            config(
                policy={
                    "default": "deny",
                    "rules": [
                        {"tool": "fs__read_*", "action": "allow"},
                        {"tool": "fs__*", "action": "require_approval"},
                    ],
                }
            )
        )
        policy = parsed.build_policy()
        assert policy.default is Action.DENY
        assert [rule.tool for rule in policy.rules] == ["fs__read_*", "fs__*"]
        assert policy.rules[0].action is Action.ALLOW

    def test_argument_condition_compiles(self) -> None:
        parsed = parse_config(
            config(
                policy={
                    "rules": [
                        {
                            "tool": "fs__write_file",
                            "action": "deny",
                            "when": {"args": {"path": "/prod/**"}},
                        }
                    ]
                }
            )
        )
        condition = parsed.build_policy().rules[0].condition
        assert len(condition.arguments) == 1
        assert condition.arguments[0].path == "path"
        assert condition.arguments[0].pattern == "/prod/**"

    def test_annotation_condition_compiles(self) -> None:
        parsed = parse_config(
            config(
                policy={
                    "rules": [
                        {
                            "tool": "*",
                            "action": "require_approval",
                            "when": {"destructive_hint": True},
                        }
                    ]
                }
            )
        )
        assert parsed.build_policy().rules[0].condition.destructive is True

    def test_rule_reason_is_preserved(self) -> None:
        parsed = parse_config(
            config(policy={"rules": [{"tool": "*", "action": "deny", "reason": "no"}]})
        )
        assert parsed.build_policy().rules[0].reason == "no"

    def test_unknown_action_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="action"):
            parse_config(config(policy={"rules": [{"tool": "*", "action": "maybe"}]}))

    def test_rule_referencing_an_unknown_upstream_is_rejected(self) -> None:
        # Catches a typo that would otherwise produce a rule that never fires.
        with pytest.raises(ConfigError, match="unknown upstream"):
            parse_config(
                config(
                    upstreams=[{"name": "fs", "command": "x"}],
                    policy={"rules": [{"tool": "*", "action": "deny", "upstream": "typo"}]},
                )
            )

    def test_rule_referencing_a_known_upstream_is_accepted(self) -> None:
        parsed = parse_config(
            config(
                upstreams=[{"name": "fs", "command": "x"}],
                policy={"rules": [{"tool": "*", "action": "deny", "upstream": "fs"}]},
            )
        )
        assert parsed.build_policy().rules[0].upstream == "fs"


class TestStrictness:
    def test_unknown_top_level_key_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="policies"):
            parse_config(config(policies={}))

    def test_misspelled_rule_key_is_rejected(self) -> None:
        # 'acton: deny' would otherwise read as a denial but evaluate as the
        # default. Loud failure is the whole point of extra="forbid".
        with pytest.raises(ConfigError):
            parse_config(config(policy={"rules": [{"tool": "*", "acton": "deny"}]}))

    def test_unknown_when_key_is_rejected(self) -> None:
        with pytest.raises(ConfigError):
            parse_config(
                config(policy={"rules": [{"tool": "*", "action": "deny", "when": {"arg": {}}}]})
            )

    def test_unsupported_version_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="version"):
            parse_config({"version": 2})

    @pytest.mark.parametrize("port", [0, 65536, -1])
    def test_invalid_port_is_rejected(self, port: int) -> None:
        with pytest.raises(ConfigError):
            parse_config(config(approvals={"ui": {"port": port}}))

    @pytest.mark.parametrize("timeout", [0, -5])
    def test_non_positive_timeout_is_rejected(self, timeout: float) -> None:
        with pytest.raises(ConfigError):
            parse_config(config(approvals={"timeout_seconds": timeout}))


class TestErrorMessages:
    def test_names_the_offending_field(self) -> None:
        with pytest.raises(ConfigError) as error:
            parse_config(config(policy={"rules": [{"tool": "*", "action": "nope"}]}))
        message = str(error.value)
        assert "policy.rules.0.action" in message

    def test_rejects_a_non_mapping_document(self) -> None:
        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            parse_config([1, 2, 3])

    def test_rejects_an_empty_document(self) -> None:
        with pytest.raises(ConfigError, match="empty"):
            parse_config(None)


class TestLoadConfig:
    def test_round_trip_from_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "gatekeeper.yaml"
        path.write_text(
            yaml.safe_dump(
                config(
                    upstreams=[{"name": "fs", "command": "npx"}],
                    policy={"rules": [{"tool": "fs__read_*", "action": "allow"}]},
                )
            ),
            encoding="utf-8",
        )
        parsed = load_config(path)
        assert parsed.upstreams[0].name == "fs"
        assert parsed.build_policy().rules[0].action is Action.ALLOW

    def test_missing_file_message(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="config file not found"):
            load_config(tmp_path / "absent.yaml")

    def test_malformed_yaml_message(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("key: [unclosed", encoding="utf-8")
        with pytest.raises(ConfigError, match="not valid YAML"):
            load_config(path)

    def test_error_message_names_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "gatekeeper.yaml"
        path.write_text(yaml.safe_dump({"version": 1, "nope": True}), encoding="utf-8")
        with pytest.raises(ConfigError, match=r"gatekeeper\.yaml"):
            load_config(path)
