"""Pydantic schema for ``gatekeeper.yaml``.

These models mirror the YAML file, which is a separate concern from the
policy value types in :mod:`mcp_gatekeeper.policy.models`. The config layer
owns wire format, defaults, and error messages; the policy layer owns
evaluation. :meth:`GatekeeperConfig.build_policy` is the one bridge between
them, so the file format can change without touching the engine.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mcp_gatekeeper.policy.models import (
    Action,
    ArgumentCondition,
    Policy,
    Rule,
    RuleCondition,
)

__all__ = [
    "ApprovalConfig",
    "AuditConfig",
    "GatekeeperConfig",
    "HttpUpstream",
    "PolicyConfig",
    "RuleConfig",
    "StdioUpstream",
    "Upstream",
    "UpstreamBase",
    "WhenConfig",
]

NAMESPACE_SEPARATOR = "__"


class _Strict(BaseModel):
    """Reject unknown keys everywhere.

    A typo in a policy file should fail loudly at validation time. Silently
    ignoring ``acton: deny`` would leave a rule that reads as a denial but
    evaluates as something else.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class UpstreamBase(_Strict):
    name: Annotated[str, Field(min_length=1)]
    """Namespace prefix for this server's tools, e.g. ``fs`` -> ``fs__read_file``."""

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if NAMESPACE_SEPARATOR in value:
            raise ValueError(
                f"upstream name {value!r} must not contain {NAMESPACE_SEPARATOR!r}; "
                "it is the namespace separator"
            )
        if not value.replace("-", "_").replace("_", "a").isalnum():
            raise ValueError(
                f"upstream name {value!r} must contain only letters, digits, '-' and '_'"
            )
        return value


class StdioUpstream(UpstreamBase):
    """An upstream launched as a subprocess and spoken to over stdio."""

    transport: Literal["stdio"] = "stdio"
    command: Annotated[str, Field(min_length=1)]
    args: list[str] = []
    env: dict[str, str] = {}
    cwd: str | None = None


class HttpUpstream(UpstreamBase):
    """An upstream reached over Streamable HTTP."""

    transport: Literal["http"]
    url: Annotated[str, Field(min_length=1)]
    headers: dict[str, str] = {}

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError(f"upstream url {value!r} must start with http:// or https://")
        return value


Upstream = Annotated[StdioUpstream | HttpUpstream, Field(discriminator="transport")]


class WhenConfig(_Strict):
    """Optional extra conditions on a rule."""

    args: dict[str, str] = {}
    """Dotted argument path -> glob pattern. All must match."""

    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None

    def to_condition(self) -> RuleCondition:
        return RuleCondition(
            arguments=tuple(
                ArgumentCondition(path=path, pattern=pattern)
                for path, pattern in sorted(self.args.items())
            ),
            read_only=self.read_only_hint,
            destructive=self.destructive_hint,
            idempotent=self.idempotent_hint,
            open_world=self.open_world_hint,
        )


class RuleConfig(_Strict):
    tool: Annotated[str, Field(min_length=1)]
    action: Action
    when: WhenConfig | None = None
    reason: str | None = None
    upstream: str | None = None

    def to_rule(self) -> Rule:
        return Rule(
            tool=self.tool,
            action=self.action,
            condition=self.when.to_condition() if self.when else RuleCondition(),
            reason=self.reason,
            upstream=self.upstream,
        )


class PolicyConfig(_Strict):
    default: Action = Action.REQUIRE_APPROVAL
    """Applied when no rule matches. Defaults to the safe option."""

    default_reason: str | None = None
    rules: list[RuleConfig] = []


class ApprovalUiConfig(_Strict):
    host: str = "127.0.0.1"
    port: Annotated[int, Field(ge=1, le=65535)] = 8765
    base_url: str = "http://localhost:8765"
    """Public URL handed to clients in elicitation links. Must be reachable by
    the approver's browser, which is not always the same host we bind to."""


class ApprovalConfig(_Strict):
    mode: Literal["auto", "elicit", "block"] = "auto"
    """``auto`` picks per request from the client's advertised capabilities."""

    timeout_seconds: Annotated[float, Field(gt=0)] = 300.0
    on_timeout: Literal["deny", "allow"] = "deny"
    ui: ApprovalUiConfig = Field(default_factory=ApprovalUiConfig)
    """``on_timeout: allow`` is permitted -- some deployments genuinely want
    fail-open -- but it inverts the point of the tool, so it must be spelled out."""


class AuditConfig(_Strict):
    database: str = "./gatekeeper.db"
    redact: list[str] = []
    """Dotted argument paths (globs allowed) to mask before anything is stored."""

    enabled: bool = True


class ServerConfig(_Strict):
    name: str = "mcp-gatekeeper"
    version: str = "0.1.0"
    instructions: str | None = None


class GatekeeperConfig(_Strict):
    """The whole configuration file."""

    version: Literal[1] = 1
    server: ServerConfig = Field(default_factory=ServerConfig)
    upstreams: list[Upstream] = []
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    approvals: ApprovalConfig = Field(default_factory=ApprovalConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    @field_validator("upstreams", mode="before")
    @classmethod
    def _default_transport(cls, value: object) -> object:
        """Let ``transport`` be omitted for stdio upstreams.

        A discriminated union needs the tag present, but stdio is far and away
        the common case and writing ``transport: stdio`` on every entry is
        noise. Fill the tag in before the union sees it.
        """
        if not isinstance(value, list):
            return value
        items = cast("list[Any]", value)
        filled: list[Any] = [
            {"transport": "stdio", **item}
            if isinstance(item, dict) and "transport" not in item
            else item
            for item in items
        ]
        return filled

    @model_validator(mode="after")
    def _validate_upstreams(self) -> GatekeeperConfig:
        seen: set[str] = set()
        for upstream in self.upstreams:
            if upstream.name in seen:
                raise ValueError(f"duplicate upstream name {upstream.name!r}")
            seen.add(upstream.name)

        for rule in self.policy.rules:
            if rule.upstream is not None and rule.upstream not in seen:
                known = ", ".join(sorted(seen)) or "none configured"
                raise ValueError(
                    f"rule for tool {rule.tool!r} targets unknown upstream "
                    f"{rule.upstream!r} (known: {known})"
                )
        return self

    def build_policy(self) -> Policy:
        """Compile the config into the pure policy the engine evaluates."""
        return Policy(
            rules=tuple(rule.to_rule() for rule in self.policy.rules),
            default=self.policy.default,
            default_reason=self.policy.default_reason,
        )
