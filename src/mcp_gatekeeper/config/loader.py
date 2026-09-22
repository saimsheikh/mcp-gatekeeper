"""Load and validate ``gatekeeper.yaml``.

Config errors are the first thing a new user hits, so Pydantic's raw output is
reshaped into messages that name the offending YAML path and say what was
expected.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from mcp_gatekeeper.config.models import GatekeeperConfig

__all__ = ["ConfigError", "load_config", "parse_config"]


class ConfigError(Exception):
    """Raised when a config file is missing, unparseable, or invalid.

    Carries a message already formatted for a terminal; the CLI prints it
    verbatim rather than re-deriving one.
    """


def _format_validation_error(error: ValidationError, source: str) -> str:
    lines = [f"{source} is not valid:"]
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "(root)"
        lines.append(f"  - {location}: {item['msg']}")
    return "\n".join(lines)


def parse_config(data: object, *, source: str = "config") -> GatekeeperConfig:
    """Validate an already-parsed config document."""
    if data is None:
        raise ConfigError(f"{source} is empty")
    if not isinstance(data, dict):
        raise ConfigError(f"{source} must be a YAML mapping, found {type(data).__name__}")

    document = cast("dict[str, Any]", data)
    try:
        return GatekeeperConfig.model_validate(document)
    except ValidationError as error:
        raise ConfigError(_format_validation_error(error, source)) from error


def load_config(path: str | Path) -> GatekeeperConfig:
    """Read, parse, and validate a config file."""
    config_path = Path(path)

    try:
        text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ConfigError(f"config file not found: {config_path}") from error
    except OSError as error:
        raise ConfigError(f"could not read {config_path}: {error}") from error

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ConfigError(f"{config_path} is not valid YAML: {error}") from error

    return parse_config(document, source=str(config_path))
