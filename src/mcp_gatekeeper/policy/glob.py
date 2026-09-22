"""Pure glob matching for policy patterns.

Two flavours, deliberately kept apart because they have different rules:

* :func:`match_tool` matches tool names, which are flat identifiers. ``*`` is
  unrestricted, so ``fs__*`` matches ``fs__write_file``.
* :func:`match_path` matches argument values that look like paths, where ``/``
  is a real boundary. ``*`` stops at ``/`` and ``**`` crosses it.

Matching is case-sensitive. See ``README.md`` ("Design decisions") for why, and
for the bypass that implies on case-insensitive filesystems.
"""

from __future__ import annotations

import re
from functools import lru_cache

__all__ = ["canonical_value", "match_path", "match_tool"]


def _compile(pattern: str, *, separator_aware: bool) -> re.Pattern[str]:
    """Translate a glob pattern into an anchored regex.

    When ``separator_aware`` is set, ``*`` and ``?`` refuse to cross ``/`` and
    ``**`` is the only way across. A trailing ``/**`` also matches the parent
    itself, so ``/prod/**`` covers ``/prod`` as well as ``/prod/db.yaml`` --
    a rule guarding production should not be defeated by naming the directory
    exactly.
    """
    star = "[^/]*" if separator_aware else ".*"
    question = "[^/]" if separator_aware else "."

    out: list[str] = []
    i = 0
    end = len(pattern)

    while i < end:
        char = pattern[i]

        if char == "*":
            # A doubled star crosses separators; a single one does not.
            if separator_aware and i + 1 < end and pattern[i + 1] == "*":
                # Trailing "/**" is special: make the separator optional so the
                # parent directory matches too.
                if out and out[-1] == "/" and i + 2 == end:
                    out[-1] = "(?:/.*)?"
                else:
                    out.append(".*")
                i += 2
                continue
            out.append(star)
        elif char == "?":
            out.append(question)
        elif char == "/":
            out.append("/")
        else:
            out.append(re.escape(char))
        i += 1

    return re.compile(f"^{''.join(out)}$", re.DOTALL)


@lru_cache(maxsize=1024)
def _tool_regex(pattern: str) -> re.Pattern[str]:
    return _compile(pattern, separator_aware=False)


@lru_cache(maxsize=1024)
def _path_regex(pattern: str) -> re.Pattern[str]:
    return _compile(pattern, separator_aware=True)


def match_tool(pattern: str, name: str) -> bool:
    """Return whether a flat tool name matches ``pattern``."""
    return _tool_regex(pattern).match(name) is not None


def match_path(pattern: str, value: str) -> bool:
    """Return whether a path-like argument value matches ``pattern``."""
    return _path_regex(pattern).match(value) is not None


def canonical_value(value: object) -> str | None:
    """Render a JSON scalar the way patterns are written against it.

    Booleans become ``true``/``false`` and ``None`` becomes ``null`` so that
    patterns read like the JSON the client actually sent, rather than like
    Python's ``True``/``None``. Containers return ``None``: a rule cannot
    meaningfully glob a list or dict, and silently stringifying one would
    invite patterns that appear to work but match on ``repr`` punctuation.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return value
    if isinstance(value, int | float):
        return str(value)
    return None
