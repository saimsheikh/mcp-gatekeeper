"""Exhaustive tests for pattern matching.

Everything the policy engine decides rests on these two functions, so the
edge cases are enumerated rather than sampled.
"""

from __future__ import annotations

import pytest

from mcp_gatekeeper.policy.glob import canonical_value, match_path, match_tool


class TestMatchTool:
    @pytest.mark.parametrize(
        ("pattern", "name"),
        [
            ("fs__write_file", "fs__write_file"),
            ("*", "anything"),
            ("*", ""),
            ("fs__*", "fs__write_file"),
            ("fs__*", "fs__"),
            ("*__write_file", "fs__write_file"),
            ("*_file", "fs__write_file"),
            ("fs__write_????", "fs__write_file"),
            ("fs__*_file", "fs__write_file"),
            ("*fs*", "my_fs_server__x"),
        ],
    )
    def test_matches(self, pattern: str, name: str) -> None:
        assert match_tool(pattern, name)

    @pytest.mark.parametrize(
        ("pattern", "name"),
        [
            ("fs__write_file", "fs__write_filex"),
            ("fs__write_file", "xfs__write_file"),
            ("fs__*", "github__write_file"),
            ("fs__write_???", "fs__write_file"),
            ("", "nonempty"),
            ("fs__read_*", "fs__write_file"),
        ],
    )
    def test_does_not_match(self, pattern: str, name: str) -> None:
        assert not match_tool(pattern, name)

    def test_star_crosses_the_namespace_separator(self) -> None:
        # Tool names are flat identifiers, so '*' has no boundary to respect.
        assert match_tool("fs*file", "fs__write_file")

    def test_is_case_sensitive(self) -> None:
        assert not match_tool("fs__write_file", "FS__WRITE_FILE")

    def test_special_regex_characters_are_literal(self) -> None:
        assert match_tool("tool.v1+beta", "tool.v1+beta")
        assert not match_tool("tool.v1", "toolXv1")


class TestMatchPath:
    @pytest.mark.parametrize(
        ("pattern", "value"),
        [
            ("/prod/db.yaml", "/prod/db.yaml"),
            ("/prod/*", "/prod/db.yaml"),
            ("/prod/**", "/prod/db.yaml"),
            ("/prod/**", "/prod/nested/deep/db.yaml"),
            ("**", "/any/thing"),
            ("**/*.env", "/a/b/.env"),
            ("/prod/*.yaml", "/prod/db.yaml"),
            ("/home/?/x", "/home/a/x"),
            ("relative/path", "relative/path"),
        ],
    )
    def test_matches(self, pattern: str, value: str) -> None:
        assert match_path(pattern, value)

    @pytest.mark.parametrize(
        ("pattern", "value"),
        [
            ("/prod/*", "/prod/nested/db.yaml"),
            ("/prod/*", "/staging/db.yaml"),
            ("/prod/**", "/staging/db.yaml"),
            ("/prod/**", "/prodigy/db.yaml"),
            ("/home/?/x", "/home/ab/x"),
            ("/prod/*.yaml", "/prod/db.json"),
        ],
    )
    def test_does_not_match(self, pattern: str, value: str) -> None:
        assert not match_path(pattern, value)

    def test_single_star_stops_at_separator(self) -> None:
        assert match_path("/a/*", "/a/b")
        assert not match_path("/a/*", "/a/b/c")

    def test_double_star_crosses_separators(self) -> None:
        assert match_path("/a/**", "/a/b/c/d/e")

    @pytest.mark.parametrize("value", ["/prod", "/prod/", "/prod/db.yaml", "/prod/a/b"])
    def test_trailing_double_star_covers_the_parent_itself(self, value: str) -> None:
        # A rule guarding production must not be defeated by naming the
        # directory exactly. This is documented behaviour, not an accident.
        assert match_path("/prod/**", value)

    def test_trailing_double_star_still_respects_the_prefix(self) -> None:
        assert not match_path("/prod/**", "/production")
        assert not match_path("/prod/**", "/prodfile")

    def test_is_case_sensitive(self) -> None:
        # Documented limitation: on a case-insensitive filesystem this is a
        # bypass. See README "Design decisions".
        assert not match_path("/prod/**", "/PROD/db.yaml")

    def test_matches_values_containing_newlines(self) -> None:
        # DOTALL is set, so a newline injected into an argument cannot be used
        # to slip past a '**' that would otherwise match.
        assert match_path("/prod/**", "/prod/a\nb")

    def test_special_regex_characters_are_literal(self) -> None:
        assert match_path("/a+b/(c)/x.y", "/a+b/(c)/x.y")
        assert not match_path("/a.b", "/axb")


class TestCanonicalValue:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("text", "text"),
            ("", ""),
            (42, "42"),
            (-1, "-1"),
            (3.5, "3.5"),
            (True, "true"),
            (False, "false"),
            (None, "null"),
        ],
    )
    def test_renders_scalars_as_json_would(self, value: object, expected: str) -> None:
        assert canonical_value(value) == expected

    def test_bool_is_checked_before_int(self) -> None:
        # bool subclasses int in Python; without an explicit check True would
        # render as "1" and never match a pattern written as "true".
        assert canonical_value(True) == "true"

    @pytest.mark.parametrize("value", [[1, 2], {"a": 1}, (1,), {1, 2}, object()])
    def test_containers_are_unmatchable(self, value: object) -> None:
        # Stringifying these would let a pattern appear to work while actually
        # matching on repr punctuation.
        assert canonical_value(value) is None
