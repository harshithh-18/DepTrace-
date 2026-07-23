"""Tests for OSV range matching under PEP 440.

Version-range bugs are the #1 false-positive source in vulnerability
scanners, so these cases are asserted directly rather than only through the
provider.
"""

from __future__ import annotations

from typing import Any

import pytest

from deptrace.providers.vulndb.ranges import (
    extract_fixed_version,
    is_affected,
    parse_version,
    version_in_range,
)


def _range(*events: dict[str, str]) -> dict[str, Any]:
    return {"type": "ECOSYSTEM", "events": list(events)}


def _affected(*events: dict[str, str]) -> list[Any]:
    return [{"package": {"name": "demo"}, "ranges": [_range(*events)]}]


def test_string_comparison_trap_is_avoided() -> None:
    """The canonical bug: "1.10" > "1.9" is False as strings, True as versions."""
    assert ("1.10" > "1.9") is False
    assert parse_version("1.10") > parse_version("1.9")  # type: ignore[operator]

    # 1.10 is fixed (>= 1.9), so it must NOT be reported as affected.
    affected = _affected({"introduced": "1.0"}, {"fixed": "1.9"})
    assert is_affected("1.10", affected) is False
    assert is_affected("1.8", affected) is True


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("5.0", False),   # before introduced
        ("5.1", True),    # at introduced
        ("5.2", True),    # inside window
        ("5.3.1", False), # at fixed -> exclusive
        ("5.4", False),   # after fixed
    ],
)
def test_introduced_fixed_window(version: str, expected: bool) -> None:
    affected = _affected({"introduced": "5.1"}, {"fixed": "5.3.1"})
    assert is_affected(version, affected) is expected


def test_introduced_zero_means_from_beginning() -> None:
    affected = _affected({"introduced": "0"}, {"fixed": "2.0"})
    assert is_affected("0.0.1", affected) is True
    assert is_affected("1.9.9", affected) is True
    assert is_affected("2.0", affected) is False


def test_open_ended_range_has_no_fix() -> None:
    """introduced with no fixed: everything at or above is still affected."""
    affected = _affected({"introduced": "1.0"})
    assert is_affected("99.0", affected) is True
    assert is_affected("0.9", affected) is False
    assert extract_fixed_version(affected) is None


def test_last_affected_is_inclusive() -> None:
    """Unlike `fixed`, `last_affected` includes the named version."""
    affected = _affected({"introduced": "1.0"}, {"last_affected": "1.5"})
    assert is_affected("1.5", affected) is True
    assert is_affected("1.6", affected) is False


def test_prerelease_versions_compare_correctly() -> None:
    affected = _affected({"introduced": "5.1b7"}, {"fixed": "5.3.1"})
    assert is_affected("5.1b7", affected) is True
    assert is_affected("5.1b6", affected) is False
    assert is_affected("5.2", affected) is True


def test_multiple_windows_in_one_range() -> None:
    """A range may reopen: affected 1.x, fixed in 2.0, regressed in 3.0."""
    affected = _affected(
        {"introduced": "1.0"},
        {"fixed": "2.0"},
        {"introduced": "3.0"},
        {"fixed": "3.5"},
    )
    assert is_affected("1.5", affected) is True
    assert is_affected("2.5", affected) is False
    assert is_affected("3.1", affected) is True
    assert is_affected("3.5", affected) is False


def test_explicit_versions_list_matches() -> None:
    entries: list[Any] = [{"versions": ["1.0", "1.1", "1.2"]}]
    assert is_affected("1.1", entries) is True
    assert is_affected("1.3", entries) is False


# -- the undecidable third state ------------------------------------------


def test_unpinned_version_is_undecidable_not_safe() -> None:
    """No version => None, so triage routes it to NEEDS_REVIEW, never safe."""
    affected = _affected({"introduced": "1.0"}, {"fixed": "2.0"})
    assert is_affected(None, affected) is None
    assert is_affected("", affected) is None


def test_unparseable_version_is_undecidable() -> None:
    affected = _affected({"introduced": "1.0"}, {"fixed": "2.0"})
    assert is_affected("not-a-version", affected) is None


def test_no_parseable_constraint_is_undecidable() -> None:
    """OSV returned the package but we cannot read the range: don't guess."""
    assert is_affected("1.0", [{"package": {"name": "demo"}}]) is None
    assert is_affected("1.0", []) is None


def test_git_ranges_are_ignored() -> None:
    """GIT ranges hold commit hashes, not PEP 440 versions."""
    entries: list[Any] = [
        {"ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}]}]}
    ]
    assert is_affected("1.0", entries) is None


# -- remediation target ----------------------------------------------------


def test_extract_fixed_version_picks_lowest() -> None:
    """The minimum safe bump is the least disruptive honest recommendation."""
    affected = _affected(
        {"introduced": "1.0"},
        {"fixed": "3.5"},
        {"introduced": "0.1"},
        {"fixed": "2.0"},
    )
    assert extract_fixed_version(affected) == "2.0"


def test_extract_fixed_version_uses_version_ordering() -> None:
    affected = _affected({"introduced": "1.0"}, {"fixed": "1.10"}, {"fixed": "1.9"})
    # Lowest by PEP 440 is 1.9, not "1.10" by string ordering.
    assert extract_fixed_version(affected) == "1.9"


def test_version_in_range_handles_malformed_events() -> None:
    assert version_in_range(parse_version("1.0"), {}) is False  # type: ignore[arg-type]
    assert version_in_range(parse_version("1.0"), {"events": "junk"}) is False  # type: ignore[arg-type]


def test_parse_version_returns_none_not_raises() -> None:
    assert parse_version("1.2.3") is not None
    assert parse_version("garbage") is None
