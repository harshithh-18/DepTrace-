"""OSV affected-range matching under PEP 440 semantics.

This module answers one question: *is version V of package P affected by
this advisory?* Getting it wrong in the permissive direction is the single
largest source of false positives in vulnerability scanners, and getting it
wrong in the strict direction hides real CVEs. So it is isolated here, kept
pure, and tested directly.

Two hard rules:

1. **Never compare versions as strings.** `"1.10" > "1.9"` is `False`, which
   would silently mark a patched project as vulnerable (or vice versa).
   Everything goes through `packaging.version.Version`.

2. **Unparseable version => do not guess.** Returning "not affected" for a
   version we cannot understand would be a silent false negative. We report
   uncertainty upward and let the caller route it to NEEDS_REVIEW.

OSV encodes ranges as an ordered `events` list rather than a specifier
string:

    {"type": "ECOSYSTEM", "events": [{"introduced": "5.1b7"}, {"fixed": "5.3.1"}]}

meaning `5.1b7 <= affected < 5.3.1`. `introduced: "0"` means "since the
beginning". A range may contain several introduced/fixed pairs, and may use
`last_affected` (inclusive) instead of `fixed` (exclusive).
"""

from __future__ import annotations

from typing import Any

from packaging.version import InvalidVersion, Version


def parse_version(raw: str) -> Version | None:
    """Parse a version string, returning None when it is not PEP 440.

    None is a meaningful third state here, never coerced to a boolean.
    """
    try:
        return Version(raw)
    except (InvalidVersion, TypeError):
        return None


def _event_versions(events: list[Any]) -> list[tuple[str, str]]:
    """Flatten OSV events into ordered (kind, version) pairs."""
    pairs: list[tuple[str, str]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            raw = event.get(kind)
            if isinstance(raw, str):
                pairs.append((kind, raw))
    return pairs


def version_in_range(version: Version, osv_range: dict[str, Any]) -> bool:
    """Check a concrete version against one OSV range object.

    Walks the event list in order, tracking whether we are currently inside
    an affected window. `introduced` opens a window, `fixed`/`limit` close it
    exclusively, `last_affected` closes it inclusively.
    """
    events = osv_range.get("events")
    if not isinstance(events, list):
        return False

    affected = False
    for kind, raw in _event_versions(events):
        if kind == "introduced":
            # "0" is OSV's sentinel for "from the first release".
            if raw == "0":
                affected = True
                continue
            bound = parse_version(raw)
            if bound is not None and version >= bound:
                affected = True
        elif kind in ("fixed", "limit"):
            bound = parse_version(raw)
            if bound is not None and version >= bound:
                affected = False
        elif kind == "last_affected":
            bound = parse_version(raw)
            if bound is not None and version > bound:
                affected = False

    return affected


def is_affected(version_str: str | None, affected_entries: list[Any]) -> bool | None:
    """Decide whether `version_str` is affected by an OSV `affected` block.

    Returns:
        True  — the version falls inside a declared affected range.
        False — the version is provably outside every range.
        None  — undecidable (no version pinned, or unparseable version).
                The caller must route None to NEEDS_REVIEW, never to safe.
    """
    if not version_str:
        return None
    version = parse_version(version_str)
    if version is None:
        return None

    saw_constraint = False

    for entry in affected_entries:
        if not isinstance(entry, dict):
            continue

        # An explicit version list is authoritative when it matches.
        versions = entry.get("versions")
        if isinstance(versions, list):
            for raw in versions:
                if not isinstance(raw, str):
                    continue
                saw_constraint = True
                parsed = parse_version(raw)
                if parsed is not None and parsed == version:
                    return True

        ranges = entry.get("ranges")
        if isinstance(ranges, list):
            for osv_range in ranges:
                if not isinstance(osv_range, dict):
                    continue
                # SEMVER/GIT ranges do not describe PyPI versions; skip them
                # rather than misinterpret them under PEP 440.
                if osv_range.get("type") not in ("ECOSYSTEM", "SEMVER", None):
                    continue
                if osv_range.get("type") == "GIT":
                    continue
                saw_constraint = True
                if version_in_range(version, osv_range):
                    return True

    # No parseable constraint at all: OSV returned it for this package but we
    # cannot confirm the range. Undecidable beats a confident wrong answer.
    if not saw_constraint:
        return None
    return False


def extract_fixed_version(affected_entries: list[Any]) -> str | None:
    """Find the lowest `fixed` version across all ranges — the upgrade target.

    Lowest rather than highest: the minimum safe bump is the least disruptive
    remediation we can honestly recommend.
    """
    candidates: list[Version] = []

    for entry in affected_entries:
        if not isinstance(entry, dict):
            continue
        ranges = entry.get("ranges")
        if not isinstance(ranges, list):
            continue
        for osv_range in ranges:
            if not isinstance(osv_range, dict) or osv_range.get("type") == "GIT":
                continue
            events = osv_range.get("events")
            if not isinstance(events, list):
                continue
            for kind, raw in _event_versions(events):
                if kind != "fixed":
                    continue
                parsed = parse_version(raw)
                if parsed is not None:
                    candidates.append(parsed)

    if not candidates:
        return None
    return str(min(candidates))
