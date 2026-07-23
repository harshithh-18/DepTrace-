"""Tests for name normalization and distribution -> import mapping.

Getting this wrong produces false negatives that look like clean scans, so
the tricky cases are asserted explicitly rather than trusted to a heuristic.
"""

from __future__ import annotations

import pytest

from deptrace.tools.names import import_names_for, normalize


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("PyYAML", "pyyaml"),
        ("Flask_SQLAlchemy", "flask-sqlalchemy"),
        ("zope.interface", "zope-interface"),
        ("ruamel...yaml", "ruamel-yaml"),
        ("  requests  ", "requests"),
        ("scikit_learn", "scikit-learn"),
        ("Django", "django"),
    ],
)
def test_normalize_follows_pep503(raw: str, expected: str) -> None:
    assert normalize(raw) == expected


def test_normalize_is_idempotent() -> None:
    """Names pass through normalize repeatedly; it must be a fixed point."""
    for raw in ("PyYAML", "scikit-learn", "zope.interface"):
        once = normalize(raw)
        assert normalize(once) == once


@pytest.mark.parametrize(
    ("dist", "expected_root"),
    [
        ("pyyaml", "yaml"),
        ("PyYAML", "yaml"),
        ("beautifulsoup4", "bs4"),
        ("Pillow", "PIL"),
        ("scikit-learn", "sklearn"),
        ("scikit_learn", "sklearn"),
        ("msgpack-python", "msgpack"),
        ("python-dateutil", "dateutil"),
        ("opencv-python", "cv2"),
        ("pyjwt", "jwt"),
        ("pycryptodome", "Crypto"),
        ("mysqlclient", "MySQLdb"),
    ],
)
def test_known_tricky_mappings(dist: str, expected_root: str) -> None:
    """The classic distribution != import cases must all resolve."""
    assert expected_root in import_names_for(dist)


def test_fallback_guess_for_unknown_package() -> None:
    """An unknown name still yields a usable import root, never empty."""
    assert import_names_for("some-unknown-pkg-xyz") == ("some_unknown_pkg_xyz",)


def test_import_names_never_empty() -> None:
    """Empty import names would make the AST engine silently skip a package."""
    for dist in ("requests", "pyyaml", "totally-made-up-name", "a"):
        assert import_names_for(dist), f"{dist} produced no import names"
