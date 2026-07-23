"""Tests for manifest parsing across requirements.txt, pyproject.toml, uv.lock."""

from __future__ import annotations

from pathlib import Path

from deptrace.core.state import Dependency
from deptrace.tools.manifest import (
    find_manifests,
    parse_manifests,
    parse_pyproject,
    parse_requirements_txt,
    parse_uv_lock,
)


def _by_name(deps: list[Dependency]) -> dict[str, Dependency]:
    return {d.name: d for d in deps}


# --------------------------------------------------------------------------
# requirements.txt
# --------------------------------------------------------------------------


def test_requirements_basic_parsing(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        """
# a comment line
requests==2.31.0
PyYAML>=5.1,<6.0
Flask
        """.strip()
    )
    deps = _by_name(parse_requirements_txt(tmp_path / "requirements.txt", tmp_path))

    assert set(deps) == {"requests", "pyyaml", "flask"}
    assert deps["requests"].version == "2.31.0"
    assert deps["pyyaml"].version is None  # a range is not a pin
    assert deps["pyyaml"].specifier is not None
    assert deps["flask"].specifier is None


def test_requirements_normalizes_and_maps_import_names(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("PyYAML==6.0.1\nbeautifulsoup4==4.12.0\n")
    deps = _by_name(parse_requirements_txt(tmp_path / "requirements.txt", tmp_path))

    assert "yaml" in deps["pyyaml"].import_names
    assert "bs4" in deps["beautifulsoup4"].import_names


def test_requirements_handles_extras_and_markers(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        'requests[security]==2.31.0 ; python_version < "3.13"\n'
        "uvicorn[standard]>=0.30\n"
    )
    deps = _by_name(parse_requirements_txt(tmp_path / "requirements.txt", tmp_path))

    assert deps["requests"].version == "2.31.0"
    assert "uvicorn" in deps


def test_requirements_follows_includes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("-r base.txt\nflask==3.0.0\n")
    (tmp_path / "base.txt").write_text("requests==2.31.0\n")

    deps = _by_name(parse_requirements_txt(tmp_path / "requirements.txt", tmp_path))
    assert set(deps) == {"requests", "flask"}
    assert deps["requests"].source == "base.txt"


def test_requirements_include_cycle_terminates(tmp_path: Path) -> None:
    """A self-including file must not hang the scan."""
    (tmp_path / "a.txt").write_text("-r b.txt\nflask==3.0.0\n")
    (tmp_path / "b.txt").write_text("-r a.txt\nrequests==2.31.0\n")

    deps = _by_name(parse_requirements_txt(tmp_path / "a.txt", tmp_path))
    assert set(deps) == {"flask", "requests"}


def test_requirements_skips_options_and_urls(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://example.com/simple\n"
        "-e .\n"
        "mypkg @ https://example.com/mypkg.whl\n"
        "requests==2.31.0\n"
    )
    deps = _by_name(parse_requirements_txt(tmp_path / "requirements.txt", tmp_path))
    assert set(deps) == {"requests"}


def test_requirements_handles_continuations_and_inline_comments(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0  # pinned for CVE\nflask>=3.0, \\\n    <4.0\n"
    )
    deps = _by_name(parse_requirements_txt(tmp_path / "requirements.txt", tmp_path))
    assert deps["requests"].version == "2.31.0"
    assert "flask" in deps


def test_requirements_survives_malformed_lines(tmp_path: Path) -> None:
    """A junk line must be skipped, never crash the scan."""
    (tmp_path / "requirements.txt").write_text("!!!not a requirement!!!\nrequests==2.31.0\n")
    deps = _by_name(parse_requirements_txt(tmp_path / "requirements.txt", tmp_path))
    assert set(deps) == {"requests"}


# --------------------------------------------------------------------------
# pyproject.toml
# --------------------------------------------------------------------------


def test_pyproject_pep621_with_optional_and_groups(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
dependencies = ["requests>=2.0", "PyYAML==6.0.1"]

[project.optional-dependencies]
web = ["flask==3.0.0"]

[dependency-groups]
dev = ["pytest>=8.0"]
        """.strip()
    )
    deps = _by_name(parse_pyproject(tmp_path / "pyproject.toml", tmp_path))

    assert set(deps) == {"requests", "pyyaml", "flask", "pytest"}
    assert deps["pyyaml"].version == "6.0.1"
    assert "yaml" in deps["pyyaml"].import_names


def test_pyproject_poetry_section(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.12"
requests = "^2.31.0"
PyYAML = { version = "6.0.1" }

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
        """.strip()
    )
    deps = _by_name(parse_pyproject(tmp_path / "pyproject.toml", tmp_path))

    assert set(deps) == {"requests", "pyyaml", "pytest"}
    assert "python" not in deps  # the interpreter is not a dependency
    assert deps["pyyaml"].version == "6.0.1"


def test_pyproject_malformed_toml_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project\nbroken =")
    assert parse_pyproject(tmp_path / "pyproject.toml", tmp_path) == []


# --------------------------------------------------------------------------
# uv.lock
# --------------------------------------------------------------------------


UV_LOCK = """
version = 1
requires-python = ">=3.12"

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "requests" },
]

[package.metadata]
requires-dist = [{ name = "requests", specifier = ">=2.0" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "2.2.1"
source = { registry = "https://pypi.org/simple" }
"""


def test_uv_lock_resolves_versions_and_directness(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    deps = _by_name(parse_uv_lock(tmp_path / "uv.lock", tmp_path))

    # The local project itself must not appear as its own dependency.
    assert "demo" not in deps
    assert deps["requests"].version == "2.31.0"
    assert deps["requests"].is_direct is True
    assert deps["urllib3"].is_direct is False  # transitive


def test_uv_lock_on_this_repo_is_realistic() -> None:
    """Parse DepTrace's own lockfile — the cheapest available real fixture."""
    lock = Path(__file__).resolve().parent.parent / "uv.lock"
    deps = _by_name(parse_uv_lock(lock))

    assert "pydantic" in deps
    assert deps["pydantic"].is_direct is True
    assert deps["pydantic"].version is not None
    assert "deptrace" not in deps  # itself excluded


# --------------------------------------------------------------------------
# repo-level
# --------------------------------------------------------------------------


def test_find_manifests_skips_vendored_dirs(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    venv = tmp_path / ".venv" / "lib" / "site-packages"
    venv.mkdir(parents=True)
    (venv / "requirements.txt").write_text("evil==6.6.6\n")

    found = find_manifests(tmp_path)
    assert [p.name for p in found] == ["requirements.txt"]
    assert ".venv" not in str(found[0])


def test_parse_manifests_merges_and_prefers_locked_version(tmp_path: Path) -> None:
    """pyproject declares a range; the lockfile resolves it. Lock wins."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["requests>=2.0"]\n'
    )
    (tmp_path / "uv.lock").write_text(UV_LOCK)

    deps = _by_name(parse_manifests(tmp_path))
    assert deps["requests"].version == "2.31.0"
    assert deps["requests"].is_direct is True
    assert deps["urllib3"].version == "2.2.1"


def test_parse_manifests_output_is_sorted_and_unique(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests==2.31.0\n")
    (tmp_path / "requirements-dev.txt").write_text("requests==2.31.0\npytest==8.0.0\n")

    deps = parse_manifests(tmp_path)
    names = [d.name for d in deps]
    assert names == sorted(names)
    assert len(names) == len(set(names))


def test_parse_manifests_on_empty_repo(tmp_path: Path) -> None:
    assert parse_manifests(tmp_path) == []
