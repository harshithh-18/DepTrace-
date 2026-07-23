"""Manifest parsing: a repo path -> `list[Dependency]`.

No network, no LLM, no side effects. This is the first stage of the
pipeline and it is deliberately boring: everything downstream (OSV lookup,
AST reachability) is only as correct as the dependency list it starts from.

Three formats are supported, in descending order of trustworthiness:

  uv.lock          exact resolved versions, including transitives
  pyproject.toml   declared constraints (PEP 621 and Poetry)
  requirements.txt declared constraints, often pinned

A lockfile is preferred when present because reachability triage needs a
concrete version to ask OSV about. `>=2.0` does not answer "am I affected".
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Iterator
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from deptrace.core.state import Dependency

from .names import import_names_for, normalize

# Directories that must never be walked for manifests. Scanning a vendored
# .venv would pull in the entire transitive world of unrelated projects.
EXCLUDED_DIRS = frozenset(
    {
        ".venv",
        "venv",
        "env",
        ".env",
        "site-packages",
        "node_modules",
        ".git",
        ".tox",
        ".nox",
        "build",
        "dist",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)

MANIFEST_FILENAMES = ("uv.lock", "pyproject.toml", "requirements.txt")


def _make_dependency(
    name: str,
    *,
    source: str,
    version: str | None = None,
    specifier: str | None = None,
    is_direct: bool = True,
) -> Dependency:
    """Single construction point so normalization can never be skipped."""
    normalized = normalize(name)
    return Dependency(
        name=normalized,
        version=version,
        specifier=specifier,
        import_names=import_names_for(normalized),
        source=source,
        is_direct=is_direct,
    )


def _pinned_version(req: Requirement) -> str | None:
    """Extract a concrete version only from a true `==` pin.

    Deliberately conservative. `>=5.1` tells us nothing about what is
    installed, and guessing a version here would make the OSV range check
    answer a question nobody asked.
    """
    for spec in req.specifier:
        if spec.operator in ("==", "==="):
            return spec.version.rstrip(".*")
    return None


# --------------------------------------------------------------------------
# requirements.txt
# --------------------------------------------------------------------------


def _iter_requirement_lines(path: Path, seen: set[Path]) -> Iterator[tuple[str, Path]]:
    """Yield logical requirement lines, following `-r` / `--requirement`.

    Handles comments, blank lines, backslash continuations, and include
    cycles. `seen` guards against a file including itself transitively.
    """
    resolved = path.resolve()
    if resolved in seen or not path.is_file():
        return
    seen.add(resolved)

    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    buffer = ""
    for raw_line in raw.splitlines():
        line = raw_line.split(" #", 1)[0].rstrip() if " #" in raw_line else raw_line.rstrip()
        if line.lstrip().startswith("#"):
            continue
        if line.endswith("\\"):
            buffer += line[:-1]
            continue
        line = (buffer + line).strip()
        buffer = ""
        if not line:
            continue

        if line.startswith(("-r ", "--requirement ", "-r=", "--requirement=")):
            head = line.split(" ", 1)[0]
            # Both `-r file.txt` and `--requirement=file.txt` are valid.
            target = line.split("=", 1)[-1] if "=" in head else line.split(None, 1)[1]
            yield from _iter_requirement_lines(path.parent / target.strip(), seen)
            continue

        # Option lines (-e, --index-url, --hash, -c ...) are not requirements.
        if line.startswith("-"):
            continue

        yield line, path


def parse_requirements_txt(path: Path, repo_root: Path | None = None) -> list[Dependency]:
    """Parse a requirements.txt, following `-r` includes."""
    root = repo_root or path.parent
    deps: list[Dependency] = []
    seen: set[Path] = set()

    for line, origin in _iter_requirement_lines(path, seen):
        # Strip environment markers before parsing; we intentionally keep
        # marker-gated deps rather than evaluating markers against this
        # machine. A CVE reachable only on Windows is still a finding.
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue
        if req.url:  # direct URL/VCS installs carry no reliable version
            continue

        try:
            source = str(origin.relative_to(root))
        except ValueError:
            source = origin.name

        deps.append(
            _make_dependency(
                req.name,
                source=source,
                version=_pinned_version(req),
                specifier=str(req.specifier) or None,
                is_direct=True,
            )
        )
    return deps


# --------------------------------------------------------------------------
# pyproject.toml
# --------------------------------------------------------------------------


def _parse_pep621(data: dict[str, object], source: str) -> list[Dependency]:
    project = data.get("project")
    if not isinstance(project, dict):
        return []

    deps: list[Dependency] = []
    raw_deps = project.get("dependencies")
    if isinstance(raw_deps, list):
        deps.extend(_deps_from_requirement_strings(raw_deps, source))

    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group in optional.values():
            if isinstance(group, list):
                deps.extend(_deps_from_requirement_strings(group, source))

    # PEP 735 dependency-groups (dev deps live here in uv projects).
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, list):
                deps.extend(_deps_from_requirement_strings(group, source))

    return deps


def _deps_from_requirement_strings(items: Iterable[object], source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for item in items:
        if not isinstance(item, str):
            continue  # PEP 735 include-group tables, etc.
        try:
            req = Requirement(item)
        except InvalidRequirement:
            continue
        if req.url:
            continue
        deps.append(
            _make_dependency(
                req.name,
                source=source,
                version=_pinned_version(req),
                specifier=str(req.specifier) or None,
            )
        )
    return deps


def _parse_poetry(data: dict[str, object], source: str) -> list[Dependency]:
    """Parse `[tool.poetry.dependencies]`, which is not PEP 508.

    Poetry uses a table of `name = constraint`, where the constraint may be
    a caret string (`^1.2`) or an inline table (`{version = "^1.2"}`).
    """
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return []
    poetry = tool.get("poetry")
    if not isinstance(poetry, dict):
        return []

    tables: list[dict[str, object]] = []
    main = poetry.get("dependencies")
    if isinstance(main, dict):
        tables.append(main)
    group = poetry.get("group")
    if isinstance(group, dict):
        for entry in group.values():
            if isinstance(entry, dict):
                sub = entry.get("dependencies")
                if isinstance(sub, dict):
                    tables.append(sub)

    deps: list[Dependency] = []
    for table in tables:
        for name, constraint in table.items():
            if name.lower() == "python":  # the interpreter, not a package
                continue
            spec: str | None = None
            if isinstance(constraint, str):
                spec = constraint
            elif isinstance(constraint, dict):
                raw = constraint.get("version")
                spec = raw if isinstance(raw, str) else None
            version = spec if spec and spec[0].isdigit() else None
            deps.append(
                _make_dependency(name, source=source, version=version, specifier=spec)
            )
    return deps


def parse_pyproject(path: Path, repo_root: Path | None = None) -> list[Dependency]:
    """Parse PEP 621 + PEP 735 + Poetry dependency declarations."""
    root = repo_root or path.parent
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return []

    try:
        source = str(path.relative_to(root))
    except ValueError:
        source = path.name

    return _parse_pep621(data, source) + _parse_poetry(data, source)


# --------------------------------------------------------------------------
# uv.lock
# --------------------------------------------------------------------------


def parse_uv_lock(path: Path, repo_root: Path | None = None) -> list[Dependency]:
    """Parse uv.lock into fully-resolved dependencies.

    A lockfile lists every package in the resolution, including the project
    itself and all transitives. `is_direct` is derived by reading the root
    project's own dependency list rather than assumed — transitives are
    still worth scanning, but they rank lower and are reported differently.
    """
    root = repo_root or path.parent
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return []

    packages = data.get("package")
    if not isinstance(packages, list):
        return []

    try:
        source = str(path.relative_to(root))
    except ValueError:
        source = path.name

    # A package is "local" (the project under scan or a workspace member)
    # when its source is a directory rather than a registry.
    local_names: set[str] = set()
    direct_names: set[str] = set()

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        if not isinstance(name, str):
            continue
        pkg_source = pkg.get("source")
        is_local = isinstance(pkg_source, dict) and (
            "editable" in pkg_source or "directory" in pkg_source or "virtual" in pkg_source
        )
        if not is_local:
            continue
        local_names.add(normalize(name))
        direct_names |= _direct_names_of(pkg)

    deps: list[Dependency] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str):
            continue
        normalized = normalize(name)
        if normalized in local_names:
            continue  # never report the project under scan as its own dep
        deps.append(
            _make_dependency(
                normalized,
                source=source,
                version=version if isinstance(version, str) else None,
                is_direct=normalized in direct_names,
            )
        )
    return deps


def _direct_names_of(pkg: dict[str, object]) -> set[str]:
    """Collect names the root package declares directly.

    uv records these under `dependencies` and, for declared metadata, under
    `[package.metadata] requires-dist` plus dev-dependency groups.
    """
    names: set[str] = set()

    def harvest(entries: object) -> None:
        if not isinstance(entries, list):
            return
        for entry in entries:
            if isinstance(entry, dict):
                entry_name = entry.get("name")
                if isinstance(entry_name, str):
                    names.add(normalize(entry_name))

    harvest(pkg.get("dependencies"))

    dev = pkg.get("dev-dependencies")
    if isinstance(dev, dict):
        for group in dev.values():
            harvest(group)

    meta = pkg.get("metadata")
    if isinstance(meta, dict):
        harvest(meta.get("requires-dist"))
        dev_meta = meta.get("requires-dev")
        if isinstance(dev_meta, dict):
            for group in dev_meta.values():
                harvest(group)

    return names


# --------------------------------------------------------------------------
# repo-level entry point
# --------------------------------------------------------------------------


def find_manifests(repo_root: Path) -> list[Path]:
    """Locate manifest files, skipping vendored and build directories."""
    found: list[Path] = []
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file() or path.name not in MANIFEST_FILENAMES:
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(repo_root).parts):
            continue
        found.append(path)
    # requirements-*.txt is common enough to be worth catching too.
    for path in sorted(repo_root.rglob("requirements*.txt")):
        if path in found or not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(repo_root).parts):
            continue
        found.append(path)
    return found


def _merge(deps: Iterable[Dependency]) -> list[Dependency]:
    """Deduplicate by name, preferring the entry that carries a version.

    The same package routinely appears in pyproject.toml and uv.lock. The
    locked entry is strictly more useful downstream, so a versioned record
    always wins over an unversioned one.
    """
    best: dict[str, Dependency] = {}
    for dep in deps:
        current = best.get(dep.name)
        if current is None:
            best[dep.name] = dep
            continue
        if current.version is None and dep.version is not None:
            # Keep the richer version info but do not lose direct-ness.
            best[dep.name] = dep.model_copy(
                update={"is_direct": current.is_direct or dep.is_direct}
            )
        elif dep.is_direct and not current.is_direct:
            best[dep.name] = current.model_copy(update={"is_direct": True})
    return sorted(best.values(), key=lambda d: d.name)


def parse_manifests(repo_root: Path) -> list[Dependency]:
    """Parse every manifest under `repo_root` into a deduplicated list."""
    root = repo_root.resolve()
    collected: list[Dependency] = []

    for path in find_manifests(root):
        if path.name == "uv.lock":
            collected.extend(parse_uv_lock(path, root))
        elif path.name == "pyproject.toml":
            collected.extend(parse_pyproject(path, root))
        else:
            collected.extend(parse_requirements_txt(path, root))

    return _merge(collected)
