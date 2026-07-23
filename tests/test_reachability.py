"""Tests for the AST reachability engine.

This is the moat, so it is tested hardest. Two properties matter most:

  * a REACHABLE claim must be backed by a real file:line (no false alarms);
  * a NOT_REACHABLE claim must not hide a real call (no silent misses).

False negatives are the critical failure — a missed reachable CVE is worse
than a false alarm — so the "must be found" cases outnumber the rest.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from deptrace.core.state import Evidence, VulnerableSymbol
from deptrace.tools.reachability import (
    ImportTable,
    build_import_table,
    dotted_name,
    find_reachable,
    iter_python_files,
    symbol_matches,
)

FIXTURES = Path(__file__).resolve().parent.parent / "evals" / "fixtures"

YAML_LOAD = VulnerableSymbol(module="yaml", name="load")


def _scan(fixture: str, targets: list[VulnerableSymbol] | None = None):
    return find_reachable(FIXTURES / fixture, targets or [YAML_LOAD])


def _write(tmp_path: Path, source: str, name: str = "app.py") -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    return path


# -- the trust boundary ----------------------------------------------------


def test_evidence_is_always_attributed_to_the_ast_engine() -> None:
    """Every Evidence object must carry the AST engine's provenance."""
    report = _scan("direct_call")
    assert report.evidence
    for item in report.evidence:
        assert item.produced_by == "ast_engine"
        assert isinstance(item, Evidence)


def test_no_targets_means_no_evidence(tmp_path: Path) -> None:
    """Nothing to hunt for => nothing found. Never speculative."""
    _write(tmp_path, "import yaml\nyaml.load(1)\n")
    assert find_reachable(tmp_path, []).evidence == []


def test_missing_directory_is_not_an_error() -> None:
    assert find_reachable(Path("/nonexistent/xyz"), [YAML_LOAD]).evidence == []


# -- positive cases: these MUST be found -----------------------------------


def test_direct_call_is_found_with_real_location() -> None:
    report = _scan("direct_call")
    assert len(report.evidence) == 1

    found = report.evidence[0]
    assert found.symbol == "yaml.load"
    assert found.kind == "call"
    assert found.file == "app.py"
    assert found.line == 9
    assert "yaml.load(handle)" in found.snippet


def test_aliased_module_import_resolves() -> None:
    """`import yaml as y` then `y.load()` — a text search would miss this."""
    report = _scan("aliased_import")
    assert [e.symbol for e in report.evidence] == ["yaml.load"]
    assert "y.load(handle)" in report.evidence[0].snippet


def test_from_import_binds_bare_name() -> None:
    """`from yaml import load` makes the call site a bare Name."""
    report = _scan("from_import")
    assert [e.symbol for e in report.evidence] == ["yaml.load"]


def test_from_import_alias_resolves_to_its_own_symbol() -> None:
    """`safe_load as sl` must resolve to safe_load, not to load."""
    report = _scan("from_import", [VulnerableSymbol(module="yaml", name="safe_load")])
    assert [e.symbol for e in report.evidence] == ["yaml.safe_load"]


def test_nested_attribute_chain_resolves() -> None:
    report = _scan("nested_attr", [VulnerableSymbol(module="yaml.composer")])
    assert report.evidence
    assert all(e.symbol.startswith("yaml.composer") for e in report.evidence)


def test_module_level_target_matches_any_use() -> None:
    """A symbol with no name matches any use of the module."""
    report = _scan("direct_call", [VulnerableSymbol(module="yaml", name=None)])
    assert report.evidence


def test_lazy_import_inside_function_is_found(tmp_path: Path) -> None:
    """A deferred import is still a real dependency edge."""
    _write(tmp_path, "def f(s):\n    import yaml\n    return yaml.load(s)\n")
    assert find_reachable(tmp_path, [YAML_LOAD]).evidence


def test_attribute_reference_without_call_is_found(tmp_path: Path) -> None:
    """`handler = yaml.load` reaches the symbol without calling it."""
    _write(tmp_path, "import yaml\nhandler = yaml.load\n")
    report = find_reachable(tmp_path, [YAML_LOAD])
    assert len(report.evidence) == 1
    assert report.evidence[0].kind == "attribute"


def test_finds_calls_across_multiple_files(tmp_path: Path) -> None:
    _write(tmp_path, "import yaml\nyaml.load(1)\n", "a.py")
    _write(tmp_path, "import yaml\nyaml.load(2)\n", "sub/b.py")
    report = find_reachable(tmp_path, [YAML_LOAD])
    assert {e.file for e in report.evidence} == {"a.py", str(Path("sub/b.py"))}


# -- negative cases: these must NOT be found -------------------------------


def test_safe_usage_only_is_not_reachable() -> None:
    """The core value proposition: safe_load only => no finding."""
    assert _scan("not_reachable").evidence == []


def test_similarly_named_modules_do_not_match() -> None:
    """`yaml_helper.load` and `myyaml.load` are not `yaml.load`."""
    report = _scan("not_reachable")
    assert not any("yaml_helper" in e.symbol for e in report.evidence)
    assert not any("myyaml" in e.symbol for e in report.evidence)


def test_unimported_name_does_not_match(tmp_path: Path) -> None:
    """A local function called `load` is not `yaml.load`."""
    _write(tmp_path, "def load(x):\n    return x\nload(1)\n")
    assert find_reachable(tmp_path, [YAML_LOAD]).evidence == []


def test_shadowed_local_name_is_not_the_library(tmp_path: Path) -> None:
    _write(tmp_path, "import json as yaml\nyaml.load(1)\n")
    report = find_reachable(tmp_path, [YAML_LOAD])
    assert report.evidence == []  # this `yaml` is really json


def test_vendored_code_is_excluded() -> None:
    """The .venv contains yaml.load; first-party code does not."""
    report = _scan("vendored")
    assert report.evidence == []
    assert report.files_scanned == 1  # only app.py


@pytest.mark.parametrize(
    "excluded", [".venv", "node_modules", "build", "__pycache__", ".tox", "site-packages"]
)
def test_all_vendored_directories_are_pruned(tmp_path: Path, excluded: str) -> None:
    _write(tmp_path, "import yaml\nyaml.load(1)\n", f"{excluded}/lib.py")
    assert find_reachable(tmp_path, [YAML_LOAD]).evidence == []


# -- the undecidable third state -------------------------------------------


def test_dynamic_import_is_flagged_not_guessed() -> None:
    """A computed module name => flagged for review, no Evidence invented."""
    report = _scan("dynamic_import")
    assert report.has_dynamic_usage
    assert report.evidence == []  # we do not claim reachability we cannot prove
    assert "importlib.import_module" in {u.call for u in report.dynamic_usages}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("getattr(m, name)(1)", "getattr"),               # computed attribute
        ("importlib.import_module(name)", "importlib.import_module"),
        ("__import__(pkg)", "__import__"),
        ("eval('yaml.load(x)')", "eval"),                 # always undecidable
        ("exec('import yaml')", "exec"),
    ],
)
def test_undecidable_constructs_are_flagged(tmp_path: Path, source: str, expected: str) -> None:
    _write(tmp_path, f"import importlib\n{source}\n")
    report = find_reachable(tmp_path, [YAML_LOAD])
    assert expected in {u.call for u in report.dynamic_usages}


@pytest.mark.parametrize(
    "source",
    [
        "getattr(obj, 'status', None)",       # literal attribute
        "getattr(self, 'headers')",
        "importlib.import_module('yaml')",    # literal module
        "__import__('yaml')",
    ],
)
def test_constant_arguments_are_not_flagged(tmp_path: Path, source: str) -> None:
    """`getattr(o, "x")` is as analyzable as `o.x` — flagging it would push
    nearly every real repo into NEEDS_REVIEW and destroy the verdict split.
    """
    _write(tmp_path, f"import importlib\n{source}\n")
    assert find_reachable(tmp_path, [YAML_LOAD]).dynamic_usages == []


def test_dynamic_usage_carries_a_location() -> None:
    report = _scan("dynamic_import")
    usage = report.dynamic_usages[0]
    assert usage.file == "app.py"
    assert usage.line > 0
    assert usage.snippet


# -- resilience ------------------------------------------------------------


def test_syntax_error_is_recorded_and_scan_continues() -> None:
    """A broken file must never abort the scan."""
    report = _scan("broken_syntax")
    assert report.files_failed == ["app.py"]
    assert [e.file for e in report.evidence] == ["good.py"]


def test_unreadable_file_does_not_crash(tmp_path: Path) -> None:
    path = _write(tmp_path, "")
    path.write_bytes(b"\xff\xfe\x00invalid")
    report = find_reachable(tmp_path, [YAML_LOAD])
    assert report.files_failed  # recorded, not raised


def test_empty_file_is_handled(tmp_path: Path) -> None:
    _write(tmp_path, "")
    assert find_reachable(tmp_path, [YAML_LOAD]).evidence == []


def test_call_site_is_reported_once(tmp_path: Path) -> None:
    """A Call wraps an Attribute; the same site must not be double-counted."""
    _write(tmp_path, "import yaml\nyaml.load(1)\n")
    assert len(find_reachable(tmp_path, [YAML_LOAD]).evidence) == 1


# -- unit-level: import table ----------------------------------------------


def _table(source: str, package_parts: tuple[str, ...] = ()) -> ImportTable:
    return build_import_table(ast.parse(source), package_parts=package_parts)


def test_import_table_plain_and_aliased() -> None:
    table = _table("import yaml\nimport numpy as np\nimport os.path\n")
    assert table.resolve("yaml") == "yaml"
    assert table.resolve("np.array") == "numpy.array"
    assert table.resolve("os.path.join") == "os.path.join"


def test_import_table_from_imports() -> None:
    table = _table("from yaml import load, safe_load as sl\n")
    assert table.resolve("load") == "yaml.load"
    assert table.resolve("sl") == "yaml.safe_load"


def test_import_table_unknown_name_is_none() -> None:
    """Unresolvable names return None rather than a guess."""
    assert _table("import yaml\n").resolve("requests.get") is None


def test_relative_import_resolves_against_package() -> None:
    table = _table("from . import helpers\n", package_parts=("pkg", "app"))
    assert table.resolve("helpers") == "pkg.helpers"


def test_relative_import_inside_package_init() -> None:
    """In `pkg/__init__.py` the file *is* the package: `.` means `pkg`."""
    table = _table("from . import helpers\n", package_parts=("pkg", "__init__"))
    assert table.resolve("helpers") == "pkg.helpers"


def test_relative_import_walks_up_multiple_levels() -> None:
    table = _table("from .. import top\n", package_parts=("pkg", "sub", "mod"))
    assert table.resolve("top") == "pkg.top"


def test_relative_import_beyond_root_is_dropped() -> None:
    """`from ... import x` at the top level cannot be resolved; don't invent."""
    table = _table("from ... import x\n", package_parts=("app",))
    assert table.resolve("x") is None


def test_relative_import_does_not_masquerade_as_third_party() -> None:
    """A first-party `helpers.parse` must never be attributed to yaml."""
    report = find_reachable(FIXTURES / "relative_import", [YAML_LOAD])
    assert {e.file for e in report.evidence} == {str(Path("pkg/helpers.py"))}


# -- unit-level: helpers ---------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("yaml.load", "yaml.load"),
        ("a.b.c.d", "a.b.c.d"),
        ("load", "load"),
        ("obj.method().chained", None),  # not statically knowable
        ("d['k'].attr", None),
    ],
)
def test_dotted_name_extraction(source: str, expected: str | None) -> None:
    node = ast.parse(source, mode="eval").body
    assert dotted_name(node) == expected


@pytest.mark.parametrize(
    ("resolved", "module", "name", "expected"),
    [
        ("yaml.load", "yaml", "load", True),
        ("yaml.load.inner", "yaml", "load", True),   # attribute of the target
        ("yaml.safe_load", "yaml", "load", False),
        ("yaml_helper.load", "yaml", "load", False), # dot-boundary guard
        ("yaml.load", "yaml", None, True),           # module-level target
        ("yamlx.load", "yaml", None, False),
        ("", "yaml", "load", False),
    ],
)
def test_symbol_matching_rules(
    resolved: str, module: str, name: str | None, expected: bool
) -> None:
    target = VulnerableSymbol(module=module, name=name)
    assert symbol_matches(resolved, target) is expected


def test_iter_python_files_prunes_and_sorts(tmp_path: Path) -> None:
    _write(tmp_path, "", "b.py")
    _write(tmp_path, "", "a.py")
    _write(tmp_path, "", ".venv/skipped.py")
    found = [p.name for p in iter_python_files(tmp_path)]
    assert found == ["a.py", "b.py"]
