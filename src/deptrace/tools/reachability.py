"""The AST reachability engine — the only component allowed to mint Evidence.

This module is the other half of DepTrace's trust boundary. The LLM layer
*proposes* which symbol an advisory implicates; this module *proves* whether
the scanned repo actually reaches it. Everything here is therefore:

  * **pure** — a repo path and a list of symbols in, Evidence out;
  * **deterministic** — same inputs always yield the same findings, so a
    verdict can be re-checked by anyone reading the report;
  * **offline** — no network, no LLM, no async. It cannot be rate-limited,
    it cannot hallucinate, and it runs identically in CI.

The analysis is a two-pass, per-file process:

  pass 1  build an import table:  local alias -> fully-qualified dotted name
  pass 2  walk calls/attributes, resolve names through that table, and emit
          Evidence when a resolved name matches a symbol we were asked about

Scope is deliberately honest. This is *not* a type inference engine: it
resolves names that were imported at module level, which is how vulnerable
library functions are reached in practice. Where static analysis genuinely
cannot decide — dynamic imports, reflection — the file is flagged so the
finding is routed to NEEDS_REVIEW rather than guessed at in either direction.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from deptrace.core.state import Evidence, VulnerableSymbol

# Directories that must never be analyzed. Scanning a vendored .venv would
# find the vulnerable function *inside the library's own source* and mark
# every project reachable — the classic false-positive catastrophe.
EXCLUDED_DIRS = frozenset(
    {
        ".venv",
        "venv",
        "env",
        ".env",
        "virtualenv",
        "site-packages",
        "dist-packages",
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".nox",
        "build",
        "dist",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".eggs",
        "eggs",
    }
)

# Calls that defeat static resolution. Their presence does not by itself
# prove reachability — it proves we cannot rule it out, which is a different
# and honest claim that routes the finding to NEEDS_REVIEW.
DYNAMIC_CALLS = frozenset(
    {
        "getattr",
        "eval",
        "exec",
        "__import__",
        "importlib.import_module",
        "importlib.__import__",
        "compile",
    }
)


def _is_truly_dynamic(node: ast.Call) -> bool:
    """Distinguish genuinely undecidable calls from constant-argument ones.

    This matters more than it looks. `getattr(obj, "status", None)` is
    everywhere in real code — 27 of 29 hits on the `requests` codebase were
    this shape — but the attribute is a literal, so it is exactly as
    analyzable as `obj.status`. Flagging those would push almost every real
    repo into NEEDS_REVIEW and collapse the three-state verdict into one
    useless state.

    Only a *computed* target defeats static analysis:

        getattr(mod, "load")        -> decidable, not flagged
        getattr(mod, user_input)    -> undecidable, flagged
        import_module("yaml")       -> decidable, not flagged
        import_module(name)         -> undecidable, flagged

    `eval`/`exec`/`compile` are always flagged: even with a literal argument
    they execute code this engine does not analyze.
    """
    target = dotted_name(node.func)
    if target in ("eval", "exec", "compile"):
        return True

    # The interesting argument is the attribute/module name: arg 2 for
    # getattr, arg 1 for the import helpers.
    index = 1 if target == "getattr" else 0
    if len(node.args) <= index:
        return True  # unusual shape; be conservative and flag it

    return not isinstance(node.args[index], ast.Constant)


@dataclass(frozen=True)
class DynamicUsage:
    """A statically-undecidable construct found in the scanned code."""

    file: str
    line: int
    call: str
    snippet: str = ""


@dataclass
class ScanReport:
    """Everything one reachability pass learned about a repo."""

    evidence: list[Evidence] = field(default_factory=list)
    dynamic_usages: list[DynamicUsage] = field(default_factory=list)
    files_scanned: int = 0
    files_failed: list[str] = field(default_factory=list)

    @property
    def has_dynamic_usage(self) -> bool:
        return bool(self.dynamic_usages)


def dotted_name(node: ast.AST) -> str | None:
    """Flatten a Name/Attribute chain into a dotted string.

    `yaml.load` -> "yaml.load", `a.b.c.d` -> "a.b.c.d", plain `load` ->
    "load". Returns None when the chain is not statically resolvable, e.g.
    `obj.method().chained` — nothing can be known about a call's return
    value without type inference, so we decline to guess.
    """
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def iter_python_files(root: Path) -> list[Path]:
    """Find analyzable .py files, pruning vendored and build directories."""
    files: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        try:
            relative = path.relative_to(root)
        except ValueError:  # pragma: no cover - defensive
            continue
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if path.is_file():
            files.append(path)
    return files


class ImportTable:
    """Maps a module's local names to the fully-qualified symbols they refer to.

    Two distinct kinds of binding have to be tracked, because they resolve
    differently at the call site:

        import yaml              alias "yaml"  -> module "yaml"
        import numpy as np       alias "np"    -> module "numpy"
        from yaml import load    alias "load"  -> symbol "yaml.load"

    In the first two cases a call looks like `alias.attr`, so the attribute
    must be appended during resolution. In the third the alias *is* already
    the full symbol and nothing may be appended.
    """

    def __init__(self) -> None:
        self.modules: dict[str, str] = {}  # alias -> module path
        self.symbols: dict[str, str] = {}  # alias -> fully-qualified symbol

    def resolve(self, name: str) -> str | None:
        """Resolve a dotted name found in code to its fully-qualified form."""
        if not name:
            return None

        # Longest-prefix match: `a.b.c` may bind at "a.b" or at "a".
        parts = name.split(".")
        for cut in range(len(parts), 0, -1):
            head = ".".join(parts[:cut])
            rest = parts[cut:]

            if head in self.symbols:
                target = self.symbols[head]
                return ".".join([target, *rest]) if rest else target

            if head in self.modules:
                target = self.modules[head]
                return ".".join([target, *rest]) if rest else target

        return None


def build_import_table(tree: ast.Module, *, package_parts: tuple[str, ...] = ()) -> ImportTable:
    """Collect every module-level and nested import in one file.

    `package_parts` is the dotted package path of the file being analyzed,
    used to resolve relative imports (`from . import x`). Nested imports
    (inside functions or `try:` blocks) are included deliberately — a lazy
    `import yaml` inside a function is still a real dependency edge.
    """
    table = ImportTable()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import a.b.c` binds the *root* name `a` unless aliased;
                # `import a.b.c as x` binds `x` to the full path.
                if alias.asname:
                    table.modules[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    table.modules[root] = root
                    # Keep the full path too so `a.b.c.f()` resolves exactly.
                    table.modules.setdefault(alias.name, alias.name)

        elif isinstance(node, ast.ImportFrom):
            module = _resolve_from_module(node, package_parts)
            if module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    # A star import binds unknown names; record the module so
                    # bare calls can still be attributed to it.
                    table.modules.setdefault(module, module)
                    continue
                local = alias.asname or alias.name
                table.symbols[local] = f"{module}.{alias.name}" if module else alias.name

    return table


def _resolve_from_module(node: ast.ImportFrom, package_parts: tuple[str, ...]) -> str | None:
    """Resolve the module of a `from ... import ...`, including relative form.

    `node.level` is the number of leading dots. Level 1 means "this package",
    level 2 means "one package up", and so on.
    """
    if not node.level:
        return node.module or ""

    # `package_parts` names the *module* (pkg.app). One dot means "the
    # package containing this module", so level 1 drops the module name,
    # level 2 drops one package above it, and so on.
    keep = len(package_parts) - node.level
    if keep < 0:
        return None  # escapes the scanned tree; not resolvable here
    base = package_parts[:keep]
    if node.module:
        return ".".join([*base, node.module]) if base else node.module
    return ".".join(base)


def _package_parts(path: Path, root: Path) -> tuple[str, ...]:
    """Derive the dotted *module* path of a file, for relative-import resolution.

    The module name is always appended, including the synthetic `__init__`
    for package files. `_resolve_from_module` strips one component per
    leading dot, so this keeps both cases uniform: inside `pkg/__init__.py`,
    `from . import x` correctly resolves to `pkg.x` rather than bare `x`.
    """
    try:
        relative = path.relative_to(root)
    except ValueError:  # pragma: no cover - defensive
        return ()
    return (*relative.parts[:-1], relative.stem)


def _snippet(lines: list[str], lineno: int) -> str:
    """The source line behind a finding, so a human can verify it instantly."""
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:200]
    return ""


def symbol_matches(resolved: str, target: VulnerableSymbol) -> bool:
    """Decide whether a resolved dotted name is the symbol we are hunting.

    Matching is prefix-based on dot boundaries so that `yaml.load` matches a
    call to `yaml.load`, and a module-level target (`yaml`, name=None)
    matches any use of that module. The dot-boundary check is what stops
    `yaml_utils` from matching the module `yaml`.
    """
    if not resolved:
        return False

    if target.name:
        full = f"{target.module}.{target.name}" if target.module else target.name
    else:
        full = target.module

    if not full:
        return False
    return resolved == full or resolved.startswith(f"{full}.")


class _ReachabilityVisitor(ast.NodeVisitor):
    """Walks one file, resolving names against its import table.

    Calls and attribute accesses are both recorded: reaching a vulnerable
    symbol without calling it (`handler = yaml.load`) is still a real
    reference worth reporting, just under a different `kind`.
    """

    def __init__(
        self,
        *,
        rel_path: str,
        table: ImportTable,
        targets: list[VulnerableSymbol],
        lines: list[str],
    ) -> None:
        self.rel_path = rel_path
        self.table = table
        self.targets = targets
        self.lines = lines
        self.evidence: list[Evidence] = []
        self.dynamic: list[DynamicUsage] = []
        self._seen: set[tuple[int, int, str]] = set()

    def _record(self, node: ast.AST, name: str, kind: str) -> None:
        resolved = self.table.resolve(name)
        if resolved is None:
            return
        if not any(symbol_matches(resolved, t) for t in self.targets):
            return

        lineno = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        key = (lineno, col, resolved)
        if key in self._seen:
            return  # a Call wraps an Attribute; report the site once
        self._seen.add(key)

        self.evidence.append(
            Evidence(
                file=self.rel_path,
                line=lineno,
                column=col,
                symbol=resolved,
                kind="call" if kind == "call" else "attribute",
                snippet=_snippet(self.lines, lineno),
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func)
        if name is not None:
            resolved = self.table.resolve(name) or name
            if (resolved in DYNAMIC_CALLS or name in DYNAMIC_CALLS) and _is_truly_dynamic(node):
                self.dynamic.append(
                    DynamicUsage(
                        file=self.rel_path,
                        line=node.lineno,
                        call=resolved,
                        snippet=_snippet(self.lines, node.lineno),
                    )
                )
            self._record(node, name, "call")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = dotted_name(node)
        if name is not None:
            self._record(node, name, "attribute")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        # A bare `load(f)` from `from yaml import load` resolves through the
        # symbol table; only Load contexts count as a use.
        if isinstance(node.ctx, ast.Load):
            self._record(node, node.id, "attribute")
        self.generic_visit(node)


def analyze_file(
    path: Path,
    root: Path,
    targets: list[VulnerableSymbol],
) -> tuple[list[Evidence], list[DynamicUsage], bool]:
    """Analyze one file. Returns (evidence, dynamic usages, parsed_ok).

    A file that fails to parse is reported as failed and skipped — a syntax
    error in the target repo (or a Python 2 file) must never crash a scan.
    """
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], [], False

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [], [], False

    try:
        rel_path = str(path.relative_to(root))
    except ValueError:  # pragma: no cover - defensive
        rel_path = path.name

    table = build_import_table(tree, package_parts=_package_parts(path, root))
    visitor = _ReachabilityVisitor(
        rel_path=rel_path,
        table=table,
        targets=targets,
        lines=source.splitlines(),
    )
    visitor.visit(tree)
    return visitor.evidence, visitor.dynamic, True


def find_reachable(
    repo_root: Path | str,
    targets: list[VulnerableSymbol],
) -> ScanReport:
    """Search a repo for uses of the given symbols.

    This is the public entry point and the only source of `Evidence` in
    DepTrace. It is a pure function of (repo contents, targets): no network,
    no LLM, no hidden state.
    """
    root = Path(repo_root).resolve()
    report = ScanReport()
    if not targets or not root.is_dir():
        return report

    for path in iter_python_files(root):
        evidence, dynamic, ok = analyze_file(path, root, targets)
        if not ok:
            try:
                report.files_failed.append(str(path.relative_to(root)))
            except ValueError:  # pragma: no cover - defensive
                report.files_failed.append(path.name)
            continue
        report.files_scanned += 1
        report.evidence.extend(evidence)
        report.dynamic_usages.extend(dynamic)

    return report
