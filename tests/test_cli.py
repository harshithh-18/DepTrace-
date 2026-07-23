"""CLI tests, focused on the contract a CI system depends on.

Exit codes are the product here. A scanner that reports correctly but exits
0 on a reachable finding cannot gate a merge, and one that exits 1 when the
scan itself broke turns an outage into a fake security finding. Those two
failures are what these tests exist to prevent.

Everything runs against fake providers — no network, no LLM.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from deptrace import cli
from deptrace.core.state import Dependency, RunState, Verdict, Vulnerability
from deptrace.providers.llm.base import SymbolExtraction
from deptrace.providers.store.sqlite import SQLiteStateStore

runner = CliRunner()

VULN = Vulnerability(
    id="GHSA-6757-jp84-gxfx",
    summary="Improper Input Validation in PyYAML",
    details="yaml.load allows arbitrary code execution.",
    severity="CRITICAL",
    fixed_version="5.3.1",
)

VULNERABLE_APP = "import yaml\n\ndef load(p):\n    return yaml.load(open(p))\n"
SAFE_APP = "import yaml\n\ndef load(p):\n    return yaml.safe_load(open(p))\n"


class FakeVulnDB:
    name = "fake"

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    async def find_vulnerabilities(
        self, dependencies: list[Dependency]
    ) -> dict[str, list[Vulnerability]]:
        return {"pyyaml": [VULN]}

    async def aclose(self) -> None:
        return None


class FakeExtractor:
    name = "fake"

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    async def extract(
        self, *, package: str, vuln_id: str, summary: str, details: str
    ) -> SymbolExtraction:
        from deptrace.core.state import VulnerableSymbol

        return SymbolExtraction(
            symbols=[VulnerableSymbol(module="yaml", name="load", confidence=0.9)]
        )


@pytest.fixture(autouse=True)
def fake_providers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Swap in offline providers and an isolated scan database."""
    monkeypatch.setattr(cli, "OSVProvider", FakeVulnDB)
    monkeypatch.setattr(cli, "LLMSymbolExtractor", FakeExtractor)
    monkeypatch.setattr(
        cli, "SQLiteStateStore", lambda *a, **k: SQLiteStateStore(tmp_path / "scans.db")
    )


def _repo(tmp_path: Path, source: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("pyyaml==5.3\n")
    (repo / "app.py").write_text(source)
    return repo


# -- exit codes: the CI contract -------------------------------------------


def test_reachable_finding_exits_1(tmp_path: Path) -> None:
    """This is what blocks a merge."""
    result = runner.invoke(cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP))])
    assert result.exit_code == 1
    assert "REACHABLE" in result.stdout


def test_clean_project_exits_0(tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["scan", str(_repo(tmp_path, SAFE_APP))])
    assert result.exit_code == 0


def test_scan_error_exits_2_not_1(tmp_path: Path) -> None:
    """A broken scan must never be mistaken for a security finding."""
    result = runner.invoke(cli.app, ["scan", str(tmp_path / "does-not-exist")])
    assert result.exit_code == 2


def test_fail_on_any_exits_1_for_unreachable_findings(tmp_path: Path) -> None:
    result = runner.invoke(
        cli.app, ["scan", str(_repo(tmp_path, SAFE_APP)), "--fail-on", "any"]
    )
    assert result.exit_code == 1


def test_fail_on_never_always_exits_0(tmp_path: Path) -> None:
    result = runner.invoke(
        cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP)), "--fail-on", "never"]
    )
    assert result.exit_code == 0


# -- output formats --------------------------------------------------------


def test_json_output_is_parseable(tmp_path: Path) -> None:
    """`deptrace scan -f json > out.json` must produce valid JSON."""
    result = runner.invoke(
        cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP)), "-f", "json"]
    )
    payload = json.loads(result.stdout)
    assert payload["status"] == "done"
    assert payload["findings"][0]["verdict"] == "reachable"


def test_sarif_output_is_parseable(tmp_path: Path) -> None:
    result = runner.invoke(
        cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP)), "-f", "sarif"]
    )
    doc = json.loads(result.stdout)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_markdown_output_renders(tmp_path: Path) -> None:
    result = runner.invoke(
        cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP)), "-f", "markdown"]
    )
    assert "# DepTrace Report" in result.stdout


def test_output_file_is_written(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    runner.invoke(
        cli.app,
        ["scan", str(_repo(tmp_path, VULNERABLE_APP)), "-f", "json", "-o", str(target)],
    )
    assert json.loads(target.read_text())["status"] == "done"


def test_verbose_reveals_not_reachable_rows(tmp_path: Path) -> None:
    repo = _repo(tmp_path, SAFE_APP)
    quiet = runner.invoke(cli.app, ["scan", str(repo)])
    loud = runner.invoke(cli.app, ["scan", str(repo), "--verbose"])

    assert "GHSA-6757" not in quiet.stdout
    assert "GHSA-6757" in loud.stdout


# -- degraded mode ---------------------------------------------------------


def test_no_llm_reports_advisories_without_claiming_reachability(
    tmp_path: Path,
) -> None:
    """The honest degraded mode: no model, so no reachability verdict."""
    result = runner.invoke(
        cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP)), "--no-llm", "-f", "json"]
    )
    payload = json.loads(result.stdout)

    assert payload["metrics"]["reachable"] == 0
    assert payload["findings"][0]["verdict"] == "needs_review"


async def test_null_extractor_makes_no_claims() -> None:
    extraction = await cli.NullExtractor().extract(
        package="p", vuln_id="v", summary="s", details="d"
    )
    assert extraction.symbols == []


# -- persistence -----------------------------------------------------------


def test_scan_is_persisted_and_listed(tmp_path: Path) -> None:
    runner.invoke(cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP))])
    result = runner.invoke(cli.app, ["history"])
    assert "Scan history" in result.stdout


def test_no_save_skips_persistence(tmp_path: Path) -> None:
    runner.invoke(cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP)), "--no-save"])
    result = runner.invoke(cli.app, ["history"])
    assert "No scans recorded yet." in result.stdout


def test_show_replays_a_stored_scan(tmp_path: Path) -> None:
    scan_result = runner.invoke(
        cli.app, ["scan", str(_repo(tmp_path, VULNERABLE_APP)), "-f", "json"]
    )
    scan_id = json.loads(scan_result.stdout)["scan_id"]

    result = runner.invoke(cli.app, ["show", scan_id])
    assert result.exit_code == 0
    assert "REACHABLE" in result.stdout


def test_show_unknown_scan_exits_2() -> None:
    result = runner.invoke(cli.app, ["show", "deadbeefcafe"])
    assert result.exit_code == 2


# -- introspection ---------------------------------------------------------


def test_providers_command_reports_selection() -> None:
    result = runner.invoke(cli.app, ["providers"])
    assert result.exit_code == 0
    assert "ollama" in result.stdout


def test_help_lists_the_commands() -> None:
    result = runner.invoke(cli.app, ["--help"])
    for command in ("scan", "history", "show", "providers"):
        assert command in result.stdout


# -- store -----------------------------------------------------------------


def test_store_round_trips_state(tmp_path: Path) -> None:
    store = SQLiteStateStore(tmp_path / "s.db")
    state = RunState(target="/repo", status="done")
    store.save(state)

    loaded = store.load(state.scan_id)
    assert loaded is not None
    assert loaded.scan_id == state.scan_id


def test_store_upserts_rather_than_duplicating(tmp_path: Path) -> None:
    store = SQLiteStateStore(tmp_path / "s.db")
    state = RunState(target="/repo", status="running")
    store.save(state)

    state.status = "done"
    store.save(state)

    assert len(store.list_scans()) == 1
    loaded = store.load(state.scan_id)
    assert loaded is not None and loaded.status == "done"


def test_store_returns_none_for_unknown_scan(tmp_path: Path) -> None:
    assert SQLiteStateStore(tmp_path / "s.db").load("nope") is None


def test_store_preserves_evidence(tmp_path: Path) -> None:
    """Persistence must not lose the proof behind a verdict."""
    from deptrace.core.state import Evidence, Finding

    store = SQLiteStateStore(tmp_path / "s.db")
    finding = Finding(
        dependency=Dependency(name="pyyaml", version="5.3", source="r"),
        vulnerability=VULN,
        verdict=Verdict.REACHABLE,
        evidence=(Evidence(file="app.py", line=4, symbol="yaml.load", kind="call"),),
    )
    state = RunState(target="/repo", findings=[finding])
    store.save(state)

    loaded = store.load(state.scan_id)
    assert loaded is not None
    assert loaded.findings[0].evidence[0].line == 4
    assert loaded.findings[0].evidence[0].produced_by == "ast_engine"


def test_store_creates_its_parent_directory(tmp_path: Path) -> None:
    store = SQLiteStateStore(tmp_path / "nested" / "dir" / "s.db")
    assert store.path.parent.is_dir()
