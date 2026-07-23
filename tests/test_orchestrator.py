"""End-to-end orchestrator tests.

These run the whole pipeline — manifests, vulnerability lookup, symbol
extraction, AST search, verification — against fake providers and a
synthetic repo whose ground truth is known exactly. No network, no LLM.

The most important test here is `test_hallucinated_claim_cannot_reach_the_report`:
it drives a *deliberately lying* extractor through the real pipeline and
proves the gate refuses it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deptrace.core.orchestrator import plan, scan, triage_one
from deptrace.core.state import Dependency, RunState, Verdict, Vulnerability, VulnerableSymbol
from deptrace.providers.llm.base import SymbolExtraction

PYYAML_VULN = Vulnerability(
    id="GHSA-6757-jp84-gxfx",
    summary="Improper Input Validation in PyYAML",
    details="yaml.load with FullLoader allows arbitrary code execution.",
    fixed_version="5.3.1",
)


class FakeVulnDB:
    """Returns a fixed advisory set. Stands in for OSV."""

    name = "fake"

    def __init__(self, results: dict[str, list[Vulnerability]] | None = None) -> None:
        self.results = results if results is not None else {"pyyaml": [PYYAML_VULN]}
        self.calls = 0

    async def find_vulnerabilities(
        self, dependencies: list[Dependency]
    ) -> dict[str, list[Vulnerability]]:
        self.calls += 1
        return self.results


class FakeExtractor:
    """Returns fixed claims. Stands in for the LLM."""

    name = "fake"

    def __init__(self, symbols: list[VulnerableSymbol] | None = None) -> None:
        self.symbols = symbols if symbols is not None else [
            VulnerableSymbol(module="yaml", name="load", confidence=0.95)
        ]
        self.calls: list[str] = []

    async def extract(
        self, *, package: str, vuln_id: str, summary: str, details: str
    ) -> SymbolExtraction:
        self.calls.append(vuln_id)
        return SymbolExtraction(symbols=list(self.symbols))


def _repo(tmp_path: Path, app_source: str) -> Path:
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n")
    (tmp_path / "app.py").write_text(app_source)
    return tmp_path


VULNERABLE_APP = "import yaml\n\ndef load(p):\n    return yaml.load(open(p))\n"
SAFE_APP = "import yaml\n\ndef load(p):\n    return yaml.safe_load(open(p))\n"


# -- THE headline test -----------------------------------------------------


async def test_hallucinated_claim_cannot_reach_the_report(tmp_path: Path) -> None:
    """A lying extractor is driven through the real pipeline and refused.

    The model claims a symbol that appears nowhere in the repo. Static
    analysis finds nothing. The verdict must not be REACHABLE, and the
    report must not contain a fabricated call site.
    """
    repo = _repo(tmp_path, SAFE_APP)  # only safe_load is ever called
    liar = FakeExtractor(
        [VulnerableSymbol(module="yaml", name="load", confidence=0.99)]
    )

    state = await scan(repo, vulndb=FakeVulnDB(), extractor=liar)

    assert len(state.findings) == 1
    finding = state.findings[0]
    assert finding.verdict is not Verdict.REACHABLE
    assert finding.evidence == ()
    assert state.metrics.reachable == 0


async def test_every_reachable_finding_carries_evidence(tmp_path: Path) -> None:
    """The invariant, checked over a real scan rather than in isolation."""
    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor())

    for finding in state.findings:
        if finding.verdict is Verdict.REACHABLE:
            assert finding.evidence
            assert all(e.produced_by == "ast_engine" for e in finding.evidence)


# -- the three verdicts, end to end ----------------------------------------


async def test_reachable_scan_produces_evidence_with_location(tmp_path: Path) -> None:
    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor())

    finding = state.findings[0]
    assert finding.verdict is Verdict.REACHABLE
    assert finding.evidence[0].file == "app.py"
    assert finding.evidence[0].line == 4
    assert finding.evidence[0].symbol == "yaml.load"
    assert state.metrics.reachable == 1


async def test_safe_usage_yields_not_reachable(tmp_path: Path) -> None:
    """The product's core claim: installed but unused => not an alert."""
    repo = _repo(tmp_path, SAFE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor())

    assert state.findings[0].verdict is Verdict.NOT_REACHABLE
    assert state.metrics.not_reachable == 1
    assert state.metrics.noise_reduction == 1.0


async def test_vague_advisory_yields_needs_review(tmp_path: Path) -> None:
    """No claims extracted => unknown, never silently safe."""
    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor([]))

    assert state.findings[0].verdict is Verdict.NEEDS_REVIEW
    assert state.metrics.needs_review == 1


async def test_dynamic_import_routes_to_needs_review(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n",
    )
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor())

    finding = state.findings[0]
    assert finding.verdict is Verdict.NEEDS_REVIEW
    assert finding.downgraded is True
    assert state.metrics.hallucination_blocked == 1


# -- planning --------------------------------------------------------------


def test_plan_deduplicates_pairs() -> None:
    dep = Dependency(name="pyyaml", version="5.3", source="req")
    pairs = plan([dep], {"pyyaml": [PYYAML_VULN, PYYAML_VULN]})
    assert len(pairs) == 1


def test_plan_skips_unknown_packages() -> None:
    dep = Dependency(name="pyyaml", version="5.3", source="req")
    pairs = plan([dep], {"other": [PYYAML_VULN]})
    assert pairs == []


def test_plan_is_deterministic() -> None:
    deps = [
        Dependency(name="b", version="1", source="r"),
        Dependency(name="a", version="1", source="r"),
    ]
    vulns = {"a": [PYYAML_VULN], "b": [PYYAML_VULN]}
    assert [p[0].name for p in plan(deps, vulns)] == ["a", "b"]


# -- state, metrics, and logging -------------------------------------------


async def test_run_state_is_json_serializable(tmp_path: Path) -> None:
    """Queue-readiness: a scan must round-trip through JSON."""
    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor())

    restored = RunState.model_validate_json(state.model_dump_json())
    assert restored.scan_id == state.scan_id
    assert len(restored.findings) == len(state.findings)
    assert restored.findings[0].evidence == state.findings[0].evidence


async def test_steps_are_recorded_for_each_stage(tmp_path: Path) -> None:
    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor())

    steps = {s.step for s in state.steps}
    assert "scan.parse_manifests" in steps
    assert "scan.query_vulndb" in steps
    assert "scan.triage" in steps


async def test_metrics_are_populated(tmp_path: Path) -> None:
    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor())

    assert state.metrics.total_dependencies == 1
    assert state.metrics.total_vulnerabilities == 1
    assert state.metrics.duration_ms > 0
    assert state.status == "done"


async def test_findings_are_sorted_actionable_first(tmp_path: Path) -> None:
    """A human reads the top of the table; put what matters there."""
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\nrequests==2.19.0\n")
    (tmp_path / "app.py").write_text(VULNERABLE_APP)

    safe_vuln = Vulnerability(id="GHSA-safe", summary="s", details="d")
    db = FakeVulnDB({"pyyaml": [PYYAML_VULN], "requests": [safe_vuln]})
    state = await scan(tmp_path, vulndb=db, extractor=FakeExtractor())

    verdicts = [f.verdict for f in state.findings]
    assert verdicts[0] is Verdict.REACHABLE


# -- graceful degradation --------------------------------------------------


async def test_extractor_failure_degrades_one_finding_only(tmp_path: Path) -> None:
    """One broken sub-task must not kill a scan."""

    class BrokenExtractor(FakeExtractor):
        async def extract(self, **kwargs: object) -> SymbolExtraction:
            raise RuntimeError("model exploded")

    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=BrokenExtractor())

    assert state.status == "done"
    assert state.findings[0].verdict is Verdict.NEEDS_REVIEW


async def test_vulndb_failure_does_not_crash_the_scan(tmp_path: Path) -> None:
    class BrokenDB(FakeVulnDB):
        async def find_vulnerabilities(
            self, dependencies: list[Dependency]
        ) -> dict[str, list[Vulnerability]]:
            raise RuntimeError("OSV is down")

    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(repo, vulndb=BrokenDB(), extractor=FakeExtractor())

    assert state.status == "done"
    assert state.findings == []
    assert any(not s.ok for s in state.steps)


async def test_repo_with_no_dependencies_is_handled(tmp_path: Path) -> None:
    state = await scan(tmp_path, vulndb=FakeVulnDB(), extractor=FakeExtractor())
    assert state.status == "done"
    assert state.findings == []


async def test_clean_repo_makes_no_llm_calls(tmp_path: Path) -> None:
    """No advisories => the expensive stage is skipped entirely."""
    (tmp_path / "requirements.txt").write_text("pyyaml==6.0.1\n")
    extractor = FakeExtractor()
    state = await scan(tmp_path, vulndb=FakeVulnDB({}), extractor=extractor)

    assert extractor.calls == []
    assert state.findings == []


# -- concurrency -----------------------------------------------------------


async def test_fan_out_handles_many_pairs(tmp_path: Path) -> None:
    """The TaskGroup path, exercised with more work than the semaphore allows."""
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n")
    (tmp_path / "app.py").write_text(VULNERABLE_APP)

    vulns = [
        Vulnerability(id=f"GHSA-{i:04d}", summary="s", details="d") for i in range(25)
    ]
    state = await scan(
        tmp_path,
        vulndb=FakeVulnDB({"pyyaml": vulns}),
        extractor=FakeExtractor(),
        concurrency=4,
    )

    assert len(state.findings) == 25
    assert all(f.verdict is Verdict.REACHABLE for f in state.findings)


async def test_triage_one_is_independently_usable(tmp_path: Path) -> None:
    """The sub-task is a pure unit, callable outside a full scan."""
    repo = _repo(tmp_path, VULNERABLE_APP)
    dep = Dependency(name="pyyaml", version="5.3", source="req")
    state = RunState(target=str(repo))

    finding = await triage_one(
        dep, PYYAML_VULN, repo_root=repo, extractor=FakeExtractor(), state=state
    )
    assert finding.verdict is Verdict.REACHABLE


async def test_claims_are_attached_for_transparency(tmp_path: Path) -> None:
    """A reader must be able to see what the model proposed, even if refused."""
    repo = _repo(tmp_path, SAFE_APP)
    state = await scan(repo, vulndb=FakeVulnDB(), extractor=FakeExtractor())

    claimed = state.findings[0].vulnerability.symbols
    assert [(s.module, s.name) for s in claimed] == [("yaml", "load")]


@pytest.mark.parametrize("concurrency", [1, 2, 16])
async def test_results_are_independent_of_concurrency(
    tmp_path: Path, concurrency: int
) -> None:
    repo = _repo(tmp_path, VULNERABLE_APP)
    state = await scan(
        repo, vulndb=FakeVulnDB(), extractor=FakeExtractor(), concurrency=concurrency
    )
    assert state.findings[0].verdict is Verdict.REACHABLE
