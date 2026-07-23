"""Tests for the report renderers.

Renderers must be pure: they present verdicts, never re-derive them. The
recurring assertion here is that a REACHABLE finding always carries a
checkable `file:line`, and that not-reachable noise stays out of the
machine-readable outputs a CI system consumes.
"""

from __future__ import annotations

import json

from rich.console import Console

from deptrace.core.state import (
    Dependency,
    Evidence,
    Finding,
    RunMetrics,
    RunState,
    Verdict,
    Vulnerability,
)
from deptrace.report import (
    render_json,
    render_markdown,
    render_sarif,
    render_table,
    sort_findings,
)


def _finding(
    package: str = "pyyaml",
    vuln_id: str = "GHSA-6757",
    verdict: Verdict = Verdict.REACHABLE,
    *,
    severity: str | None = "CRITICAL",
    evidence: tuple[Evidence, ...] = (),
) -> Finding:
    return Finding(
        dependency=Dependency(name=package, version="5.3", source="requirements.txt"),
        vulnerability=Vulnerability(
            id=vuln_id,
            summary=f"{package} is vulnerable",
            details="Full advisory text.",
            severity=severity,
            fixed_version="5.3.1",
        ),
        verdict=verdict,
        evidence=evidence,
        rationale="Call site found at app.py:42.",
    )


FACT = Evidence(file="app.py", line=42, symbol="yaml.load", kind="call", snippet="yaml.load(f)")


def _state(*findings: Finding) -> RunState:
    metrics = RunMetrics(
        total_dependencies=2,
        total_vulnerabilities=len(findings),
        reachable=sum(1 for f in findings if f.verdict is Verdict.REACHABLE),
        not_reachable=sum(1 for f in findings if f.verdict is Verdict.NOT_REACHABLE),
        needs_review=sum(1 for f in findings if f.verdict is Verdict.NEEDS_REVIEW),
    )
    return RunState(
        target="/repo", status="done", findings=list(findings), metrics=metrics
    )


def _rendered(state: RunState, *, verbose: bool = False) -> str:
    console = Console(width=200, record=True, force_terminal=False)
    render_table(state, console=console, verbose=verbose)
    return console.export_text()


# -- ordering --------------------------------------------------------------


def test_reachable_findings_sort_first() -> None:
    """A developer reads the top of the table and stops."""
    findings = [
        _finding("a", "GHSA-1", Verdict.NOT_REACHABLE),
        _finding("b", "GHSA-2", Verdict.NEEDS_REVIEW),
        _finding("c", "GHSA-3", Verdict.REACHABLE, evidence=(FACT,)),
    ]
    assert [f.verdict for f in sort_findings(findings)] == [
        Verdict.REACHABLE,
        Verdict.NEEDS_REVIEW,
        Verdict.NOT_REACHABLE,
    ]


def test_severity_orders_within_a_verdict() -> None:
    findings = [
        _finding("a", "GHSA-1", Verdict.REACHABLE, severity="LOW", evidence=(FACT,)),
        _finding("b", "GHSA-2", Verdict.REACHABLE, severity="CRITICAL", evidence=(FACT,)),
    ]
    assert [f.dependency.name for f in sort_findings(findings)] == ["b", "a"]


def test_sorting_is_stable_and_deterministic() -> None:
    findings = [
        _finding("z", "GHSA-2", Verdict.REACHABLE, evidence=(FACT,)),
        _finding("a", "GHSA-1", Verdict.REACHABLE, evidence=(FACT,)),
    ]
    first = [f.dependency.name for f in sort_findings(findings)]
    second = [f.dependency.name for f in sort_findings(findings)]
    assert first == second == ["a", "z"]


# -- table -----------------------------------------------------------------


def test_table_shows_location_for_reachable() -> None:
    text = _rendered(_state(_finding(evidence=(FACT,))))
    assert "app.py:42" in text
    assert "REACHABLE" in text


def test_table_hides_not_reachable_by_default() -> None:
    """Not-reachable findings are the noise this tool exists to remove."""
    state = _state(_finding("safe", "GHSA-9", Verdict.NOT_REACHABLE))
    assert "GHSA-9" not in _rendered(state)
    assert "GHSA-9" in _rendered(state, verbose=True)


def test_table_reports_noise_reduction() -> None:
    state = _state(
        _finding("a", "GHSA-1", Verdict.NOT_REACHABLE),
        _finding("b", "GHSA-2", Verdict.REACHABLE, evidence=(FACT,)),
    )
    assert "Noise reduction" in _rendered(state)


def test_table_reports_blocked_claims() -> None:
    """The headline safety metric must be visible in the default output."""
    state = _state(_finding(evidence=(FACT,)))
    state.metrics.hallucination_blocked = 3

    text = " ".join(_rendered(state).split())  # normalize Rich's line wrapping
    assert "blocked 3 unsupported claim(s)" in text


def test_empty_scan_says_so_clearly() -> None:
    assert "No known vulnerabilities" in _rendered(_state())


def test_multiple_evidence_is_indicated() -> None:
    second = Evidence(file="b.py", line=7, symbol="yaml.load", kind="call")
    text = _rendered(_state(_finding(evidence=(FACT, second))))
    assert "+1" in text


# -- json ------------------------------------------------------------------


def test_json_is_valid_and_complete() -> None:
    payload = json.loads(render_json(_state(_finding(evidence=(FACT,)))))

    assert payload["status"] == "done"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["evidence"][0]["line"] == 42


def test_json_preserves_evidence_provenance() -> None:
    """The trust boundary must survive serialization."""
    payload = json.loads(render_json(_state(_finding(evidence=(FACT,)))))
    assert payload["findings"][0]["evidence"][0]["produced_by"] == "ast_engine"


def test_json_round_trips_to_run_state() -> None:
    state = _state(_finding(evidence=(FACT,)))
    assert RunState.model_validate_json(render_json(state)).scan_id == state.scan_id


# -- markdown --------------------------------------------------------------


def test_markdown_has_metrics_and_findings_tables() -> None:
    text = render_markdown(_state(_finding(evidence=(FACT,))))
    assert "# DepTrace Report" in text
    assert "| Noise reduction |" in text
    assert "GHSA-6757" in text


def test_markdown_details_reachable_findings_with_evidence() -> None:
    text = render_markdown(_state(_finding(evidence=(FACT,))))
    assert "## Reachable findings" in text
    assert "app.py:42" in text
    assert "upgrade to `5.3.1`" in text


def test_markdown_handles_empty_scan() -> None:
    assert "No known vulnerabilities found." in render_markdown(_state())


# -- sarif -----------------------------------------------------------------


def test_sarif_is_well_formed() -> None:
    doc = json.loads(render_sarif(_state(_finding(evidence=(FACT,)))))

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "DepTrace"
    assert len(run["results"]) == 1


def test_sarif_reachable_is_an_error_needs_review_is_a_warning() -> None:
    """Severity in SARIF drives whether GitHub blocks a PR."""
    doc = json.loads(
        render_sarif(
            _state(
                _finding("a", "GHSA-1", Verdict.REACHABLE, evidence=(FACT,)),
                _finding("b", "GHSA-2", Verdict.NEEDS_REVIEW),
            )
        )
    )
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["GHSA-1"] == "error"
    assert levels["GHSA-2"] == "warning"


def test_sarif_omits_not_reachable_findings() -> None:
    """Emitting these would reintroduce the alert fatigue we removed."""
    doc = json.loads(
        render_sarif(_state(_finding("safe", "GHSA-9", Verdict.NOT_REACHABLE)))
    )
    assert doc["runs"][0]["results"] == []


def test_sarif_reachable_result_points_at_the_call_site() -> None:
    doc = json.loads(render_sarif(_state(_finding(evidence=(FACT,)))))
    location = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uri"] == "app.py"
    assert location["region"]["startLine"] == 42


def test_sarif_evidenceless_result_anchors_to_the_manifest() -> None:
    """SARIF requires a location; the manifest is the honest fallback."""
    doc = json.loads(render_sarif(_state(_finding(verdict=Verdict.NEEDS_REVIEW))))
    location = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "requirements.txt"


def test_sarif_rules_are_deduplicated() -> None:
    doc = json.loads(
        render_sarif(
            _state(
                _finding("a", "GHSA-1", Verdict.REACHABLE, evidence=(FACT,)),
                _finding("b", "GHSA-1", Verdict.REACHABLE, evidence=(FACT,)),
            )
        )
    )
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_carries_security_severity() -> None:
    doc = json.loads(render_sarif(_state(_finding(evidence=(FACT,)))))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.0"
