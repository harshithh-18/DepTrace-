"""Tests for the verification gate.

This file guards the property the whole project rests on: **an LLM claim can
never, by itself, produce a REACHABLE verdict.** If these tests pass, a
hallucinating model degrades the report's precision but cannot fabricate a
security finding out of nothing.
"""

from __future__ import annotations

import pytest

from deptrace.core.state import (
    Dependency,
    Evidence,
    Finding,
    RunMetrics,
    Verdict,
    Vulnerability,
    VulnerableSymbol,
)
from deptrace.verify import (
    VerificationInput,
    assert_evidence_integrity,
    decide_verdict,
    verify,
)

CLAIM = VulnerableSymbol(module="yaml", name="load", confidence=0.95)
FACT = Evidence(file="app.py", line=42, symbol="yaml.load", kind="call")


def _finding() -> Finding:
    return Finding(
        dependency=Dependency(name="pyyaml", version="5.3", source="requirements.txt"),
        vulnerability=Vulnerability(id="GHSA-6757-jp84-gxfx"),
    )


def _verify(**kwargs: object) -> tuple[Finding, RunMetrics]:
    data = VerificationInput(**kwargs)  # type: ignore[arg-type]
    metrics = RunMetrics()
    return verify(_finding(), data, metrics), metrics


# -- THE headline test -----------------------------------------------------


def test_fabricated_claim_without_evidence_is_blocked() -> None:
    """A confident LLM claim with zero AST evidence must NOT be REACHABLE.

    This is the hallucination gate. The model asserts `yaml.load` is used at
    0.95 confidence; static analysis found no such call; the verdict is
    refused and counted.
    """
    finding, metrics = _verify(claims=(CLAIM,), evidence=())

    assert finding.verdict is not Verdict.REACHABLE
    assert finding.verdict is Verdict.NOT_REACHABLE
    assert metrics.hallucination_blocked == 0  # searched and genuinely absent


def test_unsupported_claim_under_dynamic_code_is_downgraded_and_counted() -> None:
    """Claims + dynamic code + no evidence => refused, and counted as blocked."""
    finding, metrics = _verify(claims=(CLAIM,), evidence=(), has_dynamic_usage=True)

    assert finding.verdict is Verdict.NEEDS_REVIEW
    assert finding.downgraded is True
    assert metrics.hallucination_blocked == 1


def test_no_verdict_is_reachable_without_evidence() -> None:
    """Exhaustive: no combination of inputs yields REACHABLE without evidence."""
    for claims in ((), (CLAIM,)):
        for dynamic in (False, True):
            for searched in (False, True):
                verdict, _ = decide_verdict(
                    VerificationInput(
                        claims=claims,
                        evidence=(),
                        has_dynamic_usage=dynamic,
                        searched=searched,
                    )
                )
                assert verdict is not Verdict.REACHABLE


def test_evidence_is_required_for_reachable_invariant() -> None:
    finding = _finding()
    finding.verdict = Verdict.REACHABLE  # forced, bypassing the gate
    with pytest.raises(AssertionError):
        assert_evidence_integrity(finding)


# -- the positive path -----------------------------------------------------


def test_claim_with_evidence_is_reachable() -> None:
    finding, metrics = _verify(claims=(CLAIM,), evidence=(FACT,))

    assert finding.verdict is Verdict.REACHABLE
    assert finding.downgraded is False
    assert metrics.reachable == 1
    assert metrics.hallucination_blocked == 0
    assert_evidence_integrity(finding)


def test_reachable_rationale_names_the_call_site() -> None:
    """A verdict a human cannot check is worthless."""
    finding, _ = _verify(claims=(CLAIM,), evidence=(FACT,))
    assert "app.py:42" in finding.rationale
    assert "yaml.load" in finding.rationale


def test_evidence_outweighs_dynamic_usage() -> None:
    """A proven call site is proof regardless of other dynamic code nearby."""
    finding, _ = _verify(claims=(CLAIM,), evidence=(FACT,), has_dynamic_usage=True)
    assert finding.verdict is Verdict.REACHABLE


def test_multiple_evidence_is_summarized() -> None:
    second = Evidence(file="b.py", line=7, symbol="yaml.load", kind="call")
    finding, _ = _verify(claims=(CLAIM,), evidence=(FACT, second))
    assert "+1 more" in finding.rationale


# -- fail-safe: uncertainty resolves toward review -------------------------


def test_no_claims_means_needs_review_not_safe() -> None:
    """A vague advisory is unknown, not safe. This is the fail-safe rule."""
    finding, metrics = _verify(claims=(), evidence=())

    assert finding.verdict is Verdict.NEEDS_REVIEW
    assert metrics.needs_review == 1
    assert metrics.not_reachable == 0


def test_unsearched_finding_is_never_declared_safe() -> None:
    """If the AST scan could not run, we know nothing. Do not say 'safe'."""
    finding, _ = _verify(claims=(CLAIM,), evidence=(), searched=False)
    assert finding.verdict is Verdict.NEEDS_REVIEW


def test_finding_defaults_to_needs_review_before_verification() -> None:
    """Uncertain until proven otherwise."""
    assert _finding().verdict is Verdict.NEEDS_REVIEW


def test_not_reachable_requires_having_known_what_to_search_for() -> None:
    """NOT_REACHABLE is only reachable when claims existed and were searched."""
    verdict, _ = decide_verdict(VerificationInput(claims=(CLAIM,), evidence=()))
    assert verdict is Verdict.NOT_REACHABLE

    verdict, _ = decide_verdict(VerificationInput(claims=(), evidence=()))
    assert verdict is Verdict.NEEDS_REVIEW


# -- rationale quality -----------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected_phrase"),
    [
        ({"claims": (), "evidence": ()}, "does not identify a specific"),
        (
            {"claims": (CLAIM,), "evidence": (), "has_dynamic_usage": True},
            "Dynamic imports",
        ),
        ({"claims": (CLAIM,), "evidence": (), "searched": False}, "did not run"),
        ({"claims": (CLAIM,), "evidence": ()}, "No call site found"),
    ],
)
def test_rationale_explains_the_specific_cause(
    kwargs: dict[str, object], expected_phrase: str
) -> None:
    finding, _ = _verify(**kwargs)
    assert expected_phrase in finding.rationale


# -- metrics ---------------------------------------------------------------


def test_metrics_track_each_verdict_once() -> None:
    metrics = RunMetrics()
    verify(_finding(), VerificationInput(claims=(CLAIM,), evidence=(FACT,)), metrics)
    verify(_finding(), VerificationInput(claims=(CLAIM,), evidence=()), metrics)
    verify(_finding(), VerificationInput(claims=(), evidence=()), metrics)

    assert (metrics.reachable, metrics.not_reachable, metrics.needs_review) == (1, 1, 1)


def test_noise_reduction_reflects_filtered_alerts() -> None:
    metrics = RunMetrics(total_vulnerabilities=4, not_reachable=3)
    assert metrics.noise_reduction == 0.75


def test_evidence_is_attached_to_the_finding() -> None:
    finding, _ = _verify(claims=(CLAIM,), evidence=(FACT,))
    assert finding.evidence == (FACT,)
    assert finding.evidence[0].produced_by == "ast_engine"
