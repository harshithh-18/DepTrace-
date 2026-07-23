"""Tests for the evaluation harness.

A broken harness is worse than none: it reports 1.00 while measuring
nothing. These tests check the metric arithmetic against hand-computed
values and confirm the dataset stays consistent with the fixtures on disk.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

EVALS = Path(__file__).resolve().parent.parent / "evals"
sys.path.insert(0, str(EVALS))

from run_eval import (  # noqa: E402
    FIXTURES,
    Case,
    Metrics,
    Outcome,
    load_dataset,
    markdown_table,
    run_case,
)

from deptrace.core.state import Verdict  # noqa: E402


def _case(expected: Verdict, case_id: str = "c", location: str | None = None) -> Case:
    return Case(
        id=case_id,
        fixture="direct_call",
        package="pyyaml",
        version="5.3",
        cve="GHSA-1",
        symbols=(),
        expected_verdict=expected,
        expected_location=location,
    )


def _outcome(expected: Verdict, actual: Verdict, **kw: object) -> Outcome:
    return Outcome(
        case=_case(expected, **kw),  # type: ignore[arg-type]
        actual_verdict=actual,
        actual_location=None,
        latency_ms=1.0,
    )


# -- metric arithmetic -----------------------------------------------------


def test_perfect_run_scores_one() -> None:
    metrics = Metrics(
        outcomes=[
            _outcome(Verdict.REACHABLE, Verdict.REACHABLE),
            _outcome(Verdict.NOT_REACHABLE, Verdict.NOT_REACHABLE),
        ]
    )
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0


def test_false_positive_lowers_precision_only() -> None:
    """Two predicted reachable, one correct => precision 0.5, recall 1.0."""
    metrics = Metrics(
        outcomes=[
            _outcome(Verdict.REACHABLE, Verdict.REACHABLE),
            _outcome(Verdict.NOT_REACHABLE, Verdict.REACHABLE),
        ]
    )
    assert metrics.false_positives == 1
    assert metrics.precision == 0.5
    assert metrics.recall == 1.0


def test_false_negative_lowers_recall_only() -> None:
    """The critical failure: a reachable CVE reported as safe."""
    metrics = Metrics(
        outcomes=[
            _outcome(Verdict.REACHABLE, Verdict.REACHABLE),
            _outcome(Verdict.REACHABLE, Verdict.NOT_REACHABLE),
        ]
    )
    assert metrics.false_negatives == 1
    assert metrics.recall == 0.5
    assert metrics.precision == 1.0


def test_needs_review_on_a_reachable_case_is_a_false_negative() -> None:
    """Routing a genuinely reachable CVE to review still misses it."""
    metrics = Metrics(outcomes=[_outcome(Verdict.REACHABLE, Verdict.NEEDS_REVIEW)])
    assert metrics.false_negatives == 1
    assert metrics.recall == 0.0


def test_f1_is_the_harmonic_mean() -> None:
    metrics = Metrics(
        outcomes=[
            _outcome(Verdict.REACHABLE, Verdict.REACHABLE),
            _outcome(Verdict.NOT_REACHABLE, Verdict.REACHABLE),
            _outcome(Verdict.REACHABLE, Verdict.NOT_REACHABLE),
        ]
    )
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1 == pytest.approx(0.5)


def test_three_state_accuracy_counts_exact_agreement() -> None:
    """A reachable case answered NEEDS_REVIEW is wrong, not partially right."""
    metrics = Metrics(
        outcomes=[
            _outcome(Verdict.REACHABLE, Verdict.REACHABLE),
            _outcome(Verdict.NEEDS_REVIEW, Verdict.NOT_REACHABLE),
        ]
    )
    assert metrics.accuracy == 0.5


def test_noise_reduction_counts_filtered_alerts() -> None:
    metrics = Metrics(
        outcomes=[
            _outcome(Verdict.NOT_REACHABLE, Verdict.NOT_REACHABLE),
            _outcome(Verdict.NOT_REACHABLE, Verdict.NOT_REACHABLE),
            _outcome(Verdict.REACHABLE, Verdict.REACHABLE),
            _outcome(Verdict.REACHABLE, Verdict.REACHABLE),
        ]
    )
    assert metrics.noise_reduction == 0.5


def test_empty_metrics_do_not_divide_by_zero() -> None:
    metrics = Metrics()
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.accuracy == 0.0


def test_location_accuracy_requires_the_right_line() -> None:
    """A REACHABLE verdict pointing at the wrong line is not a pass."""
    wrong = Outcome(
        case=_case(Verdict.REACHABLE, location="app.py:9"),
        actual_verdict=Verdict.REACHABLE,
        actual_location="app.py:99",
        latency_ms=1.0,
    )
    assert wrong.location_correct is False
    assert Metrics(outcomes=[wrong]).location_accuracy == 0.0


# -- dataset integrity -----------------------------------------------------


def test_dataset_loads() -> None:
    cases = load_dataset()
    assert len(cases) >= 12
    assert len({c.id for c in cases}) == len(cases)  # ids are unique


def test_every_fixture_referenced_exists() -> None:
    """A typo in the dataset must not silently skip a case."""
    for case in load_dataset():
        assert (FIXTURES / case.fixture).is_dir(), f"missing fixture: {case.fixture}"


def test_dataset_covers_all_three_verdicts() -> None:
    """A dataset without negatives measures nothing useful."""
    verdicts = {c.expected_verdict for c in load_dataset()}
    assert verdicts == {
        Verdict.REACHABLE,
        Verdict.NOT_REACHABLE,
        Verdict.NEEDS_REVIEW,
    }


def test_reachable_cases_declare_an_expected_location() -> None:
    """Ground truth for a reachable case must be checkable."""
    for case in load_dataset():
        if case.expected_verdict is Verdict.REACHABLE:
            assert case.expected_location, f"{case.id} lacks an expected location"


def test_dataset_includes_the_adversarial_cases() -> None:
    """The hallucination and prefix-decoy traps must stay in the set."""
    ids = {c.id for c in load_dataset()}
    assert "fx-hallucination" in ids
    assert "fx-prefix-decoy" in ids


# -- end to end ------------------------------------------------------------


async def test_every_labeled_case_passes() -> None:
    """The regression gate itself: the full dataset must be green."""
    failures: list[str] = []
    for case in load_dataset():
        outcome = await run_case(case)
        if not (outcome.correct and outcome.location_correct):
            failures.append(
                f"{case.id}: expected {case.expected_verdict.value} "
                f"at {case.expected_location}, got "
                f"{outcome.actual_verdict.value} at {outcome.actual_location}"
            )
    assert not failures, "\n".join(failures)


async def test_no_false_negatives_on_the_dataset() -> None:
    """The failure that matters most, asserted on its own."""
    metrics = Metrics()
    for case in load_dataset():
        metrics.outcomes.append(await run_case(case))
    assert metrics.false_negatives == 0


async def test_hallucinated_claim_is_refused_in_the_eval() -> None:
    """The adversarial row, end to end through the real pipeline."""
    case = next(c for c in load_dataset() if c.id == "fx-hallucination")
    outcome = await run_case(case)
    assert outcome.actual_verdict is not Verdict.REACHABLE


def test_markdown_table_reports_measured_values() -> None:
    metrics = Metrics(outcomes=[_outcome(Verdict.REACHABLE, Verdict.REACHABLE)])
    table = markdown_table(metrics)
    assert "| Precision (reachable) | 1.00 |" in table
    assert "| False negatives | 0 |" in table
