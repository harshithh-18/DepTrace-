"""The evaluation harness — objective numbers for DepTrace.

    uv run python evals/run_eval.py
    uv run python evals/run_eval.py --markdown   # table for the README

This is what separates DepTrace from a wrapper: every claim in the README is
produced here, from a labeled dataset, and re-derivable by anyone who clones
the repo.

**Why this runs offline by design.** Each row supplies its own `symbols`
list, standing in for what the LLM would extract. That is deliberate, not a
shortcut: it isolates the component under test. The AST engine and the
verification gate are the parts that must be *correct*; symbol extraction is
the part that must be *good*, and conflating the two would mean a model's bad
day silently looked like a reachability regression. It also makes the suite
deterministic, keyless, and fast enough to gate CI.

The trade-off is recorded honestly: these numbers measure the deterministic
core given correct claims. They do not measure end-to-end extraction quality,
which is bounded by the model and is reported separately.

**False negatives are the critical failure.** A missed reachable CVE looks
exactly like a clean scan, so `--fail-under-recall` defaults to 1.0: any
missed reachable finding fails the run.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from deptrace.core.orchestrator import scan
from deptrace.core.state import (
    Dependency,
    Verdict,
    Vulnerability,
    VulnerableSymbol,
)
from deptrace.providers.llm.base import SymbolExtraction

EVALS_DIR = Path(__file__).resolve().parent
DATASET = EVALS_DIR / "dataset.jsonl"
FIXTURES = EVALS_DIR / "fixtures"


@dataclass(frozen=True)
class Case:
    """One labeled row: a fixture, a CVE, and the verdict a human confirmed."""

    id: str
    fixture: str
    package: str
    version: str
    cve: str
    symbols: tuple[VulnerableSymbol, ...]
    expected_verdict: Verdict
    expected_location: str | None
    notes: str = ""


@dataclass
class Outcome:
    """What DepTrace actually produced for one case."""

    case: Case
    actual_verdict: Verdict
    actual_location: str | None
    latency_ms: float
    blocked: int = 0

    @property
    def correct(self) -> bool:
        return self.actual_verdict is self.case.expected_verdict

    @property
    def location_correct(self) -> bool:
        """A REACHABLE verdict is only useful if it points at the right line."""
        if self.case.expected_location is None:
            return True
        return self.actual_location == self.case.expected_location


@dataclass
class Metrics:
    """Aggregate results over the dataset."""

    outcomes: list[Outcome] = field(default_factory=list)

    # -- confusion matrix on the REACHABLE class -------------------------

    @property
    def true_positives(self) -> int:
        return sum(
            1
            for o in self.outcomes
            if o.case.expected_verdict is Verdict.REACHABLE
            and o.actual_verdict is Verdict.REACHABLE
        )

    @property
    def false_positives(self) -> int:
        return sum(
            1
            for o in self.outcomes
            if o.case.expected_verdict is not Verdict.REACHABLE
            and o.actual_verdict is Verdict.REACHABLE
        )

    @property
    def false_negatives(self) -> int:
        """The critical failure: a reachable CVE reported as anything else."""
        return sum(
            1
            for o in self.outcomes
            if o.case.expected_verdict is Verdict.REACHABLE
            and o.actual_verdict is not Verdict.REACHABLE
        )

    @property
    def true_negatives(self) -> int:
        return sum(
            1
            for o in self.outcomes
            if o.case.expected_verdict is not Verdict.REACHABLE
            and o.actual_verdict is not Verdict.REACHABLE
        )

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def f1(self) -> float:
        total = self.precision + self.recall
        return 2 * self.precision * self.recall / total if total else 0.0

    @property
    def accuracy(self) -> float:
        """Exact three-state agreement, not just the REACHABLE class."""
        if not self.outcomes:
            return 0.0
        return sum(1 for o in self.outcomes if o.correct) / len(self.outcomes)

    @property
    def noise_reduction(self) -> float:
        """Share of advisories DepTrace proved were not reachable."""
        if not self.outcomes:
            return 0.0
        filtered = sum(
            1 for o in self.outcomes if o.actual_verdict is Verdict.NOT_REACHABLE
        )
        return filtered / len(self.outcomes)

    @property
    def hallucination_blocked(self) -> int:
        return sum(o.blocked for o in self.outcomes)

    @property
    def location_accuracy(self) -> float:
        checkable = [o for o in self.outcomes if o.case.expected_location is not None]
        if not checkable:
            return 1.0
        return sum(1 for o in checkable if o.location_correct) / len(checkable)

    @property
    def latencies(self) -> list[float]:
        return sorted(o.latency_ms for o in self.outcomes)

    def percentile(self, p: float) -> float:
        values = self.latencies
        if not values:
            return 0.0
        index = min(int(len(values) * p), len(values) - 1)
        return values[index]


class ScriptedExtractor:
    """Replays the dataset's labeled symbols instead of calling a model.

    Isolates the deterministic core: given the claims a competent extractor
    would produce, does the AST engine plus the gate reach the right verdict?
    """

    name = "scripted"

    def __init__(self, symbols: tuple[VulnerableSymbol, ...]) -> None:
        self._symbols = symbols

    async def extract(
        self, *, package: str, vuln_id: str, summary: str, details: str
    ) -> SymbolExtraction:
        return SymbolExtraction(symbols=list(self._symbols))


class ScriptedVulnDB:
    """Serves exactly the one advisory a case is about. No network."""

    name = "scripted"

    def __init__(self, case: Case) -> None:
        self._case = case

    async def find_vulnerabilities(
        self, dependencies: list[Dependency]
    ) -> dict[str, list[Vulnerability]]:
        vuln = Vulnerability(
            id=self._case.cve,
            summary=f"Advisory for {self._case.package}",
            details=self._case.notes,
            severity="HIGH",
        )
        return {self._case.package: [vuln]}


def load_dataset(path: Path = DATASET) -> list[Case]:
    """Read the labeled rows."""
    cases: list[Case] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        row = json.loads(line)
        cases.append(
            Case(
                id=row["id"],
                fixture=row["fixture"],
                package=row["package"],
                version=row["version"],
                cve=row["cve"],
                symbols=tuple(
                    VulnerableSymbol(
                        module=s["module"], name=s.get("name"), confidence=0.9
                    )
                    for s in row.get("symbols", [])
                ),
                expected_verdict=Verdict(row["expected_verdict"]),
                expected_location=row.get("expected_location"),
                notes=row.get("notes", ""),
            )
        )
    return cases


async def run_case(case: Case) -> Outcome:
    """Run one labeled case through the full pipeline."""
    started = time.perf_counter()
    state = await scan(
        FIXTURES / case.fixture,
        vulndb=ScriptedVulnDB(case),
        extractor=ScriptedExtractor(case.symbols),
        concurrency=4,
    )
    latency = (time.perf_counter() - started) * 1000

    matching = [f for f in state.findings if f.vulnerability.id == case.cve]
    if not matching:
        # No finding at all means the advisory never reached triage; that is
        # a miss, recorded as NOT_REACHABLE so it counts against recall.
        return Outcome(case, Verdict.NOT_REACHABLE, None, latency)

    finding = matching[0]
    location = (
        f"{finding.evidence[0].file}:{finding.evidence[0].line}"
        if finding.evidence
        else None
    )
    return Outcome(
        case,
        finding.verdict,
        location,
        latency,
        blocked=state.metrics.hallucination_blocked,
    )


async def run_all(cases: list[Case]) -> Metrics:
    metrics = Metrics()
    for case in cases:  # sequential: fixtures are tiny and order aids debugging
        metrics.outcomes.append(await run_case(case))
    return metrics


# -- reporting -------------------------------------------------------------


def print_report(metrics: Metrics) -> None:
    """Human-readable results, failures first."""
    print("\n" + "=" * 72)
    print("DepTrace evaluation")
    print("=" * 72)

    print(f"\n{'CASE':<28} {'EXPECTED':<14} {'ACTUAL':<14} {'':<3} LOCATION")
    print("-" * 72)
    for outcome in metrics.outcomes:
        mark = "ok " if outcome.correct and outcome.location_correct else "FAIL"
        print(
            f"{outcome.case.id:<28} "
            f"{outcome.case.expected_verdict.value:<14} "
            f"{outcome.actual_verdict.value:<14} "
            f"{mark:<3} "
            f"{outcome.actual_location or '—'}"
        )

    print("\n" + "-" * 72)
    print("Confusion matrix (REACHABLE class)")
    print("-" * 72)
    print(f"  True positives   {metrics.true_positives:>3}")
    print(f"  False positives  {metrics.false_positives:>3}   (false alarms)")
    print(f"  False negatives  {metrics.false_negatives:>3}   <- CRITICAL: missed CVEs")
    print(f"  True negatives   {metrics.true_negatives:>3}")

    print("\n" + "-" * 72)
    print("Metrics")
    print("-" * 72)
    print(f"  Precision            {metrics.precision:.3f}")
    print(f"  Recall               {metrics.recall:.3f}")
    print(f"  F1                   {metrics.f1:.3f}")
    print(f"  Three-state accuracy {metrics.accuracy:.3f}")
    print(f"  Location accuracy    {metrics.location_accuracy:.3f}")
    print(f"  Noise reduction      {metrics.noise_reduction:.1%}")
    print(f"  Claims blocked       {metrics.hallucination_blocked}")
    print(f"  Latency p50          {metrics.percentile(0.5):.0f} ms")
    print(f"  Latency p95          {metrics.percentile(0.95):.0f} ms")
    print(f"  Cases                {len(metrics.outcomes)}")

    failures = [o for o in metrics.outcomes if not (o.correct and o.location_correct)]
    if failures:
        print("\n" + "-" * 72)
        print(f"FAILURES ({len(failures)})")
        print("-" * 72)
        for outcome in failures:
            print(f"  {outcome.case.id}: {outcome.case.notes}")
            print(
                f"    expected {outcome.case.expected_verdict.value} "
                f"at {outcome.case.expected_location or '—'}, "
                f"got {outcome.actual_verdict.value} "
                f"at {outcome.actual_location or '—'}"
            )
    print()


def markdown_table(metrics: Metrics) -> str:
    """The block that goes in the README. Real measured values only."""
    mean_latency = (
        statistics.mean(o.latency_ms for o in metrics.outcomes)
        if metrics.outcomes
        else 0.0
    )
    return "\n".join(
        [
            "| Metric | Value |",
            "| --- | --- |",
            f"| Precision (reachable) | {metrics.precision:.2f} |",
            f"| Recall (reachable) | {metrics.recall:.2f} |",
            f"| F1 | {metrics.f1:.2f} |",
            f"| Three-state accuracy | {metrics.accuracy:.2f} |",
            f"| Location accuracy | {metrics.location_accuracy:.2f} |",
            f"| Noise reduction | {metrics.noise_reduction:.0%} |",
            f"| False negatives | {metrics.false_negatives} |",
            f"| Unsupported claims blocked | {metrics.hallucination_blocked} |",
            f"| Mean latency per case | {mean_latency:.0f} ms |",
            f"| Labeled cases | {len(metrics.outcomes)} |",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the DepTrace eval suite.")
    parser.add_argument("--markdown", action="store_true", help="Emit a README table.")
    parser.add_argument(
        "--fail-under-recall",
        type=float,
        default=1.0,
        help="Fail if recall drops below this (default 1.0: no missed CVEs).",
    )
    parser.add_argument(
        "--fail-under-precision",
        type=float,
        default=1.0,
        help="Fail if precision drops below this.",
    )
    args = parser.parse_args()

    cases = load_dataset()
    metrics = asyncio.run(run_all(cases))

    if args.markdown:
        print(markdown_table(metrics))
    else:
        print_report(metrics)

    if metrics.recall < args.fail_under_recall:
        print(
            f"REGRESSION: recall {metrics.recall:.3f} < {args.fail_under_recall}"
            f" ({metrics.false_negatives} reachable CVE(s) missed)",
            file=sys.stderr,
        )
        return 1
    if metrics.precision < args.fail_under_precision:
        print(
            f"REGRESSION: precision {metrics.precision:.3f} "
            f"< {args.fail_under_precision}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
