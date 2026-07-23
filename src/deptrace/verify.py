"""The verification gate — where LLM claims meet static-analysis facts.

This is the enforcement point for DepTrace's core principle:

    **The LLM proposes. Static analysis verifies.**

Everything upstream is advisory. The model may hallucinate a symbol that
does not exist, misread an advisory, or confidently name a function no one
calls. None of that can produce a REACHABLE verdict, because a verdict is
decided *here*, and here the only admissible proof is an `Evidence` object —
which by construction only the AST engine can mint.

The rules, in order of application:

  1. No `Evidence` => never REACHABLE. A claim without corroboration is
     downgraded to NEEDS_REVIEW and counted in `hallucination_blocked`.
  2. Dynamic usage in the scanned code => NEEDS_REVIEW, because static
     analysis genuinely cannot decide the question.
  3. No claims at all (a vague advisory) => NEEDS_REVIEW, not NOT_REACHABLE.
     "The advisory did not say" is not the same as "your code is safe."
  4. Claims exist, the code was searched, nothing was found => NOT_REACHABLE.

Rule 4 is the only path to a "safe" verdict, and it requires that we
actually knew what to look for. That asymmetry is deliberate: a false
negative (missing a reachable CVE) is the costly failure, so uncertainty
always resolves toward review rather than toward silence.
"""

from __future__ import annotations

from dataclasses import dataclass

from deptrace.core.state import Evidence, Finding, RunMetrics, Verdict, VulnerableSymbol


@dataclass(frozen=True)
class VerificationInput:
    """Everything the gate needs to decide one finding's verdict."""

    claims: tuple[VulnerableSymbol, ...]
    evidence: tuple[Evidence, ...]
    has_dynamic_usage: bool = False
    searched: bool = True  # False when the AST scan could not run


def _rationale(verdict: Verdict, data: VerificationInput) -> str:
    """A human-readable justification, always naming the deciding fact."""
    if verdict is Verdict.REACHABLE:
        first = data.evidence[0]
        extra = f" (+{len(data.evidence) - 1} more)" if len(data.evidence) > 1 else ""
        return (
            f"Call site found at {first.file}:{first.line} -> {first.symbol}{extra}. "
            f"Verified by static analysis."
        )

    if verdict is Verdict.NOT_REACHABLE:
        named = ", ".join(
            f"{c.module}.{c.name}" if c.name else c.module for c in data.claims[:3]
        )
        return (
            f"No call site found for {named}. "
            f"The package is installed but this code path is not used."
        )

    # NEEDS_REVIEW has several distinct causes; say which one applies.
    if not data.searched:
        return "Static analysis did not run for this finding; verdict withheld."
    if not data.claims:
        return (
            "The advisory does not identify a specific vulnerable symbol, "
            "so reachability cannot be determined statically."
        )
    if data.has_dynamic_usage:
        return (
            "Dynamic imports or reflection detected; static analysis cannot "
            "prove whether the vulnerable symbol is reached."
        )
    return "Unsupported claim: no static evidence corroborates it."


def decide_verdict(data: VerificationInput) -> tuple[Verdict, bool]:
    """Apply the gate. Returns (verdict, was_downgraded).

    `was_downgraded` is True only when evidence-free claims existed and were
    therefore refused — the signal counted as `hallucination_blocked`.
    """
    # Rule 1: evidence is the only thing that can justify REACHABLE.
    if data.evidence:
        return Verdict.REACHABLE, False

    # Beyond this point there is no evidence, so REACHABLE is unreachable.
    if not data.searched:
        return Verdict.NEEDS_REVIEW, False

    # Rule 3: nothing was claimed, so nothing could be searched for.
    if not data.claims:
        return Verdict.NEEDS_REVIEW, False

    # Rule 2: the code defeats static analysis; do not conclude either way.
    if data.has_dynamic_usage:
        return Verdict.NEEDS_REVIEW, True

    # Rule 4: we knew what to look for, we looked, and it is not there.
    return Verdict.NOT_REACHABLE, False


def verify(finding: Finding, data: VerificationInput, metrics: RunMetrics) -> Finding:
    """Assign a verified verdict to a finding and update run metrics.

    Mutates `finding` in place and returns it. `metrics.hallucination_blocked`
    is incremented whenever an unsupported claim is refused — a concrete,
    checkable safety property worth reporting in the README.
    """
    verdict, downgraded = decide_verdict(data)

    finding.verdict = verdict
    finding.evidence = data.evidence
    finding.downgraded = downgraded
    finding.rationale = _rationale(verdict, data)

    if downgraded:
        metrics.hallucination_blocked += 1

    if verdict is Verdict.REACHABLE:
        metrics.reachable += 1
    elif verdict is Verdict.NOT_REACHABLE:
        metrics.not_reachable += 1
    else:
        metrics.needs_review += 1

    return finding


def assert_evidence_integrity(finding: Finding) -> None:
    """Fail loudly if a REACHABLE finding ever lacks evidence.

    A belt-and-braces invariant check. `decide_verdict` already guarantees
    this, but the property is important enough that a future refactor should
    break a test rather than silently ship an unprovable verdict.
    """
    if finding.verdict is Verdict.REACHABLE and not finding.evidence:
        raise AssertionError(
            f"Invariant violated: {finding.vulnerability.id} is REACHABLE "
            "with no supporting evidence."
        )
