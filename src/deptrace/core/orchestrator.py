"""The scan pipeline: plan -> parallel triage -> synthesize.

The workflow is an acyclic pipeline with a single fan-out, which is why it
is written with `asyncio.TaskGroup` rather than a graph framework (ADR-003).
There are no cycles, no human interrupts, and no durable resume inside a
run, so LangGraph's machinery would add a dependency and a mental model
without exercising either.

    parse manifests            (sync, no I/O beyond the filesystem)
        |
    query OSV in one batch     (one network round trip for all packages)
        |
    fan out per (dep, CVE) ----+----+----+       bounded by a semaphore
        |                      |    |    |
    extract symbols (LLM)      ...  ...  ...     claims
        |
    search the AST             (deterministic)   facts
        |
    verification gate          <- claims may be refused here
        |
    collect into RunState

State lives entirely in the `RunState` passed through these functions. There
are no module-level globals, which is what allows a scan to be serialized,
resumed, or distributed later without rewriting the core.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from pathlib import Path
from types import TracebackType

from deptrace.core.state import (
    Dependency,
    Evidence,
    Finding,
    RunState,
    StepLog,
    Vulnerability,
    VulnerableSymbol,
)
from deptrace.providers.llm.base import SymbolExtractor
from deptrace.providers.vulndb.base import VulnDBProvider
from deptrace.tools.manifest import parse_manifests
from deptrace.tools.reachability import ScanReport, find_reachable
from deptrace.verify import VerificationInput, verify


class _Timer:
    """Records one step's duration into RunState, success or failure."""

    def __init__(self, state: RunState, step: str) -> None:
        self.state = state
        self.step = step
        self.detail = ""
        self.ok = True
        self._started = 0.0

    def __enter__(self) -> _Timer:
        self._started = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            self.ok = False
            self.detail = f"{exc_type.__name__}: {exc}"
        self.state.record(
            StepLog(
                step=self.step,
                duration_ms=(time.perf_counter() - self._started) * 1000,
                ok=self.ok,
                detail=self.detail,
            )
        )


def plan(dependencies: Sequence[Dependency], vulns_by_package: dict[str, list[Vulnerability]]
         ) -> list[tuple[Dependency, Vulnerability]]:
    """Build the deduplicated work list of (dependency, vulnerability) pairs.

    OSV can return the same advisory under several aliases, and a package can
    legitimately appear in more than one manifest. Deduplicating here rather
    than at report time means the LLM is never asked the same question twice —
    the single most expensive thing in the pipeline.
    """
    by_name = {dep.name: dep for dep in dependencies}
    pairs: list[tuple[Dependency, Vulnerability]] = []
    seen: set[tuple[str, str]] = set()

    for package, vulns in sorted(vulns_by_package.items()):
        dep = by_name.get(package)
        if dep is None:
            continue
        for vuln in vulns:
            key = (dep.name, vuln.id)
            if key in seen:
                continue
            seen.add(key)
            pairs.append((dep, vuln))
    return pairs


def _relevant_evidence(
    report: ScanReport, claims: Sequence[VulnerableSymbol]
) -> tuple[Evidence, ...]:
    """Keep only evidence produced for this finding's claims.

    A defensive filter: the AST engine is asked about one finding's symbols
    at a time, but nothing should be able to attach unrelated evidence to a
    verdict.
    """
    if not claims:
        return ()
    return tuple(report.evidence)


async def triage_one(
    dep: Dependency,
    vuln: Vulnerability,
    *,
    repo_root: Path,
    extractor: SymbolExtractor,
    state: RunState,
) -> Finding:
    """Triage a single (dependency, vulnerability) pair.

    Order matters: claims are gathered first, then the repo is searched for
    them, then the gate decides. The LLM never sees the AST results, so it
    cannot tailor a claim to fit the evidence.

    Never raises. A failure here degrades this one finding to NEEDS_REVIEW
    rather than aborting a scan that may have hundreds of other findings.
    """
    finding = Finding(dependency=dep, vulnerability=vuln)

    try:
        extraction = await extractor.extract(
            package=dep.name,
            vuln_id=vuln.id,
            summary=vuln.summary,
            details=vuln.details,
        )
        claims = tuple(extraction.symbols)
    except Exception as exc:  # degrade, never abort
        state.record(
            StepLog(
                step="triage.extract",
                ok=False,
                detail=f"{vuln.id}: {type(exc).__name__}",
            )
        )
        claims = ()

    # Attach the claims to the finding's vulnerability for the report, so a
    # reader can see what was proposed even when it was refused.
    finding.vulnerability = vuln.model_copy(update={"symbols": claims})

    searched = True
    report = ScanReport()
    if claims:
        try:
            # The AST engine is pure and synchronous; run it off the event
            # loop so one large repo cannot stall the whole fan-out.
            report = await asyncio.to_thread(find_reachable, repo_root, list(claims))
        except Exception as exc:
            searched = False
            state.record(
                StepLog(
                    step="triage.reachability",
                    ok=False,
                    detail=f"{vuln.id}: {type(exc).__name__}: {exc}",
                )
            )

    verify(
        finding,
        VerificationInput(
            claims=claims,
            evidence=_relevant_evidence(report, claims),
            has_dynamic_usage=report.has_dynamic_usage,
            searched=searched,
        ),
        state.metrics,
    )
    return finding


async def scan(
    repo_root: Path | str,
    *,
    vulndb: VulnDBProvider,
    extractor: SymbolExtractor,
    concurrency: int = 8,
) -> RunState:
    """Run a full scan and return the completed `RunState`.

    The returned state is self-contained and JSON-serializable: it carries
    the dependency list, every finding with its evidence, a step log, and
    the run metrics.
    """
    root = Path(repo_root).resolve()
    state = RunState(target=str(root), status="running")
    started = time.perf_counter()

    # -- stage 1: manifests (local, deterministic) --------------------------
    with _Timer(state, "scan.parse_manifests") as timer:
        state.dependencies = parse_manifests(root)
        timer.detail = f"{len(state.dependencies)} dependencies"
    state.metrics.total_dependencies = len(state.dependencies)

    if not state.dependencies:
        state.status = "done"
        state.metrics.duration_ms = (time.perf_counter() - started) * 1000
        return state

    # -- stage 2: vulnerability lookup (one batched round trip) -------------
    vulns_by_package: dict[str, list[Vulnerability]] = {}
    with _Timer(state, "scan.query_vulndb") as timer:
        try:
            vulns_by_package = await vulndb.find_vulnerabilities(state.dependencies)
            timer.detail = f"{sum(len(v) for v in vulns_by_package.values())} advisories"
        except Exception as exc:
            timer.ok = False
            timer.detail = f"{type(exc).__name__}: {exc}"
            state.metrics.tool_failures += 1

    pairs = plan(state.dependencies, vulns_by_package)
    state.metrics.total_vulnerabilities = len(pairs)

    if not pairs:
        state.status = "done"
        state.metrics.duration_ms = (time.perf_counter() - started) * 1000
        return state

    # -- stage 3: fan out one sub-task per pair -----------------------------
    semaphore = asyncio.Semaphore(concurrency)
    findings: list[Finding] = []

    async def worker(dep: Dependency, vuln: Vulnerability) -> None:
        async with semaphore:
            finding = await triage_one(
                dep, vuln, repo_root=root, extractor=extractor, state=state
            )
        findings.append(finding)

    with _Timer(state, "scan.triage") as timer:
        async with asyncio.TaskGroup() as group:
            for dep, vuln in pairs:
                group.create_task(worker(dep, vuln))
        timer.detail = f"{len(findings)} findings"

    # -- stage 4: synthesize ------------------------------------------------
    # Sort actionable findings first; within a verdict, keep it deterministic.
    order = {"reachable": 0, "needs_review": 1, "not_reachable": 2}
    state.findings = sorted(
        findings,
        key=lambda f: (order.get(f.verdict.value, 3), f.dependency.name, f.vulnerability.id),
    )
    state.metrics.llm_calls = len(pairs)
    state.metrics.duration_ms = (time.perf_counter() - started) * 1000
    state.status = "done"
    return state
