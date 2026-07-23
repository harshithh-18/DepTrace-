"""Core domain models for DepTrace.

These types are the contract between every layer. Nothing here imports
from providers/ or tools/ — the domain must stay independent of I/O.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def _now() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return uuid4().hex[:12]


class Verdict(StrEnum):
    """Triage outcome for one (dependency, vulnerability) pair."""

    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    NEEDS_REVIEW = "needs_review"


class Dependency(BaseModel):
    """A package the target project depends on."""

    model_config = ConfigDict(frozen=True)

    name: str                          # normalized, e.g. "pyyaml"
    version: str | None = None         # resolved version if pinned
    specifier: str | None = None       # raw constraint, e.g. ">=5.1,<6"
    import_names: tuple[str, ...] = () # e.g. ("yaml",) — NOT always the name
    source: str                        # which manifest declared it
    is_direct: bool = True             # direct vs transitive


class VulnerableSymbol(BaseModel):
    """An LLM-extracted CLAIM about what code an advisory implicates.

    This is unverified by construction. It tells the AST engine what to
    look for; it never on its own justifies a REACHABLE verdict.
    """

    model_config = ConfigDict(frozen=True)

    module: str                        # "yaml"
    name: str | None = None            # "load"  (None => whole module)
    kind: Literal["function", "method", "class", "module"] = "function"
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class Vulnerability(BaseModel):
    """A known vulnerability affecting a dependency (from OSV/GHSA)."""

    model_config = ConfigDict(frozen=True)

    id: str                            # "GHSA-xxxx" or "CVE-2024-xxxx"
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    severity: str | None = None
    fixed_version: str | None = None
    references: tuple[str, ...] = ()
    symbols: tuple[VulnerableSymbol, ...] = ()   # claims, filled in later


class Evidence(BaseModel):
    """A FACT produced by static analysis. The trust boundary.

    `produced_by` is pinned to a single literal value so that no other
    component — including the LLM layer — can construct Evidence.
    """

    model_config = ConfigDict(frozen=True)

    produced_by: Literal["ast_engine"] = "ast_engine"
    file: str                          # repo-relative path
    line: int = Field(ge=1)
    column: int = Field(ge=0, default=0)
    symbol: str                        # resolved dotted name, "yaml.load"
    kind: Literal["import", "call", "attribute"]
    snippet: str = ""                  # the source line, for the report


class Finding(BaseModel):
    """One triaged (dependency, vulnerability) pair — the unit of output."""

    dependency: Dependency
    vulnerability: Vulnerability
    verdict: Verdict = Verdict.NEEDS_REVIEW
    evidence: tuple[Evidence, ...] = ()
    rationale: str = ""                # human-readable explanation
    remediation: str | None = None     # e.g. "upgrade to >=5.4"
    downgraded: bool = False           # True if verify.py rejected a claim

    @property
    def is_actionable(self) -> bool:
        return self.verdict is Verdict.REACHABLE


class StepLog(BaseModel):
    """One recorded step of a scan. Feeds tracing AND the eval harness."""

    model_config = ConfigDict(frozen=True)

    step: str
    started_at: datetime = Field(default_factory=_now)
    duration_ms: float = 0.0
    ok: bool = True
    detail: str = ""
    tokens_in: int = 0
    tokens_out: int = 0


class RunMetrics(BaseModel):
    """Operational counters, reported per scan."""

    total_dependencies: int = 0
    total_vulnerabilities: int = 0
    reachable: int = 0
    not_reachable: int = 0
    needs_review: int = 0
    hallucination_blocked: int = 0     # LLM claims rejected by verify.py
    llm_calls: int = 0
    tool_calls: int = 0
    tool_failures: int = 0
    duration_ms: float = 0.0

    @property
    def noise_reduction(self) -> float:
        """Fraction of raw alerts shown to be not reachable."""
        if self.total_vulnerabilities == 0:
            return 0.0
        return self.not_reachable / self.total_vulnerabilities


class RunState(BaseModel):
    """Everything about one scan. Serializable, passed explicitly.

    No module-level globals anywhere in DepTrace: the full state of a run
    lives here, which is what makes the core stateless and horizontally
    scalable later without a rewrite.
    """

    scan_id: str = Field(default_factory=_new_id)
    target: str                        # repo path or URL
    status: Literal["pending", "running", "done", "failed"] = "pending"
    created_at: datetime = Field(default_factory=_now)

    dependencies: list[Dependency] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    steps: list[StepLog] = Field(default_factory=list)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    error: str | None = None

    def record(self, step: StepLog) -> None:
        self.steps.append(step)