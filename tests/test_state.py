import pytest
from pydantic import ValidationError

from deptrace.core.state import (
    Dependency,
    Evidence,
    Finding,
    RunState,
    Verdict,
    Vulnerability,
)


def test_evidence_provenance_is_locked() -> None:
    """The trust boundary: Evidence cannot claim another producer."""
    with pytest.raises(ValidationError):
        Evidence(
            produced_by="llm",  # type: ignore[arg-type]
            file="a.py", line=1, symbol="yaml.load", kind="call",
        )


def test_facts_are_immutable() -> None:
    ev = Evidence(file="a.py", line=1, symbol="yaml.load", kind="call")
    with pytest.raises(ValidationError):
        ev.file = "b.py"  # type: ignore[misc]


def test_finding_defaults_to_needs_review() -> None:
    f = Finding(
        dependency=Dependency(name="pyyaml", source="requirements.txt"),
        vulnerability=Vulnerability(id="GHSA-test"),
    )
    assert f.verdict is Verdict.NEEDS_REVIEW
    assert not f.is_actionable


def test_noise_reduction_math() -> None:
    state = RunState(target=".")
    state.metrics.total_vulnerabilities = 10
    state.metrics.not_reachable = 7
    assert state.metrics.noise_reduction == 0.7


def test_run_state_roundtrips() -> None:
    """Serializability is what makes the core queue-ready."""
    state = RunState(target="./repo")
    assert RunState.model_validate_json(state.model_dump_json()).target == "./repo"