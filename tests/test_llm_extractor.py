"""Tests for the LLM symbol-extraction layer.

**Every test here runs offline with zero API calls.** Pydantic AI's
`TestModel`/`FunctionModel` stand in for a real model, so CI needs no keys,
no Ollama, and no egress. `test_no_real_model_is_constructed_in_tests`
guards that property explicitly.

The behaviour under test is mostly about restraint: the model produces
*claims*, and the valuable claim is often the empty one.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from deptrace.core.state import VulnerableSymbol
from deptrace.providers.llm.base import (
    LLMConfig,
    SymbolExtraction,
    SymbolExtractor,
    config_from_env,
)
from deptrace.providers.llm.extractor import (
    MAX_DETAIL_CHARS,
    LLMSymbolExtractor,
    _salvage_from_text,
    _sanitize,
    build_model,
)

PYYAML_DETAILS = (
    "In PyYAML before 5.3.1, the full_load method and the FullLoader loader "
    "allow arbitrary code execution when loading untrusted YAML. Use "
    "yaml.safe_load instead."
)


def _returning(symbols: list[dict[str, Any]], reasoning: str = "") -> FunctionModel:
    """A model that always answers with the given symbols."""

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        return ModelResponse(
            parts=[
                ToolCallPart(
                    "final_result", {"symbols": symbols, "reasoning": reasoning}
                )
            ]
        )

    return FunctionModel(respond)


def _extractor(model: Any) -> LLMSymbolExtractor:
    # retry_wait=0: the suite proves retries happen without paying backoff.
    return LLMSymbolExtractor(
        model=model, config=LLMConfig(provider="test", retry_wait=0.0)
    )


async def _extract(model: Any, **kw: Any) -> SymbolExtraction:
    defaults = {
        "package": "pyyaml",
        "vuln_id": "GHSA-6757-jp84-gxfx",
        "summary": "Improper Input Validation in PyYAML",
        "details": PYYAML_DETAILS,
    }
    return await _extractor(model).extract(**{**defaults, **kw})


# -- the offline guarantee -------------------------------------------------


def test_no_real_model_is_constructed_in_tests() -> None:
    """A stub model must be used verbatim, never replaced by a live client."""
    stub = TestModel()
    extractor = LLMSymbolExtractor(model=stub, config=LLMConfig(provider="test"))
    assert extractor._model is stub


async def test_extraction_runs_with_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even with no keys and no server reachable, extraction completes."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    result = await _extract(TestModel())
    assert isinstance(result, SymbolExtraction)


# -- extraction behaviour --------------------------------------------------


async def test_extracts_named_symbol() -> None:
    result = await _extract(
        _returning([{"module": "yaml", "name": "load", "confidence": 0.95}])
    )
    assert len(result.symbols) == 1

    symbol = result.symbols[0]
    assert symbol.module == "yaml"
    assert symbol.name == "load"
    assert symbol.confidence == 0.95


async def test_extracts_multiple_symbols() -> None:
    result = await _extract(
        _returning(
            [
                {"module": "yaml", "name": "load"},
                {"module": "yaml", "name": "full_load"},
            ]
        )
    )
    assert {s.name for s in result.symbols} == {"load", "full_load"}


async def test_module_only_claim_is_allowed() -> None:
    """Advisories that implicate a whole module are legitimate claims."""
    result = await _extract(_returning([{"module": "yaml", "name": None}]))
    assert result.symbols[0].name is None


async def test_vague_advisory_yields_empty_list() -> None:
    """The NEEDS_REVIEW path: no named symbol means no claim, not a guess."""
    result = await _extract(
        _returning([]),
        summary="A flaw was found in the way the library processes input",
        details="An attacker could cause a denial of service.",
    )
    assert result.symbols == []


async def test_default_model_output_is_empty_not_invented() -> None:
    """TestModel returns schema defaults; that must be an empty claim list."""
    assert (await _extract(TestModel())).symbols == []


async def test_claims_carry_confidence_facts_do_not() -> None:
    """Claims are uncertain by construction — that asymmetry is the design."""
    result = await _extract(_returning([{"module": "yaml", "name": "load"}]))
    assert hasattr(result.symbols[0], "confidence")
    assert 0.0 <= result.symbols[0].confidence <= 1.0


# -- resilience: extraction failure must never abort a scan ----------------


async def test_model_error_degrades_to_empty_extraction() -> None:
    def explode(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        raise RuntimeError("model is down")

    result = await _extract(FunctionModel(explode))
    assert result.symbols == []  # degraded, not raised


async def test_failed_extraction_is_logged_as_not_ok() -> None:
    def explode(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        raise RuntimeError("model is down")

    extractor = _extractor(FunctionModel(explode))
    await extractor.extract(package="p", vuln_id="GHSA-x", summary="s", details="d")

    assert extractor.steps[-1].ok is False
    assert "GHSA-x" in extractor.steps[-1].detail


async def test_transient_failure_is_retried_then_succeeds() -> None:
    """A flaky model gets another chance before the claim is abandoned."""
    attempts = {"n": 0}

    def flaky(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("transient 503")
        return ModelResponse(
            parts=[
                ToolCallPart(
                    "final_result", {"symbols": [{"module": "yaml", "name": "load"}]}
                )
            ]
        )

    result = await _extract(FunctionModel(flaky))
    assert attempts["n"] == 2  # proved a retry occurred
    assert result.symbols[0].name == "load"


async def test_retries_are_bounded() -> None:
    """A permanently dead model must not retry forever."""
    attempts = {"n": 0}

    def always_fails(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        attempts["n"] += 1
        raise RuntimeError("down")

    extractor = LLMSymbolExtractor(
        model=FunctionModel(always_fails),
        config=LLMConfig(provider="test", retry_wait=0.0, max_attempts=3),
    )
    result = await extractor.extract(
        package="p", vuln_id="GHSA-x", summary="s", details="d"
    )

    assert attempts["n"] == 3
    assert result.symbols == []


async def test_missing_advisory_text_is_handled() -> None:
    result = await _extract(_returning([]), summary="", details="")
    assert result.symbols == []


# -- observability ---------------------------------------------------------


async def test_step_log_records_tokens_and_latency() -> None:
    extractor = _extractor(_returning([{"module": "yaml", "name": "load"}]))
    await extractor.extract(
        package="pyyaml", vuln_id="GHSA-1", summary="s", details="d"
    )

    step = extractor.steps[-1]
    assert step.step == "llm.extract_symbols"
    assert step.ok is True
    assert step.duration_ms > 0
    assert step.tokens_in > 0
    assert step.tokens_out > 0


async def test_each_extraction_appends_one_step() -> None:
    extractor = _extractor(TestModel())
    for i in range(3):
        await extractor.extract(
            package="p", vuln_id=f"GHSA-{i}", summary="s", details="d"
        )
    assert len(extractor.steps) == 3


async def test_long_details_are_truncated() -> None:
    """Advisory details can be many KB; the prompt must stay bounded."""
    captured: list[str] = []

    def capture(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        captured.append(str(messages[-1]))
        return ModelResponse(parts=[ToolCallPart("final_result", {"symbols": []})])

    await _extract(FunctionModel(capture), details="x" * 50_000)
    assert len(captured[0]) < MAX_DETAIL_CHARS + 2000


# -- claim sanitization ----------------------------------------------------


# -- salvage: recovering claims from schema-violating output ---------------
#
# These shapes are not hypothetical. They were captured from a real
# qwen2.5-coder run against Ollama, which is DepTrace's keyless default:
# small local models routinely emit correct *content* in the wrong envelope.


def test_salvage_recovers_json_objects_from_markdown_fence() -> None:
    """The observed 7b failure: right content, bare array, wrapped in prose."""
    raw = (
        "[type=json_invalid, input_value='Here is the corrected JSON:\\n"
        '```json\\n[\\n  {"module": "yaml", "name": "load"},\\n'
        '  {"module": "yaml", "name": "FullLoader"}\\n]\\n```\']'
    )
    result = _salvage_from_text(raw)
    assert result is not None
    assert [(s.module, s.name) for s in result.symbols] == [
        ("yaml", "load"),
        ("yaml", "FullLoader"),
    ]


def test_salvage_recovers_bare_dotted_names() -> None:
    """The observed 1.5b failure: a plain list of strings."""
    raw = "[type=json_invalid, input_value='[\"yaml.load\"]']"
    result = _salvage_from_text(raw)
    assert result is not None
    assert (result.symbols[0].module, result.symbols[0].name) == ("yaml", "load")


def test_salvaged_claims_carry_reduced_confidence() -> None:
    """They came from a model that ignored instructions — weaker claims."""
    raw = "[type=json_invalid, input_value='[\"yaml.load\"]']"
    result = _salvage_from_text(raw)
    assert result is not None
    assert result.symbols[0].confidence < 0.5


def test_salvage_returns_none_for_prose_without_symbols() -> None:
    """No recognizable symbol => no claim. Never a guess."""
    raw = "[type=json_invalid, input_value='There is nothing to fix here.']"
    assert _salvage_from_text(raw) is None


def test_salvage_returns_none_without_a_payload() -> None:
    assert _salvage_from_text("Exceeded maximum output retries (1)") is None


def test_salvage_ignores_framework_identifiers() -> None:
    """Dotted names in the surrounding traceback are not package symbols."""
    raw = "pydantic_ai.exceptions.ToolRetryError [input_value='no symbols here']"
    assert _salvage_from_text(raw) is None


def test_salvage_is_bounded() -> None:
    """A runaway model must not produce unbounded claims."""
    names = ", ".join(f'"mod{i}.fn{i}"' for i in range(50))
    raw = f"[input_value='[{names}]']"
    result = _salvage_from_text(raw)
    assert result is not None
    assert len(result.symbols) <= 10


async def test_schema_violation_is_salvaged_end_to_end() -> None:
    """A model that never satisfies the schema still yields usable claims."""

    def wrong_shape(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        return ModelResponse(parts=[TextPart('["yaml.load"]')])

    result = await _extract(FunctionModel(wrong_shape))
    assert [(s.module, s.name) for s in result.symbols] == [("yaml", "load")]


def test_sanitize_drops_empty_modules() -> None:
    """A claim with no module cannot be searched for; drop it."""
    assert _sanitize([VulnerableSymbol(module="  ", name="load")]) == []


def test_sanitize_deduplicates() -> None:
    dupes = [
        VulnerableSymbol(module="yaml", name="load"),
        VulnerableSymbol(module="yaml", name="load"),
    ]
    assert len(_sanitize(dupes)) == 1


def test_sanitize_splits_dotted_name_into_module_path() -> None:
    """Models often answer `name="sessions.Session"`; normalize it."""
    cleaned = _sanitize([VulnerableSymbol(module="requests", name="sessions.Session")])
    assert cleaned[0].module == "requests.sessions"
    assert cleaned[0].name == "Session"


def test_sanitize_preserves_confidence_and_kind() -> None:
    cleaned = _sanitize(
        [VulnerableSymbol(module="yaml", name="Loader", kind="class", confidence=0.8)]
    )
    assert cleaned[0].kind == "class"
    assert cleaned[0].confidence == 0.8


async def test_malformed_claims_are_filtered_end_to_end() -> None:
    result = await _extract(
        _returning([{"module": "", "name": "load"}, {"module": "yaml", "name": "load"}])
    )
    assert [(s.module, s.name) for s in result.symbols] == [("yaml", "load")]


# -- configuration ---------------------------------------------------------


def test_defaults_to_ollama_when_no_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """The keyless guarantee: a clean clone must work with no accounts."""
    for var in ("DEPTRACE_LLM_PROVIDER", "GROQ_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(var, raising=False)

    config = config_from_env()
    assert config.provider == "ollama"
    assert config.api_key is None
    assert config.requires_key is False
    assert "localhost" in (config.base_url or "")


def test_explicit_provider_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "secret")
    assert config_from_env("ollama").provider == "ollama"


def test_provider_autoselected_from_available_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEPTRACE_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "secret")

    config = config_from_env()
    assert config.provider == "groq"
    assert config.api_key == "secret"
    assert config.requires_key is True


def test_env_overrides_model_and_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPTRACE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("DEPTRACE_LLM_MODEL", "llama3.2")
    monkeypatch.setenv("DEPTRACE_LLM_BASE_URL", "http://elsewhere:1234/v1")

    config = config_from_env()
    assert config.model == "llama3.2"
    assert config.base_url == "http://elsewhere:1234/v1"


@pytest.mark.parametrize("provider", ["ollama", "groq", "gemini"])
def test_every_provider_builds_a_model(provider: str) -> None:
    """Construction must not require network — only a client object."""
    config = LLMConfig(provider=provider, api_key="k", base_url="http://x/v1")
    assert build_model(config) is not None


def test_extractor_satisfies_the_protocol() -> None:
    extractor = _extractor(TestModel())
    assert isinstance(extractor, SymbolExtractor)


def test_no_module_level_globals_leak_between_configs() -> None:
    """Two extractors must not share state — RunState is the only state."""
    a = LLMSymbolExtractor(model=TestModel(), config=LLMConfig(provider="a"))
    b = LLMSymbolExtractor(model=TestModel(), config=LLMConfig(provider="b"))
    assert a.steps is not b.steps
    assert a.name != b.name


def test_os_environ_is_not_mutated() -> None:
    before = dict(os.environ)
    config_from_env("ollama")
    assert dict(os.environ) == before
