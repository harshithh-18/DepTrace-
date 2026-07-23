"""The LLM provider interface and model selection.

Everything in this package produces **claims**, never facts. That asymmetry
is the whole architecture: the model reads messy advisory prose and proposes
which symbol is implicated; only the AST engine can prove the scanned repo
reaches it. Nothing here may construct `Evidence`, and the type system
enforces it — `Evidence.produced_by` is `Literal["ast_engine"]`.

Provider selection defaults to **Ollama**, which runs locally with no API
key. That is a deliberate constraint, not a fallback of last resort: a clean
clone of this repo must scan a project with zero accounts and zero secrets.
Gemini and Groq are opt-in accelerations for anyone who has keys.

All three are reached through the OpenAI-compatible chat API, so there is
one code path rather than three bespoke clients.

Operational note, measured rather than assumed: small local models are
unreliable at structured output. `qwen2.5-coder:1.5b` ignores tool-calling
entirely; `qwen2.5-coder:7b` succeeds but sometimes wraps a correct answer in
prose or a bare JSON array. `extractor._salvage_from_text` exists for exactly
that case. Extraction quality is therefore *better* with a hosted provider —
the keyless path guarantees the tool runs, not that it runs optimally.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from deptrace.core.state import VulnerableSymbol


class SymbolExtraction(BaseModel):
    """The typed output contract for advisory -> symbol extraction.

    An empty `symbols` list is a valid, expected answer. Most advisories name
    no function at all, and inventing one would manufacture a false positive
    that the verification gate would then have to catch.
    """

    symbols: list[VulnerableSymbol] = Field(default_factory=list)
    reasoning: str = ""


@dataclass(frozen=True)
class LLMConfig:
    """How to reach a model. Resolved from the environment, never global."""

    provider: str = "ollama"
    model: str = "qwen2.5-coder:7b"
    base_url: str | None = None
    api_key: str | None = None
    concurrency: int = 4
    timeout: float = 120.0
    max_attempts: int = 3
    # Backoff base in seconds. Tests set this to 0 so the suite does not
    # spend real wall-clock time proving that retries happen.
    retry_wait: float = 1.0

    @property
    def requires_key(self) -> bool:
        return self.provider in ("gemini", "groq")


# Default endpoints. Ollama is local; the others are OpenAI-compatible
# shims published by the vendors themselves.
_DEFAULTS: dict[str, tuple[str, str]] = {
    "ollama": ("http://localhost:11434/v1", "qwen2.5-coder:7b"),
    "groq": ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
    "gemini": (
        "https://generativelanguage.googleapis.com/v1beta/openai/",
        "gemini-2.0-flash",
    ),
}

_KEY_ENV: dict[str, str] = {
    "groq": "GROQ_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


def config_from_env(provider: str | None = None) -> LLMConfig:
    """Build an `LLMConfig` from environment variables.

    Selection order: explicit argument, then `DEPTRACE_LLM_PROVIDER`, then
    whichever key happens to be set, then Ollama. The last step is what
    guarantees the keyless path always works.
    """
    chosen = provider or os.getenv("DEPTRACE_LLM_PROVIDER")

    if not chosen:
        for candidate, env_var in _KEY_ENV.items():
            if os.getenv(env_var):
                chosen = candidate
                break
    chosen = (chosen or "ollama").lower()

    default_url, default_model = _DEFAULTS.get(chosen, _DEFAULTS["ollama"])
    key_env = _KEY_ENV.get(chosen)

    return LLMConfig(
        provider=chosen,
        model=os.getenv("DEPTRACE_LLM_MODEL") or default_model,
        base_url=os.getenv("DEPTRACE_LLM_BASE_URL") or default_url,
        api_key=os.getenv(key_env) if key_env else None,
        concurrency=int(os.getenv("DEPTRACE_LLM_CONCURRENCY") or 4),
    )


@runtime_checkable
class SymbolExtractor(Protocol):
    """Extracts vulnerable-symbol claims from advisory prose."""

    name: str

    async def extract(
        self, *, package: str, vuln_id: str, summary: str, details: str
    ) -> SymbolExtraction:
        """Propose which symbols an advisory implicates.

        Implementations must return an empty list rather than guess, and must
        never raise for a single bad advisory — extraction failure degrades
        to "no claim", which routes the finding to NEEDS_REVIEW.
        """
        ...
