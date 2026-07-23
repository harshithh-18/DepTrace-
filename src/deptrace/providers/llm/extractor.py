"""Advisory prose -> `VulnerableSymbol` claims, via Pydantic AI.

This is the only place in DepTrace where a language model runs. It exists
because advisory text is unstructured English written by many different
people:

    "yaml.load() with the default Loader allows arbitrary code execution"
    "The Cookie parser in requests.sessions mishandles redirects"
    "A flaw was found in the way the library processes untrusted input"

The first names a symbol precisely. The second names a module. The third
names nothing at all, and for it the correct output is an **empty list** —
not a guess. That empty result is what routes a finding to NEEDS_REVIEW,
which is the honest answer when the advisory simply does not say.

The model's output is a *claim*. It is never trusted on its own: Phase 6's
verification gate rejects any REACHABLE verdict that lacks AST evidence.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_ai.models import Model
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from deptrace.core.state import StepLog, VulnerableSymbol

from .base import LLMConfig, SymbolExtraction, config_from_env

INSTRUCTIONS = """\
You analyze security advisories for Python packages. Your job is to identify \
which specific code symbols (functions, methods, or classes) an advisory says \
are vulnerable, so a static analyzer can check whether the user's code calls them.

Rules:
1. Report only symbols the advisory ACTUALLY names or clearly implies. Do not \
infer likely-sounding API names from your own knowledge of the package.
2. `module` is the IMPORT path a developer writes in code (e.g. "yaml", \
"requests.sessions"), NOT the PyPI distribution name (e.g. not "pyyaml").
3. `name` is the function, method, or class. Omit it when the advisory \
implicates the whole module.
4. confidence: 0.9+ when the advisory names the symbol explicitly; 0.5-0.7 \
when it is implied by context; below 0.5 when you are unsure.
5. If the advisory does not identify any specific symbol — many only describe \
an impact — return an EMPTY list. An empty list is a correct, useful answer. \
Guessing produces false alarms, which is far worse than reporting nothing.

Return only what the text supports."""

PROMPT_TEMPLATE = """\
Package: {package}
Advisory: {vuln_id}

Summary: {summary}

Details:
{details}

Which symbols does this advisory identify as vulnerable?"""

# How much advisory text to send. Details can run to many KB of changelog;
# the symbol names live near the top, and truncating keeps local models fast.
MAX_DETAIL_CHARS = 4000


class _RetryableError(Exception):
    """A transient model/transport failure worth retrying."""


def build_model(config: LLMConfig) -> Model:
    """Construct a Pydantic AI model from config.

    All three providers speak the OpenAI chat protocol, so one adapter
    covers them. Ollama ignores the API key but the client requires a
    non-empty string, hence the placeholder.
    """
    provider = OpenAIProvider(
        base_url=config.base_url,
        api_key=config.api_key or "ollama",
    )
    return OpenAIChatModel(config.model, provider=provider)


class LLMSymbolExtractor:
    """Extracts symbol claims from advisories, with retry and rate limiting.

    Args:
        model: an explicit Pydantic AI model. Tests pass `TestModel` or
            `FunctionModel` here, which is what keeps the suite offline.
        config: provider settings; read from the environment when omitted.
    """

    def __init__(
        self,
        model: Model | None = None,
        config: LLMConfig | None = None,
    ) -> None:
        self.config = config or config_from_env()
        self.name = self.config.provider
        self._model = model if model is not None else build_model(self.config)
        # Per-provider cap: free tiers rate-limit aggressively, and the
        # orchestrator fans out one sub-task per CVE.
        self._semaphore = asyncio.Semaphore(self.config.concurrency)
        self.steps: list[StepLog] = []

        self._agent: Agent[None, SymbolExtraction] = Agent(
            self._model,
            output_type=SymbolExtraction,
            instructions=INSTRUCTIONS,
            retries=2,
        )

    async def _run_agent(self, prompt: str) -> tuple[SymbolExtraction, int, int]:
        """Run the agent once, retrying transient failures with backoff.

        The retry policy is built from config rather than hardcoded in a
        decorator so tests can set `retry_wait=0` — otherwise proving that
        retries happen costs real seconds of wall-clock time on every run.
        """
        retrying = AsyncRetrying(
            retry=retry_if_exception_type(_RetryableError),
            wait=wait_exponential_jitter(initial=self.config.retry_wait, max=15),
            stop=stop_after_attempt(self.config.max_attempts),
            reraise=True,
        )

        async for attempt in retrying:
            with attempt:
                try:
                    result = await self._agent.run(prompt)
                except UnexpectedModelBehavior as exc:
                    # The model answered, but not in the requested shape.
                    # Small local models frequently ignore tool-calling and
                    # emit a bare JSON list instead. Retrying will not change
                    # that, so salvage what the raw text contains rather than
                    # discarding a usable answer. The rejected output is
                    # carried on the causing ToolRetryError, not on `exc`.
                    salvaged = _salvage_from_text(f"{exc} {exc.__cause__}")
                    if salvaged is not None:
                        return salvaged, 0, 0
                    raise _RetryableError(str(exc)) from exc
                except Exception as exc:
                    raise _RetryableError(str(exc)) from exc

                usage = result.usage
                return (
                    result.output,
                    getattr(usage, "input_tokens", 0) or 0,
                    getattr(usage, "output_tokens", 0) or 0,
                )

        raise _RetryableError("retry loop exhausted")  # pragma: no cover - unreachable

    async def extract(
        self, *, package: str, vuln_id: str, summary: str, details: str
    ) -> SymbolExtraction:
        """Propose the symbols one advisory implicates.

        Never raises. A model that is unreachable, slow, or returns garbage
        yields an empty extraction, and the finding lands in NEEDS_REVIEW —
        degraded but honest, rather than a failed scan.
        """
        prompt = PROMPT_TEMPLATE.format(
            package=package,
            vuln_id=vuln_id,
            summary=summary or "(none provided)",
            details=(details or "(none provided)")[:MAX_DETAIL_CHARS],
        )

        started = time.perf_counter()
        ok = True
        detail = ""
        tokens_in = tokens_out = 0
        extraction = SymbolExtraction()

        try:
            async with self._semaphore:
                extraction, tokens_in, tokens_out = await self._run_agent(prompt)
            extraction = SymbolExtraction(
                symbols=_sanitize(extraction.symbols),
                reasoning=extraction.reasoning,
            )
            detail = f"{vuln_id}: {len(extraction.symbols)} symbol(s)"
        except Exception as exc:
            ok = False
            detail = f"{vuln_id}: extraction failed ({type(exc).__name__})"

        self.steps.append(
            StepLog(
                step="llm.extract_symbols",
                duration_ms=(time.perf_counter() - started) * 1000,
                ok=ok,
                detail=detail,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
            )
        )
        return extraction


# A dotted Python symbol: `yaml.load`, `requests.sessions.Session`. Used only
# to recover claims from models that ignore the tool-calling schema.
_SYMBOL_RE = re.compile(r"\b([a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)+)\b")

# Pydantic AI reports the rejected payload as `input_value=...`. Scanning only
# that slice keeps library identifiers in the surrounding traceback
# (`pydantic_ai.exceptions`, `json_invalid`) from being mistaken for claims.
# Two shapes occur in practice: a quoted string when the model returned raw
# text, and a bare Python repr when it returned a parsed list/dict.
_INPUT_VALUE_RE = re.compile(
    r"input_value=(?:(['\"])(?P<quoted>.*?)\1|(?P<bare>\[.*?\]|\{.*?\}))",
    re.DOTALL,
)

# Names that are never a package symbol, in case they survive the slice.
_SALVAGE_STOPWORDS = frozenset({"pydantic_ai", "pydantic", "json", "self", "cls"})

# A single flat JSON object, for recovering `{"module": "yaml", ...}` entries
# embedded in prose or markdown fences.
_JSON_OBJECT_RE = re.compile(r"\{[^{}]*\}")


def _salvage_from_text(text: str) -> SymbolExtraction | None:
    """Recover symbol claims from a model that ignored the output schema.

    Small local models — the keyless default — often reply with a bare JSON
    list like `["yaml.load", "FullLoader"]` instead of calling the result
    tool. Retrying does not fix that, and failing outright would make the
    keyless path useless on exactly the hardware it exists to support.

    Returns None when the text contains no recognizable dotted symbol, so
    an unparseable answer still degrades to "no claim" rather than a guess.
    Salvaged entries carry reduced confidence: they came from a model that
    already failed to follow instructions, so they are weaker claims — and
    like every claim, they still prove nothing until the AST engine agrees.
    """
    # Only the model's own rejected output is searched, never the framework's
    # error prose around it.
    payloads = [
        m.group("quoted") or m.group("bare") or ""
        for m in _INPUT_VALUE_RE.finditer(text)
    ]
    payloads = [p for p in payloads if p]
    if not payloads:
        return None

    # `input_value` is a repr, so escapes arrive literally.
    blob = "\n".join(payloads).replace("\\n", "\n").replace("\\'", "'")

    symbols = _salvage_json_objects(blob) or _salvage_dotted_names(blob)
    if not symbols:
        return None
    return SymbolExtraction(
        symbols=symbols[:10], reasoning="salvaged from unstructured output"
    )


def _salvage_json_objects(blob: str) -> list[VulnerableSymbol]:
    """Pull `{"module": ..., "name": ...}` objects out of prose or code fences.

    The common failure is a model that produces *correct content* in the
    wrong envelope — a bare array wrapped in markdown, rather than the
    `{"symbols": [...]}` object the schema asks for. The content is fine, so
    it is worth recovering.
    """
    symbols: list[VulnerableSymbol] = []
    for match in _JSON_OBJECT_RE.finditer(blob):
        try:
            obj = json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        module = obj.get("module")
        if not isinstance(module, str) or not module.strip():
            continue
        name = obj.get("name")
        symbols.append(
            VulnerableSymbol(
                module=module.strip(),
                name=name.strip() if isinstance(name, str) and name.strip() else None,
                confidence=0.4,
            )
        )
    return symbols


def _salvage_dotted_names(blob: str) -> list[VulnerableSymbol]:
    """Last resort: treat bare dotted names as claims (`["yaml.load"]`)."""
    symbols: list[VulnerableSymbol] = []
    for match in _SYMBOL_RE.findall(blob):
        module, _, name = match.rpartition(".")
        if not module or module.split(".")[0] in _SALVAGE_STOPWORDS:
            continue
        symbols.append(VulnerableSymbol(module=module, name=name, confidence=0.4))
    return symbols


def _sanitize(symbols: list[VulnerableSymbol]) -> list[VulnerableSymbol]:
    """Drop malformed claims and deduplicate.

    Models occasionally return the PyPI name instead of the import path, or
    an empty module. A claim with no module cannot be searched for, so it is
    discarded here rather than becoming a silently-unmatchable target.
    """
    cleaned: list[VulnerableSymbol] = []
    seen: set[tuple[str, str | None]] = set()

    for symbol in symbols:
        module = symbol.module.strip().strip(".")
        if not module:
            continue

        name = symbol.name.strip() if symbol.name else None
        # Models sometimes answer with the fully-qualified path in `name`;
        # keep only the final component so it matches the AST resolver.
        if name and "." in name:
            module = f"{module}.{name.rsplit('.', 1)[0]}" if name.count(".") else module
            name = name.rsplit(".", 1)[-1]
        if name in ("", "None"):
            name = None

        key = (module, name)
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(
            VulnerableSymbol(
                module=module,
                name=name,
                kind=symbol.kind,
                confidence=symbol.confidence,
            )
        )
    return cleaned


def extractor_from_env(**overrides: Any) -> LLMSymbolExtractor:
    """Convenience constructor used by the CLI and orchestrator."""
    return LLMSymbolExtractor(config=config_from_env(**overrides))
