# DepTrace — Design Decisions

Architecture decision records for DepTrace v0.1.0. Each records what was
decided, why, what it costs, and what would change the answer.

---

## ADR-001 — The LLM proposes, static analysis verifies

**Status:** accepted · **Date:** 2026-07-23

### Context

Security advisories are unstructured prose written by many different people:

> "yaml.load() with the default Loader allows arbitrary code execution"
> "The Cookie parser in requests.sessions mishandles redirects"
> "A flaw was found in the way the library processes untrusted input"

The first names a symbol precisely. The second names a module. The third
names nothing at all. Reading that variety is exactly what language models
are good at — and exactly what a regex is not.

But a language model cannot be trusted to answer "does this repository call
that function?" It has not read the repository, and it will produce a
confident, plausible, occasionally fabricated answer. In a security tool a
fabricated finding is worse than no finding: it teaches the user to ignore
the tool.

### Decision

Split the work by what each component can actually be held to:

| Component | Produces | Trust |
| --- | --- | --- |
| LLM (advisory → symbol) | **Claims** (`VulnerableSymbol`) | Unverified, carries `confidence` |
| AST engine (code → call site) | **Facts** (`Evidence`) | Deterministic, re-checkable, carries `file:line` |

The separation is enforced in the type system rather than by convention.
`Evidence.produced_by` is `Literal["ast_engine"]`, so mypy rejects any other
producer at check time and Pydantic rejects it at runtime. The LLM layer
*cannot construct evidence* — not "should not", cannot.

`verify.py` is the single gate: no `Evidence`, no `REACHABLE` verdict. An
unsupported claim is downgraded and counted in `metrics.hallucination_blocked`.

### Consequences

**Good.** A hallucinating model degrades precision but cannot fabricate a
security finding. This is tested adversarially: `test_hallucinated_claim_cannot_reach_the_report`
drives a deliberately lying extractor through the real pipeline, and a live
run against 16 real advisories with fabricated symbols at 0.99 confidence
produced **zero** reachable verdicts.

**Good.** Every REACHABLE finding carries a `file:line` a human can open. A
verdict nobody can check is worth nothing.

**Cost.** DepTrace can only find what the AST engine can resolve. Extraction
quality bounds the *usefulness* of the result even though it cannot bound
its *correctness* — a lazy extractor yields a scanner that is perfectly
correct and completely useless. That is why the eval measures both.

### What would change this

If advisories carried machine-readable symbol data (a CVE field naming the
affected function), the LLM would be unnecessary and this becomes a pure
static-analysis tool. OSV has no such field today.

---

## ADR-002 — Three-state verdicts, never binary

**Status:** accepted · **Date:** 2026-07-23

### Context

The obvious API is `reachable: bool`. It is also a lie. Dynamic imports,
reflection, and advisories that name no symbol are genuinely undecidable by
static analysis, and forcing them into a binary means either inventing
alarms or silently declaring unknown code safe.

### Decision

`REACHABLE` / `NOT_REACHABLE` / `NEEDS_REVIEW`, with uncertainty always
resolving toward review. `Finding.verdict` defaults to `NEEDS_REVIEW`: a
finding is uncertain until something proves otherwise.

Four rules, applied in order:

1. No `Evidence` → never `REACHABLE`.
2. Dynamic usage detected → `NEEDS_REVIEW`.
3. No claims extracted → `NEEDS_REVIEW`, **not** `NOT_REACHABLE`.
   "The advisory did not say" is not "your code is safe."
4. Claims existed, code was searched, nothing found → `NOT_REACHABLE`.

Rule 4 is the only path to a safe verdict, and it requires having known what
to look for.

### Consequences

**Good.** The tool never claims certainty it does not have. `NEEDS_REVIEW`
is a useful answer that a binary API cannot express.

**Cost.** Users must handle three states, and `--fail-on` needs a policy
rather than a boolean. A repo full of dynamic imports will produce many
review items — honest, but less satisfying than a clean yes/no.

**Cost, measured.** An early version flagged *every* `getattr` call as
dynamic. On the real `requests` codebase that was 29 flags, 27 of them
`getattr(obj, "constant", default)` — a static attribute access, as
analyzable as `obj.status`. Since any flag routes findings to review, nearly
every real repo would have collapsed into "everything needs review" and the
three-state verdict would have been worthless. Fixed by flagging only
*computed* arguments: 29 → 10 flags, no true positives lost.

---

## ADR-003 — No graph framework for orchestration

**Status:** accepted · **Date:** 2026-07-23

### Context

LangGraph and similar frameworks are the default choice for "AI agent"
projects. They provide cycles, conditional edges, human-in-the-loop
interrupts, and durable resume.

### Decision

Use `asyncio.TaskGroup` with a `Semaphore`. No orchestration framework.

DepTrace's workflow is an acyclic pipeline with exactly one fan-out:

```
parse manifests → query OSV (batched) → fan out per (dep, CVE) → verify → collect
```

There are no cycles, no interrupts, and no mid-run resume. Every feature the
framework exists to provide would go unused, while its concepts, version
churn, and transitive dependencies would all be paid for.

For a tool whose entire thesis is "your dependency tree is a liability",
adding a heavyweight dependency to avoid writing 40 lines of `asyncio` would
be self-refuting.

### Consequences

**Good.** 8 direct runtime dependencies. The orchestrator is one readable
file with no framework concepts to learn.

**Good.** `RunState` is a plain Pydantic model that round-trips through JSON,
which is what makes the core queue-ready without a rewrite.

**Cost.** Retries, fan-out, and step logging are hand-written (~40 lines).
If DepTrace later needs cyclic re-planning — "the extraction was ambiguous,
re-read the advisory with more context" — this decision should be revisited.

---

## ADR-004 — SQLite and diskcache defaults; the tool must run keyless

**Status:** accepted · **Date:** 2026-07-23

### Context

The natural production choices are Postgres for state and Redis for cache.
Both require a running service, and a portfolio project that requires
`docker compose up` before it does anything is a project nobody runs.

### Decision

SQLite for state, `diskcache` for advisories, **Ollama as the default LLM**,
and OSV.dev (which needs no key) for vulnerability data. Postgres, Redis,
Groq, and Gemini are all swappable behind provider interfaces.

The hard constraint: `git clone && uv sync && deptrace scan .` must work
with no accounts, no API keys, and no services running. CI enforces this
with a keyless smoke-test job.

### Consequences

**Good.** A clean clone scans a project immediately. The whole test suite —
289 tests — runs offline; `tests/conftest.py` blocks outbound sockets so a
test that reaches the internet fails loudly rather than becoming flaky.

**Cost, measured and honest.** Small local models are unreliable at
structured output. `qwen2.5-coder:1.5b` ignores tool-calling entirely and
returns bare JSON text. `qwen2.5-coder:7b` succeeds but sometimes wraps a
correct answer in prose or a markdown fence, and on modest hardware takes
143–296 s per advisory. A salvage parser recovers claims from both failure
shapes, but the honest summary is: **the keyless path guarantees the tool
runs, not that it runs well.** Groq or Gemini extract better and faster.

---

## ADR-005 — Python-only in v1

**Status:** accepted · **Date:** 2026-07-23

### Context

Reachability triage is language-agnostic in principle. JavaScript, Go, and
Java all have the same alert-fatigue problem.

### Decision

Python only. Every language needs its own manifest parsers, its own
distribution→import name mapping, and its own AST resolver with its own
import semantics. That last part is the moat, and it does not transfer:
Python's `from . import x` has no JavaScript equivalent.

Shipping one language where the analysis is genuinely correct beats shipping
three where it is approximately correct — especially for a security tool,
where "approximately correct" means silent false negatives.

### Consequences

**Good.** The AST engine handles Python's real complexity: aliased imports,
`from` imports, relative imports (including inside `__init__.py`), lazy
imports inside functions, conditional imports in `try`/`except`, and
vendored-code exclusion. Each is a labeled eval case.

**Cost.** A polyglot repo gets partial coverage. This is documented as a
scope decision in the README, not omitted.

### v2

The `tools/` layer is already the seam. A `reachability_js.py` implementing
the same `find_reachable(repo, symbols) -> Evidence` contract would need no
changes to `core/`, `verify.py`, or the reporters.
