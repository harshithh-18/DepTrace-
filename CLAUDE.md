# DepTrace — Project Context

---

## 0. How to use this document (instructions to Claude Code)

You are guiding a third-year CS undergraduate through building this project from scratch. He is competent in Python but new to static analysis and agent architecture. Follow these rules:

1. **Work one phase at a time.** Never jump ahead, never dump multiple phases at once. Finish a phase, verify it, commit, then move on.
2. **Gate on green.** A phase is not done until `uv run pytest -q`, `uv run mypy src`, and `uv run ruff check .` all pass. Do not proceed on a red build — everything downstream assumes the previous phase is solid.
3. **He types the code and makes the commits.** Explain what to build and why, provide the implementation, but the commit history must be his and must be incremental. One giant "initial commit" destroys a core deliverable of this project.
4. **Explain the *why* before the *what*.** He is learning, not just shipping. Every non-obvious design decision should come with its reasoning — those reasons are the interview answers this project exists to produce.
5. **Ask before changing scope.** If a phase is running long, propose a scope cut from §9 rather than silently expanding or skipping.
6. **Never invent numbers.** Any metric in the README, resume bullet, or docs must come from an actual measured run. Use `[brackets]` as placeholders until real values exist.

---

## 1. What DepTrace is

**One line:** DepTrace triages dependency CVEs by call-path reachability — it proves which vulnerabilities the user's code actually touches.

**The problem.** A package like `pyyaml` has hundreds of functions. A CVE affects *one* of them (`yaml.load`). Existing scanners (Dependabot, Snyk, pip-audit) only check *"is this package installed?"* — not *"does your code call the broken part?"* Result: 47 alerts, 3 that matter, developers ignore all of them, real vulnerabilities slip through. That's alert fatigue, and it is the actual security failure.

**What DepTrace does.** Points at a Python repo → reads manifests → queries OSV for known CVEs → uses an LLM to extract *which symbol* each advisory implicates → walks the repo's AST to check whether that symbol is actually imported/called → returns a three-state verdict with file:line evidence.

**Input:** a path to a Python project.
**Output:** a prioritized table of findings, JSON/SARIF export, and a non-zero exit code if anything is reachable.

```
PACKAGE    VULNERABILITY     VERDICT         WHERE
pyyaml     CVE-2024-1234     REACHABLE       app/config.py:42
pillow     CVE-2023-5678     NOT REACHABLE   —
requests   CVE-2024-9999     NEEDS REVIEW    (dynamic import)
```

**Why it exists as a portfolio project:** it is a narrow real problem, objectively evaluable against labeled ground truth, fully open-sourceable (no secrets, no private data), and it maps 1:1 onto AI-agent-engineer interview questions (planner loop, tool use, memory/state, evaluation, failure modes).

---

## 2. The inviolable architectural principle

**The LLM proposes. Static analysis verifies.**

| Component | Produces | Trustworthiness |
|---|---|---|
| LLM (advisory → symbol extraction) | **Claims** (`VulnerableSymbol`) | Unverified, may hallucinate, carries `confidence` |
| AST engine (code → call sites) | **Facts** (`Evidence`) | Deterministic, re-checkable, carries `file:line` |

Four rules that follow, and must never be violated:

1. **Only the AST engine can mint `Evidence`.** Enforced in the type system: `Evidence.produced_by` is `Literal["ast_engine"]`. Nothing else can construct it — mypy rejects it and Pydantic rejects it at runtime.
2. **No `REACHABLE` verdict without at least one `Evidence` object.** `verify.py` is the gate. An LLM claim with no supporting AST evidence gets downgraded to `NEEDS_REVIEW` and increments `metrics.hallucination_blocked`.
3. **Three-state verdicts, never binary.** `REACHABLE` / `NOT_REACHABLE` / `NEEDS_REVIEW`. Refusing to force a binary is the maturity signal — dynamic imports and vague advisories are honestly routed to review rather than guessed at.
4. **Fail safe.** `Finding.verdict` defaults to `NEEDS_REVIEW`. A finding is uncertain until something proves otherwise. Never silently mark something safe.

`hallucination_blocked` is a headline metric. "The model attempted N unsupported call-path claims across the eval set; the gate caught all N" is a concrete, checkable safety property — report it in the README.

---

## 3. Tech stack and hard constraints

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.12 | `asyncio.TaskGroup` needs 3.11+ |
| Packaging | `uv` + `uv.lock` | Reproducible builds; also a format DepTrace parses |
| Layout | `src/` layout | Tests import the *installed* package, not the working dir |
| Agent layer | **Pydantic AI** | Typed tools, DI for mocking, stateless by default |
| Async | `asyncio` + `TaskGroup` + `Semaphore` | Parallel per-CVE fan-out, rate-limit control |
| CLI | Typer + Rich | Tables, progress, exit codes |
| API (thin) | FastAPI | Second adapter; proves queue-readiness |
| LLM (reasoning) | Gemini Flash free tier | Advisory → symbol extraction |
| LLM (bulk) | Groq / Llama 3.3 70B | Fast summarization |
| LLM (keyless) | Ollama + qwen2.5-coder | **Default fallback — repo must run with zero API keys** |
| Vuln data | **OSV.dev** | Free, no key, batch endpoint |
| Advisory prose | GitHub Security Advisories | Richer text → better extraction |
| **Reachability** | **stdlib `ast`** | Zero third-party deps — right kind of flex for a security tool |
| Version logic | `packaging` | PEP 440. **Never hand-roll** — `"1.10" > "1.9"` is `False` as strings |
| State | SQLite default, Postgres optional | Zero-config clone; Neon for the scale story |
| Cache | `diskcache` default, Redis optional | No service required to run |
| HTTP | `httpx` | Async; `requests` would block the fan-out |
| Retry | `tenacity` | Exponential backoff on 429/5xx |
| Tracing | Langfuse self-host / OTel spans | Feeds the eval harness |
| Quality | ruff + mypy `strict` + pytest-asyncio | The anti-vibecode signal |
| CI | GitHub Actions | Lint + types + tests + eval regression |
| License | MIT | |

**Hard constraints:**

- **Must run keyless.** `git clone && uv sync && deptrace scan .` works with no accounts, no API keys, no external services. Ollama fallback for the LLM, SQLite for state, diskcache for cache. This property is worth more than a hosted demo.
- **Python-only in v1.** Multi-language is v2 and is documented as a deliberate scope decision, not an omission.
- **Zero cost.** Everything free-tier or local.
- **Lean dependency tree.** It is a dependency security tool; a bloated transitive tree is thematically damning.
- **No framework for orchestration.** The workflow is an acyclic pipeline with one fan-out — LangGraph's value (cycles, interrupts, durable resume) isn't exercised. This decision is recorded as ADR-003 in `DESIGN.md`.

---

## 4. Repo structure and the dependency rule

```
deptrace/
├── src/deptrace/
│   ├── core/
│   │   ├── state.py           # ✅ DONE — domain models
│   │   ├── orchestrator.py    # plan → parallel triage → synthesize
│   │   └── config.py          # provider selection from env/toml
│   ├── providers/
│   │   ├── llm/               # base.py, gemini.py, groq.py, ollama.py
│   │   ├── vulndb/            # base.py, osv.py
│   │   └── store/             # base.py, sqlite.py, postgres.py
│   ├── tools/
│   │   ├── manifest.py        # requirements/pyproject/uv.lock → Dependency
│   │   ├── advisory.py        # fetch + LLM symbol extraction
│   │   ├── reachability.py    # ← THE MOAT: pure, deterministic, tested
│   │   └── remediation.py     # minimum safe version bump
│   ├── verify.py              # the evidence gate
│   ├── report.py              # rich table / json / markdown / sarif
│   ├── cli.py                 # primary entrypoint
│   └── api.py                 # thin FastAPI adapter
├── evals/
│   ├── dataset.jsonl          # labeled (repo@sha, CVE, verdict)
│   ├── fixtures/              # synthetic mini-repos with known answers
│   └── run_eval.py            # → precision/recall/F1 table
├── tests/
├── .github/workflows/ci.yml
├── DESIGN.md                  # ADRs
├── CLAUDE.md                  # this file
└── README.md
```

**The dependency rule: dependencies point inward.** `providers/` and `tools/` import from `core/`; `core/` imports from neither. This is what makes the core stateless and testable with no network access — and it's why the entire eval suite runs offline in CI.

---

## 5. Domain vocabulary (already built, in `core/state.py`)

| Type | Role | Key detail |
|---|---|---|
| `Verdict` | StrEnum | `REACHABLE` / `NOT_REACHABLE` / `NEEDS_REVIEW` |
| `Dependency` | frozen | `name`, `version`, `specifier`, **`import_names`**, `source`, `is_direct` |
| `VulnerableSymbol` | frozen | **A CLAIM.** `module`, `name`, `kind`, `confidence` |
| `Vulnerability` | frozen | `id`, `aliases`, `summary`, `details`, `severity`, `fixed_version`, `references`, `symbols` |
| `Evidence` | frozen | **A FACT.** `produced_by: Literal["ast_engine"]`, `file`, `line`, `column`, `symbol`, `kind`, `snippet` |
| `Finding` | mutable | The output unit: dependency + vulnerability + verdict + evidence + rationale + remediation + `downgraded` |
| `StepLog` | frozen | Per-step record; feeds tracing **and** the eval harness |
| `RunMetrics` | mutable | Counters incl. `hallucination_blocked`, `noise_reduction` property |
| `RunState` | mutable | Everything about one scan. Serializable. **No module-level globals anywhere in this codebase.** |

**Design notes worth remembering:** facts are frozen, accumulating state is mutable. Claims carry `confidence`; facts don't — that asymmetry *is* the architecture. `RunState` round-trips through JSON, which is what makes the core queue-ready and horizontally scalable without a rewrite.

---

## 6. Build sequence

Each phase: goal → what to build → definition of done → commit. Do not start a phase until the previous one's gate is green.

### Phase 2 — Manifest parsing (~2h)
**Goal:** turn a repo path into `list[Dependency]`, with no network and no LLM.
- Parse `requirements.txt` (incl. `-r` includes, comments, extras, environment markers), `pyproject.toml` (PEP 621 `dependencies` + optional groups + Poetry section), and `uv.lock`.
- Normalize names per PEP 503 (lowercase, `-`/`_`/`.` → `-`).
- **Distribution → import name mapping.** `pyyaml`→`yaml`, `beautifulsoup4`→`bs4`, `Pillow`→`PIL`, `scikit-learn`→`sklearn`. Strategy: `importlib.metadata.packages_distributions()` → static fallback map → normalized guess. Populate `Dependency.import_names`.
- Mark `is_direct` correctly (lockfiles contain transitives).

**Done when:** parsers handle all three formats, name mapping is unit-tested against the known-tricky list, gate green.
**Commit:** `feat(tools): manifest parsers with distribution-to-import-name mapping`

### Phase 3 — Vulnerability lookup (~2h)
**Goal:** `list[Dependency]` → `list[Vulnerability]`, cached.
- OSV.dev client using the **batch** endpoint (`/v1/querybatch`), async via `httpx`.
- `diskcache` layer keyed on `(package, version)`; cache advisories aggressively — eval runs will hit the same packages repeatedly.
- Version-range matching with `packaging.specifiers` / `Version`. Handle OSV's `events`-style ranges (`introduced` / `fixed`).
- Extract `fixed_version` for remediation.
- `tenacity` retry with exponential backoff + jitter; explicit 429 handling.
- Define the `VulnDBProvider` base interface so OSV is swappable.

**Done when:** a real repo returns real CVEs, second run is cache-hot and offline-capable, gate green.
**Commit:** `feat(providers): OSV vulnerability provider with caching and version matching`

### Phase 4 — AST reachability engine (~5–6h) ⚠️ THE MOAT
**Goal:** given a repo and a list of symbols, produce `Evidence`. Pure function. **No async, no network, no LLM.** Spend the most time here.
1. Walk `.py` files; exclude `.venv/`, `site-packages/`, `build/`, `dist/`, `.git/`, `node_modules/`.
2. `ast.parse` each file; on `SyntaxError`, record and skip (never crash the scan).
3. Build a per-file import table: resolve `import x.y`, `import x.y as z`, `from x import y`, `from x import y as z`, relative imports → alias ➜ fully-qualified symbol.
4. Walk `ast.Call` and `ast.Attribute`; resolve `Name` and dotted `Attribute` chains against the import table.
5. Emit `Evidence` with real `file`, `line`, `column`, resolved `symbol`, `kind`, and the source-line `snippet`.
6. **(Stretch)** Coarse intra-repo call graph; BFS upward from the vulnerable call site, bounded depth 5.
- Detect dynamic patterns (`getattr`, `importlib.import_module`, `eval`, `exec`, `__import__`) and flag the file → routes findings to `NEEDS_REVIEW`.

**Done when:** synthetic fixtures with known answers all pass, including aliased imports, `from` imports, nested attribute chains, and a dynamic-import case. Gate green.
**Commit:** `feat(tools): AST reachability engine with call-site evidence`

### Phase 5 — LLM layer (~2h) — *first LLM code in the project*
**Goal:** advisory prose → `VulnerableSymbol` claims.
- `LLMProvider` base interface; implement Gemini, Groq, Ollama. Selected by config/env, defaulting to Ollama so the repo runs keyless.
- Pydantic AI agent with typed output: `{symbols: list[VulnerableSymbol]}`.
- Prompt engineering: extract module + function names from advisory text; **return empty rather than guess** when the advisory has no function-level detail (that's the `NEEDS_REVIEW` path working as designed).
- Per-provider `asyncio.Semaphore` for rate limits; `tenacity` retry.
- Token/latency accounting into `StepLog`.
- Tests use Pydantic AI's `TestModel`/`FunctionModel` — **the whole suite must run offline with zero API calls.**

**Done when:** symbol extraction works on real advisories, tests run offline, gate green.
**Commit:** `feat(providers): pluggable LLM layer with typed symbol extraction`

### Phase 6 — Orchestrator + verification gate (~3h)
**Goal:** wire the pipeline; enforce the trust boundary.
- Plan: dedupe `(dependency, vulnerability)` pairs → fan out with `asyncio.TaskGroup`, capped by semaphore.
- Per-CVE sub-task: fetch advisory → extract symbols → run AST engine → assign verdict + rationale.
- `verify.py`: **reject any `REACHABLE` claim with zero `Evidence`** → downgrade to `NEEDS_REVIEW`, set `downgraded=True`, increment `hallucination_blocked`.
- Populate `RunMetrics` throughout; append `StepLog` per step.
- Graceful degradation: one failed sub-task must not kill the scan.

**Done when:** end-to-end scan on a real public repo produces correct three-state verdicts; a deliberately-fabricated LLM claim is provably caught by the gate (write that test). Gate green.
**Commit:** `feat(core): async orchestrator with evidence verification gate`

### Phase 7 — CLI, reporting, persistence (~3h)
**Goal:** make it usable and CI-integrable.
- Typer CLI: `deptrace scan <path>` with `--format {table,json,markdown,sarif}`, `--fail-on {reachable,any,never}`, `--offline`, `--provider`.
- Rich output: findings table, progress during fan-out, summary line with noise-reduction %.
- **Exit codes:** `0` clean, `1` reachable findings present, `2` scan error. This is what makes it a CI gate.
- SARIF export (GitHub code-scanning ingests it — strong differentiator).
- `StateStore` interface; SQLite implementation persisting `RunState` per step, keyed by `scan_id`; resume support.
- Thin FastAPI adapter (`POST /scans` → `scan_id`, `GET /scans/{id}`) over the same stateless core.
- OTel/Langfuse spans per step.

**Done when:** CLI is pleasant, exit codes correct, a scan can be resumed from SQLite, gate green.
**Commit:** `feat(cli): rich reporting, SARIF export, and CI exit codes`

### Phase 8 — Evaluation harness (~4h) ⚠️ NON-NEGOTIABLE
**Goal:** objective numbers. This is what separates this project from a wrapper.
- **Labeled dataset** (`evals/dataset.jsonl`): ~10 synthetic fixtures (you control ground truth — instant labeling) + ~15 real repos pinned to commit SHAs, manually verified. Each row: `{repo, sha, package, cve, expected_verdict, notes}`.
- `run_eval.py` computes: **precision / recall / F1** on `REACHABLE`, noise-reduction %, `hallucination_blocked` count, tool-call success rate, p50/p95 latency, cost per scan, mean step count.
- Confusion matrix output. **False negatives are the critical failure** — a missed reachable CVE is worse than a false alarm. Weight the analysis accordingly.
- Emits a Markdown table for the README.
- Wire into CI as a regression gate against local/Ollama so it runs without keys.

**Done when:** `uv run python evals/run_eval.py` prints a real metrics table, CI runs it, gate green.
**Commit:** `feat(evals): labeled benchmark with precision/recall regression harness`

### Phase 9 — Ship (~3h)
- **README:** one-line pitch → asciinema/GIF demo → Mermaid architecture diagram → quickstart (keyless) → **eval results table with real numbers** → how the trust boundary works → Known Limitations → v2 roadmap.
- **DESIGN.md ADRs:** (1) LLM-proposes/AST-verifies trust boundary; (2) three-state verdicts; (3) no graph framework for orchestration; (4) SQLite/diskcache defaults for keyless operation; (5) Python-only v1 scope.
- **Known Limitations** — state honestly: dynamic dispatch and reflection are statically undecidable; v1 analyzes first-party code only (a transitive dep may itself call the vulnerable path); advisories often lack function-level detail.
- **v2 roadmap:** multi-language, transitive-path analysis, Arq/Temporal queue, GitHub Action packaging, MCP server exposing the tools.
- Clean-clone smoke test on a fresh machine/container. Tag `v0.1.0`.

**Commit:** `docs: README with benchmark results, architecture, and limitations`

---

## 7. Time budget

| Day | Phases | Theme |
|---|---|---|
| 1 | 2, 3, 4 | Deterministic core — **zero LLM code all day** |
| 2 | 5, 6, 7 | Agent layer, verification, usable CLI |
| 3 | 8, 9 | Evaluation and ship |

If Day 1 slips, it will be Phase 4. Cut the stretch goal (step 6, caller tracing) before cutting anything else — direct call-site detection captures ~80% of the value.

---

## 8. Non-negotiables and scope-cut order

**Never cut — these three *are* the project:**
1. The AST reachability engine
2. The verification gate (`verify.py`)
3. The labeled eval set with real precision/recall

**Cut in this order if time runs short:**
1. Caller-path tracing (Phase 4 step 6) — call-site detection alone is shippable
2. FastAPI adapter (Phase 7) — CLI is the real product
3. SARIF export
4. Parallelism — go sequential; correct and slower beats broken
5. Postgres/Redis provider implementations — SQLite/diskcache are the defaults anyway
6. Real-repo eval rows — lean harder on synthetic fixtures (ground truth is free)

---

## 9. Known gotchas

- **Import names ≠ package names.** `pyyaml`→`yaml`, `beautifulsoup4`→`bs4`, `Pillow`→`PIL`, `scikit-learn`→`sklearn`, `msgpack-python`→`msgpack`. Getting this wrong produces silent false negatives — the worst failure mode, because it looks like success.
- **Never string-compare versions.** `"1.10" > "1.9"` is `False`. Use `packaging.version.Version`. Version-range bugs are the #1 source of false positives in vuln scanners.
- **Advisories are inconsistent prose.** Many name no function at all. Empty extraction → `NEEDS_REVIEW` is correct behavior, not a bug.
- **Exclude vendored code.** Scanning `.venv/` or `site-packages/` will find the vulnerable function *inside the library itself* and mark everything reachable. Exclusion list must be right.
- **Dynamic imports defeat static analysis.** `getattr`, `importlib.import_module`, `eval`, `__import__` → flag and route to `NEEDS_REVIEW`. Document this as a limitation; don't pretend to solve it.
- **Free-tier rate limits** will bite during eval runs. Cache hard; run the eval suite against Ollama locally.
- **Syntax errors in target repos** must never crash a scan. Record, skip, continue.
- **Namespace/relative imports** (`from . import x`) need care in the import-table resolver.

---

## 10. Definition of shipped (v1)

- [ ] Clean clone runs keyless: `git clone && uv sync && deptrace scan .`
- [ ] Three-state verdicts, every `REACHABLE` carrying real `file:line` evidence
- [ ] Verification gate provably blocks unsupported LLM claims (test exists)
- [ ] Eval table in README with **real measured** precision/recall/F1
- [ ] `mypy --strict`, `ruff`, `pytest` all green in CI
- [ ] Incremental, meaningful commit history
- [ ] README with diagram, demo GIF, and honest Known Limitations
- [ ] DESIGN.md with ADRs
- [ ] MIT licensed, tagged `v0.1.0`

---

## 11. Resume bullet (fill brackets only with measured values)

> Built and open-sourced **DepTrace**, an AI agent that triages dependency vulnerabilities by call-path reachability (Python, Pydantic AI, asyncio) — an async orchestrator fans out per-CVE sub-tasks whose LLM-proposed symbols are verified against a deterministic AST engine, cutting false-positive alerts by **[X]%** vs. manifest-only scanning. Benchmarked on a labeled dataset (**precision [X], recall [X]**) with CI regression gates, structured run tracing, and a hallucination-blocking verification layer.

**Interview framing:** the strongest answer is the trust boundary — "the model reads messy advisory prose and *proposes* which symbol is vulnerable; only static analysis can *prove* reachability, and the type system enforces that separation. I measure how often the gate catches unsupported claims."