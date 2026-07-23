"""The DepTrace command line — the primary interface.

    deptrace scan .                    triage this project
    deptrace scan . --format sarif     emit for GitHub code scanning
    deptrace scan . --offline          cache only, no network at all
    deptrace history                   past scans

**Exit codes are the contract**, because the point of this tool is to be a
CI gate:

    0   clean — nothing reachable
    1   reachable findings present (or --fail-on any matched)
    2   the scan itself failed

Anything that returns 1 should block a merge; anything returning 2 is a bug
in the scan, not a verdict about the code, and must be distinguishable.
"""

from __future__ import annotations

import asyncio
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from deptrace.core.orchestrator import scan as run_scan
from deptrace.core.state import RunState
from deptrace.providers.llm.base import SymbolExtraction, SymbolExtractor, config_from_env
from deptrace.providers.llm.extractor import LLMSymbolExtractor
from deptrace.providers.store.sqlite import SQLiteStateStore
from deptrace.providers.vulndb.osv import OSVProvider
from deptrace.report import RENDERERS, render_table

app = typer.Typer(
    name="deptrace",
    help="Triage dependency CVEs by call-path reachability.",
    no_args_is_help=True,
    add_completion=False,
)

# Reports go to stdout so they can be piped; progress and errors go to
# stderr so `deptrace scan . --format json > out.json` stays valid JSON.
out = Console()
err = Console(stderr=True)


class Format(StrEnum):
    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class FailOn(StrEnum):
    REACHABLE = "reachable"
    ANY = "any"
    NEVER = "never"


class ExitCode:
    CLEAN = 0
    FINDINGS = 1
    ERROR = 2


def _decide_exit_code(state: RunState, fail_on: FailOn) -> int:
    """Translate a scan result into a process exit code."""
    if fail_on is FailOn.NEVER:
        return ExitCode.CLEAN
    if fail_on is FailOn.ANY:
        return ExitCode.FINDINGS if state.findings else ExitCode.CLEAN
    return ExitCode.FINDINGS if state.metrics.reachable else ExitCode.CLEAN


@app.command()
def scan(
    path: Annotated[
        Path, typer.Argument(help="Path to the Python project to scan.")
    ] = Path("."),
    output_format: Annotated[
        Format, typer.Option("--format", "-f", help="Output format.")
    ] = Format.TABLE,
    fail_on: Annotated[
        FailOn, typer.Option("--fail-on", help="When to exit non-zero.")
    ] = FailOn.REACHABLE,
    offline: Annotated[
        bool, typer.Option("--offline", help="Use cached advisories only; no network.")
    ] = False,
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="LLM provider: ollama, groq, or gemini."),
    ] = None,
    concurrency: Annotated[
        int, typer.Option("--concurrency", "-c", help="Parallel triage tasks.")
    ] = 8,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show not-reachable findings too.")
    ] = False,
    no_llm: Annotated[
        bool,
        typer.Option(
            "--no-llm",
            help="Skip symbol extraction; report advisories without reachability.",
        ),
    ] = False,
    no_save: Annotated[
        bool, typer.Option("--no-save", help="Do not persist this scan.")
    ] = False,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file.")
    ] = None,
) -> None:
    """Scan a project and report which vulnerabilities are actually reachable."""
    target = path.resolve()
    if not target.is_dir():
        err.print(f"[red]Error:[/red] {target} is not a directory.")
        raise typer.Exit(ExitCode.ERROR)

    try:
        state = asyncio.run(
            _run(
                target,
                offline=offline,
                provider=provider,
                concurrency=concurrency,
                no_llm=no_llm,
            )
        )
    except KeyboardInterrupt:
        err.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(ExitCode.ERROR) from None
    except Exception as exc:  # a scan failure is code 2, never a verdict
        err.print(f"[red]Scan failed:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(ExitCode.ERROR) from exc

    if not no_save:
        try:
            SQLiteStateStore().save(state)
        except Exception as exc:  # persistence is not worth failing a scan over
            err.print(f"[dim]Could not persist scan: {exc}[/dim]")

    _emit(state, output_format, output, verbose=verbose)
    raise typer.Exit(_decide_exit_code(state, fail_on))


class NullExtractor:
    """Makes no claims at all, so every finding lands in NEEDS_REVIEW.

    Not a stub: this is the honest degraded mode. It answers "which packages
    have advisories" — the question every other scanner answers — without
    pretending to know reachability. Useful when no model is available, and
    for isolating the deterministic layers when debugging.
    """

    name = "none"

    async def extract(
        self, *, package: str, vuln_id: str, summary: str, details: str
    ) -> SymbolExtraction:
        return SymbolExtraction()


async def _run(
    target: Path,
    *,
    offline: bool,
    provider: str | None,
    concurrency: int,
    no_llm: bool,
) -> RunState:
    """Wire the providers and run one scan."""
    vulndb = OSVProvider(offline=offline)
    extractor: SymbolExtractor = (
        NullExtractor() if no_llm else LLMSymbolExtractor(config=config_from_env(provider))
    )
    try:
        return await run_scan(
            target, vulndb=vulndb, extractor=extractor, concurrency=concurrency
        )
    finally:
        await vulndb.aclose()


def _emit(
    state: RunState, output_format: Format, output: Path | None, *, verbose: bool
) -> None:
    """Render to stdout or to a file."""
    if output_format is Format.TABLE:
        if output is not None:
            console = Console(file=output.open("w"), force_terminal=False)
            render_table(state, console=console, verbose=verbose)
        else:
            render_table(state, console=out, verbose=verbose)
        return

    text = RENDERERS[output_format.value](state)
    if output is not None:
        output.write_text(text)
        err.print(f"[dim]Wrote {output_format.value} report to {output}[/dim]")
    else:
        # print() rather than Console.print: Rich would wrap and colorize
        # machine-readable output.
        sys.stdout.write(text + "\n")


@app.command()
def history(
    limit: Annotated[int, typer.Option("--limit", "-n", help="How many scans.")] = 10,
) -> None:
    """List previous scans stored locally."""
    try:
        scans = SQLiteStateStore().list_scans(limit=limit)
    except Exception as exc:
        err.print(f"[red]Could not read scan history:[/red] {exc}")
        raise typer.Exit(ExitCode.ERROR) from exc

    if not scans:
        out.print("No scans recorded yet.")
        return

    from rich.table import Table

    table = Table(title="Scan history")
    table.add_column("SCAN ID", style="cyan", no_wrap=True)
    table.add_column("WHEN", no_wrap=True)
    table.add_column("TARGET")
    table.add_column("REACHABLE", justify="right")
    table.add_column("ADVISORIES", justify="right")

    for state in scans:
        table.add_row(
            state.scan_id,
            state.created_at.strftime("%Y-%m-%d %H:%M"),
            state.target,
            str(state.metrics.reachable),
            str(state.metrics.total_vulnerabilities),
        )
    out.print(table)


@app.command()
def show(
    scan_id: Annotated[str, typer.Argument(help="A scan id from `deptrace history`.")],
    output_format: Annotated[
        Format, typer.Option("--format", "-f", help="Output format.")
    ] = Format.TABLE,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show not-reachable findings too.")
    ] = False,
) -> None:
    """Re-display a stored scan without re-running it."""
    state = SQLiteStateStore().load(scan_id)
    if state is None:
        err.print(f"[red]No scan found with id {scan_id}.[/red]")
        raise typer.Exit(ExitCode.ERROR)

    _emit(state, output_format, None, verbose=verbose)


@app.command()
def providers() -> None:
    """Show which LLM provider is currently selected, and why."""
    config = config_from_env()
    out.print(f"[bold]Provider:[/bold] {config.provider}")
    out.print(f"[bold]Model:[/bold]    {config.model}")
    out.print(f"[bold]Endpoint:[/bold] {config.base_url}")
    out.print(f"[bold]API key:[/bold]  {'set' if config.api_key else 'not needed'}")
    if config.provider == "ollama":
        out.print(
            "\n[dim]Running keyless against a local model. "
            "Set GROQ_API_KEY or GEMINI_API_KEY for better extraction quality.[/dim]"
        )


def main() -> None:  # pragma: no cover - console-script shim
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
