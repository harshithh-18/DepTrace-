"""Rendering a `RunState` into the formats humans and machines consume.

Four outputs, each with a distinct audience:

    table     a developer reading a terminal
    json      another program, or a later diff
    markdown  a PR comment or a report checked into a repo
    sarif     GitHub code scanning, which ingests SARIF natively

Every renderer is a pure function of `RunState`. None of them re-derive a
verdict or re-run analysis — by this point the verdicts are settled, and a
reporter that could change one would be a second, unaudited decision point.

The guiding rule for all four: **a finding a human cannot check is worth
nothing.** Every REACHABLE row carries the `file:line` that proves it.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table

from deptrace.core.state import Finding, RunState, Verdict

# Severity ordering for display. OSV gives either a GitHub label or a raw
# CVSS vector; only the labels are worth ranking.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}

_VERDICT_STYLE = {
    Verdict.REACHABLE: "bold red",
    Verdict.NEEDS_REVIEW: "yellow",
    Verdict.NOT_REACHABLE: "dim green",
}

_VERDICT_LABEL = {
    Verdict.REACHABLE: "REACHABLE",
    Verdict.NEEDS_REVIEW: "NEEDS REVIEW",
    Verdict.NOT_REACHABLE: "NOT REACHABLE",
}


def _location(finding: Finding) -> str:
    """The single most useful cell in the table: where to look."""
    if not finding.evidence:
        return "—"
    first = finding.evidence[0]
    text = f"{first.file}:{first.line}"
    if len(finding.evidence) > 1:
        text += f" (+{len(finding.evidence) - 1})"
    return text


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Actionable first, then by severity, then stable by name.

    A developer reads the top of the table and stops. Anything requiring a
    scroll to discover a REACHABLE finding is a reporting failure.
    """
    order = {Verdict.REACHABLE: 0, Verdict.NEEDS_REVIEW: 1, Verdict.NOT_REACHABLE: 2}
    return sorted(
        findings,
        key=lambda f: (
            order.get(f.verdict, 3),
            _SEVERITY_RANK.get((f.vulnerability.severity or "").upper(), 4),
            f.dependency.name,
            f.vulnerability.id,
        ),
    )


def render_table(state: RunState, *, console: Console | None = None, verbose: bool = False) -> None:
    """Print the findings table to a terminal."""
    out = console or Console()

    if not state.findings:
        out.print(
            f"[green]No known vulnerabilities[/green] across "
            f"{state.metrics.total_dependencies} dependencies."
        )
        return

    table = Table(title=f"DepTrace — {state.target}", title_style="bold")
    table.add_column("PACKAGE", style="cyan", no_wrap=True)
    table.add_column("VULNERABILITY", no_wrap=True)
    table.add_column("SEV", no_wrap=True)
    table.add_column("VERDICT", no_wrap=True)
    table.add_column("WHERE")

    findings = sort_findings(state.findings)
    shown = findings if verbose else [f for f in findings if f.verdict is not Verdict.NOT_REACHABLE]

    for finding in shown:
        table.add_row(
            f"{finding.dependency.name} {finding.dependency.version or ''}".strip(),
            finding.vulnerability.id,
            (finding.vulnerability.severity or "—")[:8],
            f"[{_VERDICT_STYLE[finding.verdict]}]{_VERDICT_LABEL[finding.verdict]}[/]",
            _location(finding),
        )

    out.print(table)

    hidden = len(findings) - len(shown)
    if hidden:
        out.print(f"[dim]{hidden} not-reachable finding(s) hidden; use --verbose to show.[/dim]")

    _print_summary(state, out)


def _print_summary(state: RunState, out: Console) -> None:
    """The line a CI log reader actually reads."""
    metrics = state.metrics
    out.print(
        f"\n[bold]{metrics.reachable}[/bold] reachable · "
        f"[bold]{metrics.needs_review}[/bold] needs review · "
        f"[bold]{metrics.not_reachable}[/bold] not reachable "
        f"of {metrics.total_vulnerabilities} advisories "
        f"across {metrics.total_dependencies} dependencies"
    )
    if metrics.total_vulnerabilities:
        out.print(
            f"[green]Noise reduction: {metrics.noise_reduction:.0%}[/green] "
            f"— alerts shown to be unreachable."
        )
    if metrics.hallucination_blocked:
        out.print(
            f"[yellow]Verification gate blocked "
            f"{metrics.hallucination_blocked} unsupported claim(s).[/yellow]"
        )


def render_json(state: RunState) -> str:
    """Full machine-readable state, including evidence and step log."""
    return state.model_dump_json(indent=2)


def render_markdown(state: RunState) -> str:
    """A report suitable for a PR comment or a checked-in file."""
    metrics = state.metrics
    lines = [
        "# DepTrace Report",
        "",
        f"**Target:** `{state.target}`  ",
        f"**Scan:** `{state.scan_id}`",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Dependencies | {metrics.total_dependencies} |",
        f"| Advisories | {metrics.total_vulnerabilities} |",
        f"| Reachable | **{metrics.reachable}** |",
        f"| Needs review | {metrics.needs_review} |",
        f"| Not reachable | {metrics.not_reachable} |",
        f"| Noise reduction | {metrics.noise_reduction:.0%} |",
        f"| Unsupported claims blocked | {metrics.hallucination_blocked} |",
        "",
    ]

    if not state.findings:
        lines.append("No known vulnerabilities found.")
        return "\n".join(lines)

    lines += [
        "## Findings",
        "",
        "| Package | Vulnerability | Severity | Verdict | Location |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in sort_findings(state.findings):
        lines.append(
            f"| `{finding.dependency.name}` "
            f"| {finding.vulnerability.id} "
            f"| {finding.vulnerability.severity or '—'} "
            f"| {_VERDICT_LABEL[finding.verdict]} "
            f"| {_location(finding)} |"
        )

    reachable = [f for f in state.findings if f.verdict is Verdict.REACHABLE]
    if reachable:
        lines += ["", "## Reachable findings", ""]
        for finding in sort_findings(reachable):
            lines += [
                f"### {finding.vulnerability.id} — `{finding.dependency.name}`",
                "",
                f"{finding.vulnerability.summary}",
                "",
                f"- **Why:** {finding.rationale}",
            ]
            if finding.vulnerability.fixed_version:
                lines.append(f"- **Fix:** upgrade to `{finding.vulnerability.fixed_version}`")
            for item in finding.evidence[:5]:
                lines.append(f"- `{item.file}:{item.line}` — `{item.snippet or item.symbol}`")
            lines.append("")

    return "\n".join(lines)


def render_sarif(state: RunState) -> str:
    """SARIF 2.1.0, which GitHub code scanning ingests directly.

    Only REACHABLE and NEEDS_REVIEW findings become results. Emitting
    not-reachable findings would reintroduce exactly the alert fatigue this
    tool exists to remove.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for finding in sort_findings(state.findings):
        if finding.verdict is Verdict.NOT_REACHABLE:
            continue

        rule_id = finding.vulnerability.id
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {
                        "text": finding.vulnerability.summary or rule_id
                    },
                    "fullDescription": {
                        "text": (finding.vulnerability.details or "")[:1000]
                    },
                    "helpUri": (
                        finding.vulnerability.references[0]
                        if finding.vulnerability.references
                        else f"https://osv.dev/vulnerability/{rule_id}"
                    ),
                    "properties": {
                        "security-severity": _sarif_severity(
                            finding.vulnerability.severity
                        ),
                        "tags": ["security", "dependency"],
                    },
                }
            )

        # SARIF requires a physical location. Findings without evidence are
        # anchored to the manifest that introduced the dependency.
        if finding.evidence:
            locations = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": item.file},
                        "region": {
                            "startLine": item.line,
                            "startColumn": max(item.column, 1),
                            "snippet": {"text": item.snippet or item.symbol},
                        },
                    }
                }
                for item in finding.evidence[:10]
            ]
        else:
            locations = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.dependency.source},
                        "region": {"startLine": 1},
                    }
                }
            ]

        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if finding.verdict is Verdict.REACHABLE else "warning",
                "message": {
                    "text": (
                        f"{finding.dependency.name} "
                        f"{finding.dependency.version or ''}: "
                        f"{finding.vulnerability.summary or rule_id}. "
                        f"{finding.rationale}"
                    ).strip()
                },
                "locations": locations,
                "properties": {
                    "verdict": finding.verdict.value,
                    "downgraded": finding.downgraded,
                },
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DepTrace",
                        "informationUri": "https://github.com/harshithh-18/DepTrace",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)


def _sarif_severity(severity: str | None) -> str:
    """Map a severity label to SARIF's 0-10 numeric scale."""
    return {
        "CRITICAL": "9.0",
        "HIGH": "7.5",
        "MODERATE": "5.0",
        "MEDIUM": "5.0",
        "LOW": "3.0",
    }.get((severity or "").upper(), "5.0")


RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "sarif": render_sarif,
}
