from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure the bar/emoji glyphs render on Windows consoles (cp1252) without crashing.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:
        pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import Settings
from .models import STATUS_FAIL
from .pipeline import AssessmentConfig, run_assessment
from .report import FUNC_NAMES, FUNC_ORDER, _bar

app = typer.Typer(
    name="nist-csf-assess",
    help="AI-powered NIST CSF 2.0 compliance posture assessment (control-first, multi-source)",
    add_completion=False,
)
console = Console()

GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "bold red", "N/A": "dim"}


@app.command()
def run(
    scope: str = typer.Option(
        "", "--scope", help="Asset scope for the assessment (e.g. 'public-facing Apache/nginx web servers')"
    ),
    sources: str = typer.Option(
        "nvd,cloud,idp", "--sources",
        help="Comma-separated evidence sources: nvd, cloud, idp. Add sources to raise coverage.",
    ),
    severity: str = typer.Option("HIGH", "--severity", help="CVSS severity filter for the NVD source"),
    keyword: str = typer.Option(None, "--keyword", help="Keyword filter for NVD, to scope to assets (e.g. 'apache')"),
    max_cves: int = typer.Option(15, "--max-cves", help="Max CVEs to pull as evidence"),
    days_back: int = typer.Option(120, "--days-back", help="Fetch CVEs published in the last N days"),
    output_dir: str = typer.Option("output", "--output-dir", help="Output directory for reports"),
) -> None:
    """Control-first, multi-source pipeline: connect evidence sources -> AI assesses which
    NIST CSF 2.0 controls each can evidence and whether they pass/fail -> aggregated posture report."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception:
        console.print("[red]Error: OPENAI_API_KEY not set. Copy .env.example to .env and add your key.[/red]")
        raise typer.Exit(1)

    settings.output_dir = Path(output_dir)
    config = AssessmentConfig(
        scope=scope,
        sources=[s.strip().lower() for s in sources.split(",") if s.strip()],
        severity=severity,
        keyword=keyword,
        max_cves=max_cves,
        days_back=days_back,
    )

    console.print(Panel.fit(
        "[bold]NIST CSF 2.0 Compliance Posture Assessment[/bold]\n"
        "[dim]Control-first · multi-source · AI-assessed[/dim]",
        border_style="cyan",
    ))

    # Drive the live Rich dashboard from the shared pipeline's progress events.
    progress = Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("{task.completed}/{task.total}"), console=console,
    )
    tasks: dict[str, int] = {}

    def on_event(event: dict) -> None:
        etype = event.get("type")
        if etype == "catalog_loaded":
            console.print(f"[green]✓[/green] Loaded [bold]{event['control_count']}[/bold] NIST CSF 2.0 controls "
                          f"across {event['function_count']} functions")
            if event.get("scope"):
                console.print(f"[green]✓[/green] Scope: [italic]{event['scope']}[/italic]")
        elif etype == "source_connecting":
            console.print(f"[dim]  · connecting {event['source']}…[/dim]")
        elif etype == "source_connected":
            console.print(f"[green]✓[/green] Connected [bold]{event['source']}[/bold] — "
                          f"{event['item_count']} evidence item(s)")
        elif etype == "source_skipped":
            console.print(f"[yellow]  ! {event['source']} skipped — {event['reason']}[/yellow]")
        elif etype == "assessing":
            src = event["source"]
            if src not in tasks:
                tasks[src] = progress.add_task(f"Assessing controls · {src}", total=event["total"])
            progress.update(
                tasks[src],
                completed=event["completed"],
                description=f"Assessing {src} · {event['func_id']} {event['func_name']}",
            )

    try:
        with progress:
            result = run_assessment(settings, config, on_event=on_event)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    _print_dashboard(result.report)

    console.print(f"\n  [dim]JSON report:[/dim] {result.json_path}")
    console.print(f"  [dim]Markdown report:[/dim] {result.markdown_path}")


def _print_dashboard(report) -> None:
    s = report.summary
    grade_style = GRADE_STYLE.get(report.posture_grade, "bold")

    console.print()
    console.print(Panel(
        f"[{grade_style}]Posture Grade: {report.posture_grade}[/{grade_style}]\n\n"
        f"Coverage  [cyan]{_bar(s.coverage_pct)}[/cyan] {s.coverage_pct:>5.1f}%  "
        f"({s.addressable_count}/{s.total_controls} controls evidenced)\n"
        f"Pass rate [cyan]{_bar(s.pass_rate_pct)}[/cyan] {s.pass_rate_pct:>5.1f}%  "
        f"([green]{s.pass_count} pass[/green] · [red]{s.fail_count} fail[/red] · [yellow]{s.partial_count} partial[/yellow])",
        title="[bold]Compliance Posture[/bold]", border_style=grade_style.split()[-1], padding=(1, 2),
    ))

    # Source contributions
    src_table = Table(title="Connected Sources — Coverage Contribution", title_justify="left", header_style="bold")
    src_table.add_column("Source", style="cyan")
    src_table.add_column("Evidence", justify="right")
    src_table.add_column("Evidenced", justify="right")
    src_table.add_column("Pass", justify="right", style="green")
    src_table.add_column("Fail", justify="right", style="red")
    src_table.add_column("Partial", justify="right", style="yellow")
    for c in report.sources:
        src_table.add_row(
            c.source_name, str(c.item_count), f"{c.addressable_count} ({c.coverage_pct}%)",
            str(c.pass_count), str(c.fail_count), str(c.partial_count),
        )
    console.print(src_table)

    # Coverage by function
    fn_table = Table(title="Coverage by CSF Function", title_justify="left", header_style="bold")
    fn_table.add_column("Function", style="cyan")
    fn_table.add_column("Coverage", justify="left")
    fn_table.add_column("Pass", justify="right", style="green")
    fn_table.add_column("Fail", justify="right", style="red")
    fn_table.add_column("Partial", justify="right", style="yellow")
    for fid in FUNC_ORDER:
        b = s.by_function.get(fid)
        if not b:
            continue
        pct = round(100 * b["addressable"] / b["total"], 0) if b["total"] else 0
        fn_table.add_row(
            f"{fid} {FUNC_NAMES[fid]}", f"{_bar(pct, 12)} {pct:.0f}%",
            str(b["pass"]), str(b["fail"]), str(b["partial"]),
        )
    console.print(fn_table)

    # Failing controls — the action list
    failing = [c for c in report.controls if c.status == STATUS_FAIL]
    if failing:
        fail_table = Table(title="❌ Priority Remediation — Failing Controls", title_justify="left", header_style="bold red")
        fail_table.add_column("Control", style="cyan")
        fail_table.add_column("Evidenced by")
        fail_table.add_column("Finding", max_width=64)
        for c in sorted(failing, key=lambda x: x.control_id):
            fail_table.add_row(c.control_id, ", ".join(c.evidenced_by), c.evidence[:64])
        console.print(fail_table)

    gaps = sum(1 for c in report.controls if not c.addressable)
    console.print(
        f"\n[bold]{gaps}[/bold] control(s) have no evidence source yet — "
        f"[dim]see 'Coverage Gaps' in the report for suggested integrations.[/dim]"
    )


if __name__ == "__main__":
    app()
