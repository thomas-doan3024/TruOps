from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from .models import (
    STATUS_FAIL,
    STATUS_NOT_ASSESSED,
    STATUS_PARTIAL,
    STATUS_PASS,
    AggregatedControl,
    AggregatedReport,
    ControlAssessment,
    CoverageSummary,
    EvidenceBundle,
    SourceContribution,
)

FUNC_ORDER = ["GV", "ID", "PR", "DE", "RS", "RC"]
FUNC_NAMES = {"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect", "RS": "Respond", "RC": "Recover"}
STATUS_LABEL = {STATUS_PASS: "PASS", STATUS_FAIL: "FAIL", STATUS_PARTIAL: "PARTIAL", STATUS_NOT_ASSESSED: "n/a"}
STATUS_MD = {STATUS_PASS: "✅ PASS", STATUS_FAIL: "❌ FAIL", STATUS_PARTIAL: "⚠️ PARTIAL", STATUS_NOT_ASSESSED: "— n/a"}
# Worst-status-wins precedence: a failing signal from any source dominates the merged posture.
STATUS_RANK = {STATUS_FAIL: 3, STATUS_PARTIAL: 2, STATUS_PASS: 1, STATUS_NOT_ASSESSED: 0}

# Suggested connector to close gaps, keyed by CSF function.
GAP_INTEGRATIONS = {
    "GV": "GRC / policy-management platform (e.g. risk register, policy docs)",
    "ID": "Asset inventory / CMDB and data-classification tooling",
    "PR": "Endpoint protection, DLP, and configuration-management sources",
    "DE": "SIEM / log analytics and detection-engineering telemetry",
    "RS": "Incident-response / ticketing platform (e.g. PagerDuty, ServiceNow)",
    "RC": "Backup / disaster-recovery and business-continuity tooling",
}


# --- aggregation ---

def build_aggregated_report(
    scope: str,
    per_source: list[tuple[EvidenceBundle, list[ControlAssessment]]],
) -> AggregatedReport:
    """Merge per-source assessments into one cross-source posture view.

    A control is addressable if ANY source can evidence it; its merged status is
    the worst status reported by any source that addressed it (a fail anywhere
    means the control is not satisfied).
    """
    # Per-source contributions
    contributions: list[SourceContribution] = []
    total_controls = len(per_source[0][1]) if per_source else 0

    merged: dict[str, AggregatedControl] = {}
    order: list[str] = []

    for bundle, assessments in per_source:
        total_controls = max(total_controls, len(assessments))
        addr = pas = fail = part = 0
        for a in assessments:
            if a.control_id not in merged:
                merged[a.control_id] = AggregatedControl(
                    control_id=a.control_id,
                    control_name=a.control_name,
                    function_id=a.function_id,
                    function_name=a.function_name,
                    category_id=a.category_id,
                )
                order.append(a.control_id)
            agg = merged[a.control_id]

            if a.addressable:
                addr += 1
                if a.status == STATUS_PASS:
                    pas += 1
                elif a.status == STATUS_FAIL:
                    fail += 1
                elif a.status == STATUS_PARTIAL:
                    part += 1

                agg.addressable = True
                if bundle.source_name not in agg.evidenced_by:
                    agg.evidenced_by.append(bundle.source_name)
                # Worst-status-wins; record the driving evidence from that source.
                if STATUS_RANK[a.status] > STATUS_RANK.get(agg.status, 0):
                    agg.status = a.status
                    agg.evidence = a.evidence
                    agg.recommendation = a.recommendation
                agg.confidence = max(agg.confidence, a.confidence)
            elif not agg.addressable and not agg.gap:
                # Keep a gap hint until/unless a source covers it.
                agg.gap = a.gap

        contributions.append(SourceContribution(
            source_name=bundle.source_name,
            source_description=bundle.source_description,
            item_count=bundle.item_count,
            addressable_count=addr,
            pass_count=pas,
            fail_count=fail,
            partial_count=part,
            coverage_pct=round(100 * addr / total_controls, 1) if total_controls else 0.0,
        ))

    controls = [merged[cid] for cid in order]
    summary = _summarize(controls, total_controls)
    grade = _posture_grade(summary)

    return AggregatedReport(
        report_id=str(uuid.uuid4())[:8],
        generated_at=datetime.now(timezone.utc).isoformat(),
        scope=scope,
        posture_grade=grade,
        sources=contributions,
        summary=summary,
        controls=controls,
    )


def _summarize(controls: list[AggregatedControl], total: int) -> CoverageSummary:
    addressable = [c for c in controls if c.addressable]
    pass_c = sum(1 for c in addressable if c.status == STATUS_PASS)
    fail_c = sum(1 for c in addressable if c.status == STATUS_FAIL)
    part_c = sum(1 for c in addressable if c.status == STATUS_PARTIAL)

    by_function: dict[str, dict] = defaultdict(lambda: {"total": 0, "addressable": 0, "pass": 0, "fail": 0, "partial": 0})
    for c in controls:
        b = by_function[c.function_id]
        b["total"] += 1
        if c.addressable:
            b["addressable"] += 1
            if c.status == STATUS_PASS:
                b["pass"] += 1
            elif c.status == STATUS_FAIL:
                b["fail"] += 1
            elif c.status == STATUS_PARTIAL:
                b["partial"] += 1

    return CoverageSummary(
        total_controls=total,
        addressable_count=len(addressable),
        pass_count=pass_c,
        fail_count=fail_c,
        partial_count=part_c,
        not_assessed_count=total - len(addressable),
        coverage_pct=round(100 * len(addressable) / total, 1) if total else 0.0,
        pass_rate_pct=round(100 * pass_c / len(addressable), 1) if addressable else 0.0,
        by_function=dict(by_function),
    )


def _posture_grade(s: CoverageSummary) -> str:
    """A simple, defensible posture grade blending coverage and pass rate."""
    if s.addressable_count == 0:
        return "N/A"
    score = 0.5 * s.coverage_pct + 0.5 * s.pass_rate_pct
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# --- persistence ---

def save_json(report: BaseModel, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"report_{ts}.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def save_markdown(report: AggregatedReport, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"report_{ts}.md"
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


# --- rendering ---

def _bar(pct: float, width: int = 24) -> str:
    filled = round(width * pct / 100)
    return "█" * filled + "░" * (width - filled)


def render_markdown(report: AggregatedReport) -> str:
    s = report.summary
    lines = [
        "# NIST CSF 2.0 Compliance Posture Report",
        "",
        f"**Generated:** {report.generated_at[:19].replace('T', ' ')} UTC &nbsp;|&nbsp; "
        f"**Framework:** {report.framework} &nbsp;|&nbsp; **Report ID:** `{report.report_id}`",
    ]
    if report.scope:
        lines.append(f"**Scope:** {report.scope}")
    lines += [
        "",
        f"## Posture Grade: {report.posture_grade}",
        "",
        f"```",
        f"Control coverage   {s.coverage_pct:>5.1f}%  {_bar(s.coverage_pct)}  {s.addressable_count}/{s.total_controls} controls",
        f"Pass rate          {s.pass_rate_pct:>5.1f}%  {_bar(s.pass_rate_pct)}  {s.pass_count}/{s.addressable_count} assessed",
        f"```",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Connected sources | {len(report.sources)} |",
        f"| Controls in framework | {s.total_controls} |",
        f"| Controls evidenced | {s.addressable_count} ({s.coverage_pct}%) |",
        f"| ✅ Passing | {s.pass_count} |",
        f"| ❌ Failing | {s.fail_count} |",
        f"| ⚠️ Partial | {s.partial_count} |",
        f"| Coverage gaps (no source) | {s.not_assessed_count} |",
        "",
    ]

    # Source contributions — the integration story
    lines.append("## Connected Sources")
    lines.append("")
    lines.append("Each connected source raises coverage. Add more integrations to close the gaps below.")
    lines.append("")
    lines.append("| Source | Evidence items | Controls evidenced | Pass | Fail | Partial |")
    lines.append("|--------|---------------:|-------------------:|-----:|-----:|--------:|")
    for c in report.sources:
        lines.append(
            f"| {c.source_name} | {c.item_count} | {c.addressable_count} ({c.coverage_pct}%) | "
            f"{c.pass_count} | {c.fail_count} | {c.partial_count} |"
        )
    lines.append("")

    # Coverage by function
    lines.append("## Coverage by CSF Function")
    lines.append("")
    lines.append("| Function | Controls | Evidenced | Coverage | Pass | Fail | Partial |")
    lines.append("|----------|---------:|----------:|----------|-----:|-----:|--------:|")
    for fid in FUNC_ORDER:
        b = s.by_function.get(fid)
        if not b:
            continue
        pct = round(100 * b["addressable"] / b["total"], 0) if b["total"] else 0
        lines.append(
            f"| {fid} — {FUNC_NAMES[fid]} | {b['total']} | {b['addressable']} | {_bar(pct, 12)} {pct:.0f}% | "
            f"{b['pass']} | {b['fail']} | {b['partial']} |"
        )
    lines.append("")

    # Failing controls first — the action list
    failing = [c for c in report.controls if c.status == STATUS_FAIL]
    if failing:
        lines.append("---")
        lines.append("")
        lines.append(f"## ❌ Failing Controls — Priority Remediation ({len(failing)})")
        lines.append("")
        lines.append("| Control | Evidenced by | Finding | Recommendation |")
        lines.append("|---------|--------------|---------|----------------|")
        for c in sorted(failing, key=lambda x: x.control_id):
            srcs = ", ".join(c.evidenced_by)
            lines.append(
                f"| **{c.control_id}** {c.control_name[:46]} | {srcs} | {c.evidence[:120]} | {c.recommendation[:120]} |"
            )
        lines.append("")

    # All assessed controls
    assessed = [c for c in report.controls if c.addressable]
    lines.append("---")
    lines.append("")
    lines.append(f"## All Assessed Controls ({len(assessed)})")
    lines.append("")
    lines.append("| Control | Status | Conf. | Evidenced by | Evidence |")
    lines.append("|---------|--------|------:|--------------|----------|")
    for c in sorted(assessed, key=lambda x: (STATUS_RANK.get(x.status, 0) * -1, x.control_id)):
        srcs = ", ".join(c.evidenced_by)
        lines.append(
            f"| **{c.control_id}** {c.control_name[:42]} | {STATUS_MD.get(c.status, c.status)} | "
            f"{c.confidence:.0%} | {srcs} | {c.evidence[:110]} |"
        )
    lines.append("")

    # Coverage gaps grouped by function with suggested integrations
    gaps = [c for c in report.controls if not c.addressable]
    lines.append("---")
    lines.append("")
    lines.append(f"## Coverage Gaps — Add Integrations to Close ({len(gaps)})")
    lines.append("")
    if gaps:
        by_func_gaps: dict[str, list[AggregatedControl]] = defaultdict(list)
        for c in gaps:
            by_func_gaps[c.function_id].append(c)
        for fid in FUNC_ORDER:
            items = by_func_gaps.get(fid)
            if not items:
                continue
            suggest = GAP_INTEGRATIONS.get(fid, "an additional evidence source")
            lines.append(f"### {fid} — {FUNC_NAMES[fid]} ({len(items)} uncovered)")
            lines.append(f"> **Suggested integration:** {suggest}")
            lines.append("")
            ids = ", ".join(c.control_id for c in items)
            lines.append(f"Uncovered controls: {ids}")
            lines.append("")
    else:
        lines.append("_No gaps — every control is evidenced by at least one source._")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_Generated by the NIST CSF 2.0 Compliance Posture Pipeline. "
                 "Coverage and pass/fail are AI-assessed from connected evidence sources and should be "
                 "reviewed by a qualified assessor._")

    return "\n".join(lines)
