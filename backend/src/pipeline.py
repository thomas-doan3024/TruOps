from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .assessor import ControlAssessor
from .config import Settings
from .framework import FrameworkCatalog
from .models import AggregatedReport, ControlAssessment, EvidenceBundle
from .nvd_client import NVDClient
from .report import build_aggregated_report, save_json, save_markdown
from .sources import DEMO_SOURCES, NVDEvidenceSource

# A progress event is a plain dict so any caller (CLI, API, tests) can render it.
Event = dict
EventCallback = Callable[[Event], None]


@dataclass
class AssessmentConfig:
    """Everything needed to run one control-first assessment.

    Mirrors the CLI options so the CLI, the HTTP API, and tests all drive the
    pipeline through the same surface.
    """

    scope: str = ""
    sources: list[str] = field(default_factory=lambda: ["nvd", "cloud", "idp"])
    severity: str = "HIGH"
    keyword: str | None = None
    max_cves: int = 15
    days_back: int = 120


@dataclass
class AssessmentResult:
    report: AggregatedReport
    json_path: str
    markdown_path: str


def _noop(_event: Event) -> None:
    pass


def run_assessment(
    settings: Settings,
    config: AssessmentConfig,
    on_event: EventCallback = _noop,
    catalog: FrameworkCatalog | None = None,
) -> AssessmentResult:
    """Run the control-first, multi-source assessment end to end.

    This is the single orchestration path shared by the CLI and the HTTP API:

      1. connect & collect an ``EvidenceBundle`` from each selected source,
      2. assess every NIST CSF 2.0 control per source (one LLM call per function),
      3. aggregate into a posture report and persist JSON + Markdown.

    Progress is reported through ``on_event`` so callers can render a terminal
    dashboard, stream Server-Sent Events, or ignore it. Event ``type`` values:
    ``catalog_loaded``, ``source_connecting``, ``source_connected``,
    ``source_skipped``, ``assessing``, ``aggregating``, ``done``, ``error``.
    """
    if catalog is None:
        catalog = FrameworkCatalog()
    functions = catalog.get_functions()
    on_event({
        "type": "catalog_loaded",
        "control_count": len(catalog.get_all_controls()),
        "function_count": len(functions),
        "scope": config.scope,
    })

    selected = [s.strip().lower() for s in config.sources if s.strip()]

    # --- Step 1: connect & collect evidence from each selected source ---
    bundles: list[EvidenceBundle] = []
    for key in selected:
        on_event({"type": "source_connecting", "source": key})
        if key == "nvd":
            nvd = NVDClient(settings)
            try:
                cves = nvd.fetch_cves(
                    severity=config.severity,
                    keyword=config.keyword,
                    max_results=config.max_cves,
                    days_back=config.days_back,
                )
            finally:
                nvd.close()
            if cves:
                bundle = NVDEvidenceSource(cves, scope=config.scope).build_bundle()
                bundles.append(bundle)
                on_event({
                    "type": "source_connected",
                    "source": bundle.source_name,
                    "item_count": bundle.item_count,
                })
            else:
                on_event({
                    "type": "source_skipped",
                    "source": key,
                    "reason": "NVD returned no CVEs for this filter.",
                })
        elif key in DEMO_SOURCES:
            bundle = DEMO_SOURCES[key](scope=config.scope).build_bundle()
            bundles.append(bundle)
            on_event({
                "type": "source_connected",
                "source": bundle.source_name,
                "item_count": bundle.item_count,
            })
        else:
            on_event({
                "type": "source_skipped",
                "source": key,
                "reason": f"Unknown source '{key}'.",
            })

    if not bundles:
        raise RuntimeError("No evidence sources produced data. Nothing to assess.")

    # --- Step 2: control-first assessment per source ---
    assessor = ControlAssessor(settings, catalog)
    per_source: list[tuple[EvidenceBundle, list[ControlAssessment]]] = []
    for bundle in bundles:
        assessments: list[ControlAssessment] = []
        for idx, (func_id, func_name) in enumerate(functions, start=1):
            on_event({
                "type": "assessing",
                "source": bundle.source_name,
                "func_id": func_id,
                "func_name": func_name,
                "completed": idx,
                "total": len(functions),
            })
            assessments.extend(assessor.assess_function(bundle, func_id, func_name))
        per_source.append((bundle, assessments))

    # --- Step 3: aggregate & persist ---
    on_event({"type": "aggregating"})
    report = build_aggregated_report(config.scope, per_source)
    json_path = save_json(report, settings.output_dir)
    md_path = save_markdown(report, settings.output_dir)

    on_event({
        "type": "done",
        "report_id": report.report_id,
        "posture_grade": report.posture_grade,
    })

    return AssessmentResult(report=report, json_path=str(json_path), markdown_path=str(md_path))
