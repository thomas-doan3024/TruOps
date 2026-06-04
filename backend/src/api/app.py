from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from ..config import Settings
from ..framework import FrameworkCatalog
from ..pipeline import AssessmentConfig
from ..report import FUNC_NAMES, FUNC_ORDER, GAP_INTEGRATIONS
from ..sources import DEMO_SOURCES, CloudConfigEvidenceSource, IdentityProviderEvidenceSource, NVDEvidenceSource
from .jobs import JobStore

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NIST CSF 2.0 Compliance Posture API",
    description="HTTP API around the control-first, multi-source AI assessment pipeline.",
    version="1.0.0",
)

# Local dev origins, plus any extra origins from the FRONTEND_ORIGINS env var
# (comma-separated) so the deployed Vercel domain can be added without a code change.
_dev_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]
_env_origins = [o.strip() for o in os.environ.get("FRONTEND_ORIGINS", "").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_dev_origins + _env_origins,
    # Allow Vercel production and preview deployments (e.g. tru-ops-git-*.vercel.app).
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- shared singletons (loaded once) ---

_catalog = FrameworkCatalog()


def _load_settings() -> Settings:
    """Load settings, surfacing a clear 503 when the OpenAI key is missing."""
    try:
        return Settings()  # type: ignore[call-arg]
    except Exception as e:  # pydantic ValidationError when OPENAI_API_KEY unset
        raise HTTPException(
            status_code=503,
            detail="Server is not configured: OPENAI_API_KEY is not set. "
                   "Copy .env.example to .env and add your key.",
        ) from e


# The store needs settings; build lazily so the server still boots without a key
# (health/framework endpoints work; starting a job fails loudly).
_store: JobStore | None = None


def _get_store() -> JobStore:
    global _store
    if _store is None:
        _store = JobStore(_load_settings())
    return _store


# --- request/response models ---

class StartAssessmentRequest(BaseModel):
    scope: str = ""
    sources: list[str] = Field(default_factory=lambda: ["nvd", "cloud", "idp"])
    severity: str = "HIGH"
    keyword: str | None = None
    max_cves: int = 15
    days_back: int = 120


# --- endpoints ---

@app.get("/api/health")
def health() -> dict:
    key_configured = True
    try:
        Settings()  # type: ignore[call-arg]
    except Exception:
        key_configured = False
    return {
        "status": "ok",
        "openai_key_configured": key_configured,
        "framework": "NIST CSF 2.0",
        "control_count": len(_catalog.get_all_controls()),
    }


@app.get("/api/framework")
def framework() -> dict:
    functions = []
    for fid in FUNC_ORDER:
        controls = _catalog.get_controls_by_function(fid)
        if not controls:
            continue
        categories: dict[str, dict] = {}
        for c in controls:
            categories.setdefault(c.category_id, {"id": c.category_id, "name": c.category_name, "control_count": 0})
            categories[c.category_id]["control_count"] += 1
        functions.append({
            "id": fid,
            "name": FUNC_NAMES.get(fid, fid),
            "control_count": len(controls),
            "categories": list(categories.values()),
        })
    return {
        "framework": "NIST CSF 2.0",
        "total_controls": len(_catalog.get_all_controls()),
        "functions": functions,
        "gap_integrations": GAP_INTEGRATIONS,
    }


@app.get("/api/sources")
def sources() -> dict:
    return {
        "sources": [
            {
                "key": "nvd",
                "name": NVDEvidenceSource.name,
                "description": NVDEvidenceSource.description,
                "live": True,
            },
            {
                "key": "cloud",
                "name": CloudConfigEvidenceSource.name,
                "description": CloudConfigEvidenceSource.description,
                "live": False,
            },
            {
                "key": "idp",
                "name": IdentityProviderEvidenceSource.name,
                "description": IdentityProviderEvidenceSource.description,
                "live": False,
            },
        ]
    }


@app.post("/api/assessments")
def start_assessment(req: StartAssessmentRequest) -> dict:
    selected = [s.strip().lower() for s in req.sources if s.strip()]
    valid = {"nvd", *DEMO_SOURCES.keys()}
    unknown = [s for s in selected if s not in valid]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown source(s): {', '.join(unknown)}")
    if not selected:
        raise HTTPException(status_code=400, detail="At least one source must be selected.")

    store = _get_store()  # raises 503 if no key
    config = AssessmentConfig(
        scope=req.scope,
        sources=selected,
        severity=req.severity,
        keyword=req.keyword,
        max_cves=req.max_cves,
        days_back=req.days_back,
    )
    job = store.start(config)
    return {"job_id": job.id, "status": job.status}


@app.get("/api/assessments")
def list_assessments() -> dict:
    """List past runs persisted to the output directory."""
    settings = _safe_settings()
    output_dir = settings.output_dir if settings else Path("output")
    runs = []
    if output_dir.exists():
        for path in sorted(output_dir.glob("report_*.json"), reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            summary = data.get("summary", {})
            runs.append({
                "report_id": data.get("report_id"),
                "file": path.name,
                "generated_at": data.get("generated_at"),
                "scope": data.get("scope", ""),
                "posture_grade": data.get("posture_grade"),
                "coverage_pct": summary.get("coverage_pct"),
                "pass_rate_pct": summary.get("pass_rate_pct"),
                "source_count": len(data.get("sources", [])),
            })
    return {"reports": runs}


@app.get("/api/assessments/{job_id}")
def get_assessment(job_id: str) -> dict:
    job = _require_job(job_id)
    return job.to_status()


@app.get("/api/assessments/{job_id}/events")
async def assessment_events(job_id: str):
    job = _require_job(job_id)

    async def event_publisher():
        # Poll the append-only events list without blocking the event loop.
        # The worker thread mutates job.events / job.status; list append and len
        # are safe to read under CPython's GIL. ~250ms latency is fine for a
        # progress UI, and avoids running a blocking generator on the loop.
        cursor = 0
        while True:
            events = job.events
            while cursor < len(events):
                event = events[cursor]
                cursor += 1
                yield {"event": event.get("type", "message"), "data": json.dumps(event)}
            if job.status in ("done", "error") and cursor >= len(job.events):
                return
            await asyncio.sleep(0.25)

    return EventSourceResponse(event_publisher())


@app.get("/api/reports/{report_id}")
def get_report(report_id: str) -> dict:
    """Fetch a saved aggregated report by its report_id from the output directory."""
    settings = _safe_settings()
    output_dir = settings.output_dir if settings else Path("output")
    if output_dir.exists():
        for path in sorted(output_dir.glob("report_*.json"), reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if data.get("report_id") == report_id:
                return data
    raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")


# --- helpers ---

def _safe_settings() -> Settings | None:
    try:
        return Settings()  # type: ignore[call-arg]
    except Exception:
        return None


def _require_job(job_id: str):
    store = _get_store()
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    return job
