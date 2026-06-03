from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..config import Settings
from ..models import AggregatedReport
from ..pipeline import AssessmentConfig, run_assessment

logger = logging.getLogger(__name__)


@dataclass
class Job:
    """A single assessment run tracked in memory.

    The pipeline is blocking (NVD rate-limit sleeps + synchronous OpenAI calls),
    so each job runs on its own thread. ``events`` is the full, append-only
    history; SSE subscribers walk it with a cursor and wait on ``_cond`` for new
    entries, so any number of clients (including late ones) see every event.
    """

    id: str
    config: AssessmentConfig
    status: str = "pending"  # pending | running | done | error
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    events: list[dict] = field(default_factory=list)
    report: AggregatedReport | None = None
    report_id: str | None = None
    error: str | None = None
    _cond: threading.Condition = field(default_factory=threading.Condition, repr=False)

    def to_status(self) -> dict:
        return {
            "job_id": self.id,
            "status": self.status,
            "created_at": self.created_at,
            "config": {
                "scope": self.config.scope,
                "sources": self.config.sources,
                "severity": self.config.severity,
                "keyword": self.config.keyword,
                "max_cves": self.config.max_cves,
                "days_back": self.config.days_back,
            },
            "report_id": self.report_id,
            "error": self.error,
            "report": self.report.model_dump() if self.report else None,
        }


class JobStore:
    """Thread-safe registry of assessment jobs with background execution."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def start(self, config: AssessmentConfig) -> Job:
        job = Job(id=str(uuid.uuid4())[:8], config=config)
        with self._lock:
            self._jobs[job.id] = job
        thread = threading.Thread(target=self._run, args=(job,), daemon=True)
        thread.start()
        return job

    def _emit(self, job: Job, event: dict) -> None:
        with job._cond:
            job.events.append(event)
            job._cond.notify_all()

    def _set_status(self, job: Job, status: str) -> None:
        with job._cond:
            job.status = status
            job._cond.notify_all()

    def _run(self, job: Job) -> None:
        self._set_status(job, "running")
        self._emit(job, {"type": "status", "status": "running"})
        try:
            result = run_assessment(
                self._settings,
                job.config,
                on_event=lambda e: self._emit(job, e),
            )
            job.report = result.report
            job.report_id = result.report.report_id
            self._set_status(job, "done")
            self._emit(job, {"type": "status", "status": "done", "report_id": job.report_id})
        except Exception as e:  # noqa: BLE001 - surface any failure to the client
            logger.exception("Assessment job %s failed", job.id)
            job.error = str(e)
            self._set_status(job, "error")
            self._emit(job, {"type": "error", "message": str(e)})
