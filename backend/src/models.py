from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


# --- NVD Data ---

class CVEData(BaseModel):
    cve_id: str
    description: str
    published: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


# --- Framework ---

class CSFSubcategory(BaseModel):
    id: str
    description: str


class CSFCategory(BaseModel):
    id: str
    name: str
    subcategories: list[CSFSubcategory] = Field(default_factory=list)


class CSFFunction(BaseModel):
    id: str
    name: str
    categories: list[CSFCategory] = Field(default_factory=list)


class CSFCatalog(BaseModel):
    framework: str
    version: str
    functions: list[CSFFunction]


class CSFControl(BaseModel):
    control_id: str
    function_id: str
    function_name: str
    category_id: str
    category_name: str
    description: str


# --- AI Analysis Output ---

class ControlMapping(BaseModel):
    control_id: str
    control_name: str
    confidence: float
    reasoning: str


class RiskAssessment(BaseModel):
    severity: str
    exploitability: str
    business_impact: str
    urgency: str


class Remediation(BaseModel):
    action: str
    priority: str
    effort: str
    details: str


class CVEAnalysisResult(BaseModel):
    cve: CVEData
    security_domains: list[str]
    domain_reasoning: str = ""
    control_mappings: list[ControlMapping]
    risk_assessment: RiskAssessment
    remediations: list[Remediation]
    analysis_timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# --- Report (legacy CVE-first) ---

class ReportSummary(BaseModel):
    total_cves: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    immediate_action_cves: list[str] = Field(default_factory=list)
    most_mapped_functions: dict[str, int] = Field(default_factory=dict)


class AssessmentReport(BaseModel):
    report_id: str
    generated_at: str
    framework: str = "NIST CSF 2.0"
    data_source: str = "NIST NVD API"
    summary: ReportSummary
    cve_analyses: list[CVEAnalysisResult]


# --- Control-first assessment (evidence source -> controls) ---

class EvidenceBundle(BaseModel):
    """Normalized evidence produced by a single data source / connector.

    This is the entry point of the control-first pipeline: a source collects
    raw data and condenses it into a summary the assessor reasons over to
    decide which controls it can evidence and whether they pass or fail.
    """
    source_name: str
    source_description: str
    scope: str = ""
    summary: str
    item_count: int = 0
    raw_excerpt: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


# Assessment status values
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_PARTIAL = "PARTIAL"
STATUS_NOT_ASSESSED = "NOT_ASSESSED"


class ControlAssessment(BaseModel):
    control_id: str
    control_name: str
    function_id: str
    function_name: str
    category_id: str = ""
    addressable: bool = False
    status: str = STATUS_NOT_ASSESSED
    confidence: float = 0.0
    evidence: str = ""
    gap: str = ""
    recommendation: str = ""


class CoverageSummary(BaseModel):
    total_controls: int
    addressable_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    partial_count: int = 0
    not_assessed_count: int = 0
    coverage_pct: float = 0.0       # addressable / total
    pass_rate_pct: float = 0.0      # pass / addressable
    by_function: dict[str, dict] = Field(default_factory=dict)


# --- Multi-source aggregation ---

class SourceContribution(BaseModel):
    """How much of the posture a single connected source accounts for."""
    source_name: str
    source_description: str = ""
    item_count: int = 0
    addressable_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    partial_count: int = 0
    coverage_pct: float = 0.0       # addressable / total framework controls


class AggregatedControl(BaseModel):
    """A control's posture merged across every connected source."""
    control_id: str
    control_name: str
    function_id: str
    function_name: str
    category_id: str = ""
    addressable: bool = False
    status: str = STATUS_NOT_ASSESSED
    confidence: float = 0.0
    evidenced_by: list[str] = Field(default_factory=list)
    evidence: str = ""
    gap: str = ""
    recommendation: str = ""


class AggregatedReport(BaseModel):
    report_id: str
    generated_at: str
    framework: str = "NIST CSF 2.0"
    scope: str = ""
    posture_grade: str = ""
    sources: list[SourceContribution] = Field(default_factory=list)
    summary: CoverageSummary
    controls: list[AggregatedControl] = Field(default_factory=list)
