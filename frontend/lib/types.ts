// TypeScript mirrors of the backend Pydantic models (src/models.py).

export type Status = "PASS" | "FAIL" | "PARTIAL" | "NOT_ASSESSED";

export interface SourceContribution {
  source_name: string;
  source_description: string;
  item_count: number;
  addressable_count: number;
  pass_count: number;
  fail_count: number;
  partial_count: number;
  coverage_pct: number;
}

export interface AggregatedControl {
  control_id: string;
  control_name: string;
  function_id: string;
  function_name: string;
  category_id: string;
  addressable: boolean;
  status: Status;
  confidence: number;
  evidenced_by: string[];
  evidence: string;
  gap: string;
  recommendation: string;
}

export interface FunctionBucket {
  total: number;
  addressable: number;
  pass: number;
  fail: number;
  partial: number;
}

export interface CoverageSummary {
  total_controls: number;
  addressable_count: number;
  pass_count: number;
  fail_count: number;
  partial_count: number;
  not_assessed_count: number;
  coverage_pct: number;
  pass_rate_pct: number;
  by_function: Record<string, FunctionBucket>;
}

export interface AggregatedReport {
  report_id: string;
  generated_at: string;
  framework: string;
  scope: string;
  posture_grade: string;
  sources: SourceContribution[];
  summary: CoverageSummary;
  controls: AggregatedControl[];
}

export interface JobStatus {
  job_id: string;
  status: "pending" | "running" | "done" | "error";
  created_at: string;
  config: {
    scope: string;
    sources: string[];
    severity: string;
    keyword: string | null;
    max_cves: number;
    days_back: number;
  };
  report_id: string | null;
  error: string | null;
  report: AggregatedReport | null;
}

export interface SourceInfo {
  key: string;
  name: string;
  description: string;
  live: boolean;
}

export interface ReportListItem {
  report_id: string;
  file: string;
  generated_at: string;
  scope: string;
  posture_grade: string;
  coverage_pct: number;
  pass_rate_pct: number;
  source_count: number;
}

// Progress event shapes emitted by the pipeline (src/pipeline.py).
export interface ProgressEvent {
  type:
    | "status"
    | "catalog_loaded"
    | "source_connecting"
    | "source_connected"
    | "source_skipped"
    | "assessing"
    | "aggregating"
    | "done"
    | "error";
  status?: string;
  source?: string;
  reason?: string;
  item_count?: number;
  control_count?: number;
  function_count?: number;
  scope?: string;
  func_id?: string;
  func_name?: string;
  completed?: number;
  total?: number;
  report_id?: string;
  posture_grade?: string;
  message?: string;
}

export interface StartAssessmentRequest {
  scope: string;
  sources: string[];
  severity: string;
  keyword: string | null;
  max_cves: number;
  days_back: number;
}
