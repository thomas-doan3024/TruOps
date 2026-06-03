import type {
  AggregatedReport,
  JobStatus,
  ReportListItem,
  SourceInfo,
  StartAssessmentRequest,
} from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "http://localhost:8000";

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      /* ignore non-JSON error bodies */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export interface HealthResponse {
  status: string;
  openai_key_configured: boolean;
  framework: string;
  control_count: number;
}

export const api = {
  health: () => jsonFetch<HealthResponse>("/api/health"),

  getSources: () => jsonFetch<{ sources: SourceInfo[] }>("/api/sources"),

  startAssessment: (body: StartAssessmentRequest) =>
    jsonFetch<{ job_id: string; status: string }>("/api/assessments", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  listAssessments: () =>
    jsonFetch<{ reports: ReportListItem[] }>("/api/assessments"),

  getJob: (jobId: string) => jsonFetch<JobStatus>(`/api/assessments/${jobId}`),

  getReport: (reportId: string) =>
    jsonFetch<AggregatedReport>(`/api/reports/${reportId}`),

  eventsUrl: (jobId: string) => `${API_BASE}/api/assessments/${jobId}/events`,
};
