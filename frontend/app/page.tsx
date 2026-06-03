"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import AssessmentForm from "@/components/AssessmentForm";
import { Card, GradeBadge, formatDate } from "@/components/ui";
import { API_BASE, api } from "@/lib/api";
import type { ReportListItem } from "@/lib/types";

export default function DashboardPage() {
  const [reports, setReports] = useState<ReportListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listAssessments()
      .then((r) => setReports(r.reports))
      .catch((e) => setApiError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Compliance posture dashboard</h1>
          <p className="mt-1 text-sm text-slate-400">
            Connect evidence sources, let the AI assess your NIST CSF 2.0 controls, and get an actionable posture
            report with coverage, pass/fail, and gap-closing integrations.
          </p>
        </div>
        <AssessmentForm />
      </div>

      <Card title="Recent assessments" subtitle="Reports saved to the pipeline output directory.">
        {apiError && (
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
            Could not reach the API at <span className="font-mono">{API_BASE}</span>: {apiError}
            <div className="mt-1 text-xs text-rose-300/80">
              Start the backend: <span className="font-mono">uv run uvicorn src.api.app:app --port 8000</span>
            </div>
          </div>
        )}
        {loading ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : reports.length === 0 ? (
          <p className="text-sm text-slate-500">No assessments yet. Run one to see it here.</p>
        ) : (
          <ul className="space-y-2">
            {reports.map((r) => (
              <li key={r.file}>
                <Link
                  href={`/reports/${r.report_id}`}
                  className="flex items-center gap-4 rounded-lg border border-edge/60 bg-ink/30 p-3 transition-colors hover:border-brand/50 hover:bg-ink/50"
                >
                  <GradeBadge grade={r.posture_grade} size="sm" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium text-slate-100">
                      {r.scope || "Untitled scope"}
                    </div>
                    <div className="text-xs text-slate-400">
                      {formatDate(r.generated_at)} · {r.source_count} source{r.source_count === 1 ? "" : "s"} ·{" "}
                      <span className="font-mono">{r.report_id}</span>
                    </div>
                  </div>
                  <div className="flex-none text-right text-xs">
                    <div className="text-slate-300">{r.coverage_pct}% coverage</div>
                    <div className="text-slate-500">{r.pass_rate_pct}% pass</div>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
