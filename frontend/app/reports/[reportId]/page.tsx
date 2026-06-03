"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import PostureReport from "@/components/PostureReport";
import { Card } from "@/components/ui";
import { api } from "@/lib/api";
import type { AggregatedReport } from "@/lib/types";

export default function ReportPage({ params }: { params: Promise<{ reportId: string }> }) {
  const { reportId } = use(params);
  const [report, setReport] = useState<AggregatedReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getReport(reportId)
      .then(setReport)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [reportId]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 text-sm text-slate-400">
        <Link href="/" className="hover:text-slate-100">
          ← Dashboard
        </Link>
        <span className="text-slate-600">/</span>
        <span className="font-mono text-slate-300">{reportId}</span>
      </div>

      {loading && <Card><p className="text-sm text-slate-500">Loading report…</p></Card>}
      {error && (
        <Card>
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
            {error}
          </div>
        </Card>
      )}
      {report && <PostureReport report={report} />}
    </div>
  );
}
