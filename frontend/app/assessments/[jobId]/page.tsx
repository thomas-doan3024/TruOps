"use client";

import { use } from "react";
import Link from "next/link";
import PostureReport from "@/components/PostureReport";
import RunProgress from "@/components/RunProgress";
import { Card } from "@/components/ui";
import { useAssessmentStream } from "@/lib/useAssessmentStream";

export default function AssessmentRunPage({ params }: { params: Promise<{ jobId: string }> }) {
  const { jobId } = use(params);
  const { events, status, report, error } = useAssessmentStream(jobId);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 text-sm text-slate-400">
        <Link href="/" className="hover:text-slate-100">
          ← Dashboard
        </Link>
        <span className="text-slate-600">/</span>
        <span className="font-mono text-slate-300">{jobId}</span>
      </div>

      {status !== "done" && <RunProgress events={events} status={status} />}

      {error && (
        <Card>
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
            <div className="font-medium">Assessment failed</div>
            <div className="mt-1 text-rose-300/90">{error}</div>
          </div>
        </Card>
      )}

      {report && <PostureReport report={report} />}
    </div>
  );
}
