"use client";

import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { AggregatedReport, JobStatus, ProgressEvent } from "./types";

export interface StreamState {
  events: ProgressEvent[];
  status: JobStatus["status"];
  report: AggregatedReport | null;
  error: string | null;
}

/**
 * Subscribes to a job's Server-Sent Events stream, accumulating progress
 * events. When the run reaches a terminal status, fetches the full job to pull
 * the final report. Falls back to a single getJob() if the stream errors.
 */
export function useAssessmentStream(jobId: string | null): StreamState {
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [status, setStatus] = useState<JobStatus["status"]>("pending");
  const [report, setReport] = useState<AggregatedReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const finalized = useRef(false);

  useEffect(() => {
    if (!jobId) return;
    finalized.current = false;
    setEvents([]);
    setStatus("pending");
    setReport(null);
    setError(null);

    const source = new EventSource(api.eventsUrl(jobId));

    const finalize = async (terminal: "done" | "error") => {
      if (finalized.current) return;
      finalized.current = true;
      source.close();
      try {
        const job = await api.getJob(jobId);
        setStatus(job.status);
        setReport(job.report);
        if (job.error) setError(job.error);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setStatus(terminal);
      }
    };

    const handle = (e: MessageEvent) => {
      let ev: ProgressEvent;
      try {
        ev = JSON.parse(e.data) as ProgressEvent;
      } catch {
        return;
      }
      setEvents((prev) => [...prev, ev]);
      if (ev.type === "status" && ev.status) {
        setStatus(ev.status as JobStatus["status"]);
      }
      if (ev.type === "done") void finalize("done");
      if (ev.type === "error") {
        setError(ev.message || "Assessment failed.");
        void finalize("error");
      }
    };

    // Named SSE events (we send `event: <type>`) plus the default channel.
    const types = [
      "status",
      "catalog_loaded",
      "source_connecting",
      "source_connected",
      "source_skipped",
      "assessing",
      "aggregating",
      "done",
      "error",
      "message",
    ];
    types.forEach((t) => source.addEventListener(t, handle as EventListener));

    source.onerror = () => {
      // Stream dropped — if we haven't finalized, poll the job once to recover.
      if (!finalized.current) {
        api
          .getJob(jobId)
          .then((job) => {
            if (job.status === "done" || job.status === "error") {
              setStatus(job.status);
              setReport(job.report);
              if (job.error) setError(job.error);
              finalized.current = true;
              source.close();
            }
          })
          .catch(() => {
            /* keep the connection; EventSource will retry */
          });
      }
    };

    return () => {
      source.close();
    };
  }, [jobId]);

  return { events, status, report, error };
}
