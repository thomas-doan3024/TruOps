"use client";

import { useMemo } from "react";
import type { ProgressEvent } from "@/lib/types";
import { Bar, Card } from "./ui";

function describe(ev: ProgressEvent): string {
  switch (ev.type) {
    case "status":
      return ev.status === "running" ? "Run started" : `Status: ${ev.status}`;
    case "catalog_loaded":
      return `Loaded ${ev.control_count} NIST CSF 2.0 controls across ${ev.function_count} functions`;
    case "source_connecting":
      return `Connecting ${ev.source}…`;
    case "source_connected":
      return `Connected ${ev.source} — ${ev.item_count} evidence item(s)`;
    case "source_skipped":
      return `Skipped ${ev.source} — ${ev.reason}`;
    case "assessing":
      return `Assessing ${ev.source} · ${ev.func_id} ${ev.func_name} (${ev.completed}/${ev.total})`;
    case "aggregating":
      return "Aggregating cross-source posture…";
    case "done":
      return `Done — posture grade ${ev.posture_grade}`;
    case "error":
      return `Error: ${ev.message}`;
    default:
      return ev.type;
  }
}

export default function RunProgress({
  events,
  status,
}: {
  events: ProgressEvent[];
  status: "pending" | "running" | "done" | "error";
}) {
  // Per-source assessment progress (the long phase).
  const sources = useMemo(() => {
    const map = new Map<string, { completed: number; total: number; func: string }>();
    for (const ev of events) {
      if (ev.type === "source_connected" && ev.source) {
        if (!map.has(ev.source)) map.set(ev.source, { completed: 0, total: 6, func: "" });
      }
      if (ev.type === "assessing" && ev.source) {
        map.set(ev.source, {
          completed: ev.completed ?? 0,
          total: ev.total ?? 6,
          func: `${ev.func_id} ${ev.func_name}`,
        });
      }
    }
    return Array.from(map.entries());
  }, [events]);

  const latest = events.length ? describe(events[events.length - 1]) : "Waiting for the run to start…";

  return (
    <Card>
      <div className="flex items-center gap-3">
        {status === "running" || status === "pending" ? (
          <span className="h-3 w-3 flex-none animate-ping rounded-full bg-brand" />
        ) : status === "done" ? (
          <span className="h-3 w-3 flex-none rounded-full bg-emerald-400" />
        ) : (
          <span className="h-3 w-3 flex-none rounded-full bg-rose-400" />
        )}
        <div>
          <h1 className="text-lg font-semibold tracking-tight">
            {status === "done" ? "Assessment complete" : status === "error" ? "Assessment failed" : "Running assessment…"}
          </h1>
          <p className="text-sm text-slate-400">{latest}</p>
        </div>
      </div>

      {sources.length > 0 && (
        <div className="mt-5 space-y-3">
          {sources.map(([name, p]) => {
            const pct = p.total ? Math.round((100 * p.completed) / p.total) : 0;
            return (
              <div key={name}>
                <div className="mb-1 flex items-center justify-between text-xs">
                  <span className="text-slate-300">{name}</span>
                  <span className="text-slate-500">{p.func || "connected"}</span>
                </div>
                <Bar pct={pct} tone={pct === 100 ? "good" : "brand"} />
              </div>
            );
          })}
        </div>
      )}

      <div className="scrollbar-thin mt-5 max-h-64 overflow-auto rounded-lg border border-edge/60 bg-ink/40 p-3 font-mono text-xs leading-relaxed text-slate-400">
        {events.map((ev, i) => (
          <div key={i} className={ev.type === "error" ? "text-rose-300" : ev.type === "source_skipped" ? "text-amber-300" : ""}>
            <span className="text-slate-600">›</span> {describe(ev)}
          </div>
        ))}
        {events.length === 0 && <div>Connecting to event stream…</div>}
      </div>
    </Card>
  );
}
