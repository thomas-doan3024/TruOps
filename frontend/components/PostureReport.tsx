"use client";

import { useMemo, useState } from "react";
import type { AggregatedControl, AggregatedReport, Status } from "@/lib/types";
import { Bar, Card, FUNC_NAMES, FUNC_ORDER, GradeBadge, StatusPill, formatDate } from "./ui";

const GAP_INTEGRATIONS: Record<string, string> = {
  GV: "GRC / policy-management platform (risk register, policy docs)",
  ID: "Asset inventory / CMDB and data-classification tooling",
  PR: "Endpoint protection, DLP, and configuration-management sources",
  DE: "SIEM / log analytics and detection-engineering telemetry",
  RS: "Incident-response / ticketing platform (PagerDuty, ServiceNow)",
  RC: "Backup / disaster-recovery and business-continuity tooling",
};

const STATUS_RANK: Record<Status, number> = { FAIL: 3, PARTIAL: 2, PASS: 1, NOT_ASSESSED: 0 };

function Gauge({ label, pct, detail, tone }: { label: string; pct: number; detail: string; tone: "brand" | "good" }) {
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-xs font-medium text-slate-300">{label}</span>
        <span className="text-lg font-bold tabular-nums">{pct.toFixed(1)}%</span>
      </div>
      <Bar pct={pct} tone={tone} />
      <p className="mt-1 text-xs text-slate-400">{detail}</p>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="rounded-lg border border-edge/60 bg-ink/40 px-3 py-2 text-center">
      <div className={`text-xl font-bold tabular-nums ${tone ?? ""}`}>{value}</div>
      <div className="text-xs text-slate-400">{label}</div>
    </div>
  );
}

export default function PostureReport({ report }: { report: AggregatedReport }) {
  const s = report.summary;
  const failing = useMemo(
    () => report.controls.filter((c) => c.status === "FAIL").sort((a, b) => a.control_id.localeCompare(b.control_id)),
    [report.controls],
  );
  const gaps = useMemo(() => report.controls.filter((c) => !c.addressable), [report.controls]);

  return (
    <div className="space-y-6">
      {/* Header / grade */}
      <Card>
        <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
          <GradeBadge grade={report.posture_grade} />
          <div className="flex-1">
            <h1 className="text-xl font-semibold tracking-tight">NIST CSF 2.0 Compliance Posture</h1>
            <p className="mt-0.5 text-sm text-slate-400">
              {report.scope ? <span className="text-slate-300">Scope: {report.scope} · </span> : null}
              {report.sources.length} source{report.sources.length === 1 ? "" : "s"} ·{" "}
              {formatDate(report.generated_at)} · <span className="font-mono text-xs">{report.report_id}</span>
            </p>
          </div>
          <div className="grid w-full grid-cols-4 gap-2 sm:w-auto sm:min-w-[22rem]">
            <Stat label="Passing" value={s.pass_count} tone="text-emerald-300" />
            <Stat label="Failing" value={s.fail_count} tone="text-rose-300" />
            <Stat label="Partial" value={s.partial_count} tone="text-amber-300" />
            <Stat label="Gaps" value={s.not_assessed_count} tone="text-slate-300" />
          </div>
        </div>
        <div className="mt-6 grid gap-6 sm:grid-cols-2">
          <Gauge
            label="Control coverage"
            pct={s.coverage_pct}
            tone="brand"
            detail={`${s.addressable_count}/${s.total_controls} controls evidenced by a source`}
          />
          <Gauge
            label="Pass rate"
            pct={s.pass_rate_pct}
            tone="good"
            detail={`${s.pass_count}/${s.addressable_count} assessed controls passing`}
          />
        </div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Source contributions */}
        <Card title="Connected sources" subtitle="Each source raises coverage. Add integrations to close gaps.">
          <div className="space-y-3">
            {report.sources.map((c) => (
              <div key={c.source_name} className="rounded-lg border border-edge/60 bg-ink/30 p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="truncate text-sm font-medium text-slate-100">{c.source_name}</span>
                  <span className="flex-none text-xs text-slate-400">{c.item_count} items</span>
                </div>
                <div className="mt-2 flex items-center gap-3">
                  <div className="flex-1">
                    <Bar pct={c.coverage_pct} />
                  </div>
                  <span className="w-12 flex-none text-right text-xs tabular-nums text-slate-300">
                    {c.coverage_pct}%
                  </span>
                </div>
                <div className="mt-2 flex gap-3 text-xs">
                  <span className="text-emerald-300">{c.pass_count} pass</span>
                  <span className="text-rose-300">{c.fail_count} fail</span>
                  <span className="text-amber-300">{c.partial_count} partial</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Coverage by function */}
        <Card title="Coverage by CSF function" subtitle="Govern · Identify · Protect · Detect · Respond · Recover">
          <div className="space-y-3">
            {FUNC_ORDER.map((fid) => {
              const b = s.by_function[fid];
              if (!b) return null;
              const pct = b.total ? Math.round((100 * b.addressable) / b.total) : 0;
              return (
                <div key={fid} className="flex items-center gap-3">
                  <span className="w-28 flex-none text-xs text-slate-300">
                    <span className="font-mono text-slate-400">{fid}</span> {FUNC_NAMES[fid]}
                  </span>
                  <div className="flex-1">
                    <Bar pct={pct} />
                  </div>
                  <span className="w-10 flex-none text-right text-xs tabular-nums text-slate-400">{pct}%</span>
                  <span className="w-24 flex-none text-right text-xs">
                    <span className="text-emerald-300">{b.pass}</span>
                    <span className="text-slate-600"> / </span>
                    <span className="text-rose-300">{b.fail}</span>
                    <span className="text-slate-600"> / </span>
                    <span className="text-amber-300">{b.partial}</span>
                  </span>
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      {/* Failing controls */}
      {failing.length > 0 && (
        <Card
          title={`Priority remediation — ${failing.length} failing control${failing.length === 1 ? "" : "s"}`}
          subtitle="Controls where connected evidence indicates the requirement is not met."
        >
          <div className="space-y-3">
            {failing.map((c) => (
              <div key={c.control_id} className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-rose-200">{c.control_id}</span>
                  <span className="text-sm text-slate-200">{c.control_name}</span>
                  <span className="ml-auto text-xs text-slate-400">{c.evidenced_by.join(", ")}</span>
                </div>
                {c.evidence && <p className="mt-1.5 text-xs text-slate-300">{c.evidence}</p>}
                {c.recommendation && (
                  <p className="mt-1 text-xs text-brand">→ {c.recommendation}</p>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* All assessed controls (filterable) */}
      <ControlsTable controls={report.controls} />

      {/* Coverage gaps */}
      <Card
        title={`Coverage gaps — ${gaps.length} control${gaps.length === 1 ? "" : "s"} with no evidence source`}
        subtitle="Add the suggested integration to bring these controls into coverage."
      >
        {gaps.length === 0 ? (
          <p className="text-sm text-slate-400">Every control is evidenced by at least one source.</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {FUNC_ORDER.map((fid) => {
              const items = gaps.filter((c) => c.function_id === fid);
              if (items.length === 0) return null;
              return (
                <div key={fid} className="rounded-lg border border-edge/60 bg-ink/30 p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-slate-200">
                      <span className="font-mono text-slate-400">{fid}</span> {FUNC_NAMES[fid]}
                    </span>
                    <span className="text-xs text-slate-500">{items.length} uncovered</span>
                  </div>
                  <p className="mt-1 text-xs text-brand/90">Suggested: {GAP_INTEGRATIONS[fid]}</p>
                  <p className="mt-1.5 font-mono text-xs leading-relaxed text-slate-500">
                    {items.map((c) => c.control_id).join(", ")}
                  </p>
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}

function ControlsTable({ controls }: { controls: AggregatedControl[] }) {
  const [statusFilter, setStatusFilter] = useState<"ALL" | Status>("ALL");
  const [funcFilter, setFuncFilter] = useState<"ALL" | string>("ALL");

  const assessed = useMemo(() => controls.filter((c) => c.addressable), [controls]);

  const rows = useMemo(() => {
    let r = assessed;
    if (statusFilter !== "ALL") r = r.filter((c) => c.status === statusFilter);
    if (funcFilter !== "ALL") r = r.filter((c) => c.function_id === funcFilter);
    return [...r].sort(
      (a, b) => STATUS_RANK[b.status] - STATUS_RANK[a.status] || a.control_id.localeCompare(b.control_id),
    );
  }, [assessed, statusFilter, funcFilter]);

  const statuses: Array<"ALL" | Status> = ["ALL", "FAIL", "PARTIAL", "PASS"];

  return (
    <Card
      title={`Assessed controls — ${assessed.length}`}
      subtitle="Every control a connected source could evidence, with the driving signal."
    >
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="flex gap-1">
          {statuses.map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                statusFilter === st ? "bg-brand text-onbrand" : "bg-ink/50 text-slate-300 hover:bg-edge"
              }`}
            >
              {st === "ALL" ? "All" : st[0] + st.slice(1).toLowerCase()}
            </button>
          ))}
        </div>
        <select
          value={funcFilter}
          onChange={(e) => setFuncFilter(e.target.value)}
          className="ml-auto rounded-md border border-edge bg-ink/60 px-2.5 py-1 text-xs outline-none focus:border-brand/70"
        >
          <option value="ALL">All functions</option>
          {FUNC_ORDER.map((fid) => (
            <option key={fid} value={fid}>
              {fid} — {FUNC_NAMES[fid]}
            </option>
          ))}
        </select>
      </div>

      <div className="scrollbar-thin max-h-[28rem] overflow-auto rounded-lg border border-edge/60">
        <table className="w-full border-collapse text-sm">
          <thead className="sticky top-0 bg-panel-2/95 text-left text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-3 py-2 font-medium">Control</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Conf.</th>
              <th className="px-3 py-2 font-medium">Source</th>
              <th className="px-3 py-2 font-medium">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.control_id} className="border-t border-edge/40 align-top hover:bg-ink/40">
                <td className="px-3 py-2">
                  <div className="font-mono text-sm font-semibold text-slate-200">{c.control_id}</div>
                  <div className="text-xs text-slate-400">{c.control_name}</div>
                </td>
                <td className="px-3 py-2">
                  <StatusPill status={c.status} />
                </td>
                <td className="px-3 py-2 text-xs tabular-nums text-slate-400">{Math.round(c.confidence * 100)}%</td>
                <td className="px-3 py-2 text-xs text-slate-400">{c.evidenced_by.join(", ")}</td>
                <td className="px-3 py-2 text-sm text-slate-300">{c.evidence}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-sm text-slate-500">
                  No controls match this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
