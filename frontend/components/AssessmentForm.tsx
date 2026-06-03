"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import type { SourceInfo } from "@/lib/types";
import { Card } from "./ui";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function AssessmentForm() {
  const router = useRouter();
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [selected, setSelected] = useState<string[]>(["nvd", "cloud", "idp"]);
  const [scope, setScope] = useState("");
  const [severity, setSeverity] = useState("HIGH");
  const [keyword, setKeyword] = useState("");
  const [maxCves, setMaxCves] = useState(15);
  const [daysBack, setDaysBack] = useState(120);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getSources()
      .then((r) => setSources(r.sources))
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const toggle = (key: string) =>
    setSelected((prev) => (prev.includes(key) ? prev.filter((s) => s !== key) : [...prev, key]));

  const nvdSelected = selected.includes("nvd");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (selected.length === 0) {
      setError("Select at least one evidence source.");
      return;
    }
    setSubmitting(true);
    try {
      const { job_id } = await api.startAssessment({
        scope,
        sources: selected,
        severity,
        keyword: keyword.trim() || null,
        max_cves: maxCves,
        days_back: daysBack,
      });
      router.push(`/assessments/${job_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setSubmitting(false);
    }
  };

  return (
    <Card title="New Assessment" subtitle="Connect evidence sources and run a control-first posture assessment.">
      <form onSubmit={submit} className="space-y-5">
        <div>
          <label className="mb-1.5 block text-xs font-medium text-slate-300">Asset scope</label>
          <input
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="e.g. public-facing Apache/nginx web servers"
            className="w-full rounded-lg border border-edge bg-ink/60 px-3 py-2 text-sm outline-none placeholder:text-slate-500 focus:border-brand/70 focus:ring-1 focus:ring-brand/40"
          />
        </div>

        <div>
          <label className="mb-2 block text-xs font-medium text-slate-300">Evidence sources</label>
          <div className="grid gap-2 sm:grid-cols-1">
            {sources.map((s) => {
              const on = selected.includes(s.key);
              return (
                <button
                  type="button"
                  key={s.key}
                  onClick={() => toggle(s.key)}
                  className={`flex items-start gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors ${
                    on
                      ? "border-brand/60 bg-brand/10"
                      : "border-edge bg-ink/40 hover:border-slate-500"
                  }`}
                >
                  <span
                    className={`mt-0.5 grid h-4 w-4 flex-none place-items-center rounded border ${
                      on ? "border-brand bg-brand text-onbrand" : "border-slate-500"
                    }`}
                  >
                    {on && (
                      <svg viewBox="0 0 12 12" className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth={2}>
                        <path d="M2 6l3 3 5-6" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    )}
                  </span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-2 text-sm font-medium text-slate-100">
                      {s.name}
                      <span
                        className={`rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
                          s.live
                            ? "bg-emerald-500/15 text-emerald-300"
                            : "bg-slate-500/15 text-slate-400"
                        }`}
                      >
                        {s.live ? "Live" : "Sample"}
                      </span>
                    </span>
                    <span className="mt-0.5 block text-xs text-slate-400">{s.description}</span>
                  </span>
                </button>
              );
            })}
            {sources.length === 0 && (
              <div className="rounded-lg border border-edge bg-ink/40 px-3 py-2 text-xs text-slate-500">
                Loading sources…
              </div>
            )}
          </div>
        </div>

        {nvdSelected && (
          <fieldset className="rounded-lg border border-edge/70 bg-ink/30 p-4">
            <legend className="px-1 text-xs font-medium text-slate-300">NVD live feed options</legend>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block text-xs text-slate-400">CVSS severity</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className="w-full rounded-lg border border-edge bg-ink/60 px-3 py-2 text-sm outline-none focus:border-brand/70"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1.5 block text-xs text-slate-400">Keyword (optional)</label>
                <input
                  value={keyword}
                  onChange={(e) => setKeyword(e.target.value)}
                  placeholder="apache, linux, openssl…"
                  className="w-full rounded-lg border border-edge bg-ink/60 px-3 py-2 text-sm outline-none placeholder:text-slate-500 focus:border-brand/70"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs text-slate-400">Max CVEs</label>
                <input
                  type="number"
                  min={1}
                  max={50}
                  value={maxCves}
                  onChange={(e) => setMaxCves(Number(e.target.value))}
                  className="w-full rounded-lg border border-edge bg-ink/60 px-3 py-2 text-sm outline-none focus:border-brand/70"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs text-slate-400">Published in last N days</label>
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={daysBack}
                  onChange={(e) => setDaysBack(Number(e.target.value))}
                  className="w-full rounded-lg border border-edge bg-ink/60 px-3 py-2 text-sm outline-none focus:border-brand/70"
                />
              </div>
            </div>
            <p className="mt-3 text-xs text-slate-500">
              NVD is rate-limited (~6s/request), so live runs take a few minutes.
            </p>
          </fieldset>
        )}

        {error && (
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded-lg bg-brand px-4 py-2.5 text-sm font-semibold text-onbrand transition-colors hover:bg-brand-2 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {submitting ? "Starting…" : "Run assessment"}
        </button>
      </form>
    </Card>
  );
}
