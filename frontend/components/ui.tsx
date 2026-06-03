import type { Status } from "@/lib/types";

export const FUNC_NAMES: Record<string, string> = {
  GV: "Govern",
  ID: "Identify",
  PR: "Protect",
  DE: "Detect",
  RS: "Respond",
  RC: "Recover",
};
export const FUNC_ORDER = ["GV", "ID", "PR", "DE", "RS", "RC"];

export function gradeClasses(grade: string): string {
  switch (grade) {
    case "A":
      return "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40";
    case "B":
      return "bg-green-500/15 text-green-300 ring-green-500/40";
    case "C":
      return "bg-amber-500/15 text-amber-300 ring-amber-500/40";
    case "D":
      return "bg-orange-500/15 text-orange-300 ring-orange-500/40";
    case "F":
      return "bg-rose-500/15 text-rose-300 ring-rose-500/40";
    default:
      return "bg-slate-500/15 text-slate-300 ring-slate-500/40";
  }
}

export function GradeBadge({ grade, size = "lg" }: { grade: string; size?: "sm" | "lg" }) {
  const dims = size === "lg" ? "h-20 w-20 text-4xl" : "h-9 w-12 text-lg";
  return (
    <div
      className={`grid place-items-center rounded-xl font-black ring-1 ${dims} ${gradeClasses(grade)}`}
      title={`Posture grade ${grade}`}
    >
      {grade}
    </div>
  );
}

const STATUS_META: Record<Status, { label: string; cls: string }> = {
  PASS: { label: "Pass", cls: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30" },
  FAIL: { label: "Fail", cls: "bg-rose-500/15 text-rose-300 ring-rose-500/30" },
  PARTIAL: { label: "Partial", cls: "bg-amber-500/15 text-amber-300 ring-amber-500/30" },
  NOT_ASSESSED: { label: "n/a", cls: "bg-slate-500/10 text-slate-400 ring-slate-500/20" },
};

export function StatusPill({ status }: { status: Status }) {
  const m = STATUS_META[status] ?? STATUS_META.NOT_ASSESSED;
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ${m.cls}`}>
      {m.label}
    </span>
  );
}

export function Bar({
  pct,
  tone = "brand",
}: {
  pct: number;
  tone?: "brand" | "good" | "warn" | "bad";
}) {
  const color =
    tone === "good"
      ? "bg-emerald-400"
      : tone === "warn"
      ? "bg-amber-400"
      : tone === "bad"
      ? "bg-rose-400"
      : "bg-brand";
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-edge/60">
      <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
    </div>
  );
}

export function Card({
  title,
  subtitle,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-2xl border border-edge/70 bg-panel/60 p-5 shadow-lg shadow-black/20 ${className}`}
    >
      {title && (
        <header className="mb-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-200">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-slate-400">{subtitle}</p>}
        </header>
      )}
      {children}
    </section>
  );
}

export function formatDate(iso: string | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}
