# NIST CSF 2.0 Compliance Posture Pipeline

An AI-powered, **control-first, multi-source** pipeline that assesses an organization's NIST Cybersecurity Framework (CSF) 2.0 compliance posture. It connects evidence sources (vulnerability feeds, cloud config, identity providers, …), uses GPT-4 to decide *which* controls each source can actually evidence and whether each one **passes or fails**, then aggregates everything into a single posture report — with a coverage grade and an explicit roadmap of which integrations would close the remaining gaps.

It ships as both a **CLI** and a **full-stack web app**: a FastAPI service wraps the pipeline and a Next.js dashboard lets a compliance team configure a run, watch it execute live, and read the posture report in the browser. See **[Web App](#web-app)**.

> **Why control-first?** Starting from a CVE feed and mapping vulnerabilities back to controls only ever lights up the same vulnerability-management subset of the framework — it measures vulnerability density, not compliance posture. This pipeline inverts that: the entry points are *evidence sources*, the AI scores controls, and **the more sources you connect the higher your coverage climbs**. The report always shows what *no* source can yet evidence, so coverage is never overstated.

## Quick Start

```bash
# 1. Clone and install
git clone <repo-url> && cd nist-csf-vuln-assessor
cd backend && uv sync

# 2. Configure
cp .env.example .env
# Edit .env and add your OpenAI API key

# 3. Run (all three demo sources by default)
uv run main.py --scope "production AWS web tier" --keyword apache

# Or a single source to see coverage drop:
uv run main.py --sources nvd
```

Reports are saved to `backend/output/` as both JSON and Markdown. The terminal prints a live posture dashboard.

## Web App

The same pipeline is exposed as a web product: a **FastAPI** backend (async jobs + live progress over Server-Sent Events) and a **Next.js + React + Tailwind** dashboard.

```
frontend/ (Next.js, :3000)  ──HTTP/JSON + SSE──▶  FastAPI (:8000)  ──▶  shared pipeline
   New-assessment form                              /api/assessments        (NVD client, GPT-4
   Live run progress (SSE)                          (start / stream /         assessor, aggregation)
   Posture report dashboard                          list / fetch report)
```

**1. Start the backend** (needs `OPENAI_API_KEY` in `backend/.env`):

```bash
cd backend
uv sync
uv run uvicorn src.api.app:app --reload --port 8000
```

**2. Start the frontend** (in a second terminal):

```bash
cd frontend
cp .env.local.example .env.local   # optional — defaults to http://localhost:8000
npm install
npm run dev
```

Open **http://localhost:3000**, configure a run (scope, sources, NVD filters), click **Run assessment**, and watch it execute live. When it finishes, the posture report renders in place; past runs are listed on the dashboard and openable at `/reports/<id>`.

> Tip: a `cloud,idp` run (sample sources) finishes fast and needs no network — good for a first smoke test. Add `nvd` for a live, CVE-driven assessment (slower due to NVD rate limits).

### API endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/api/health` | service health + whether the OpenAI key is configured |
| `GET`  | `/api/framework` | NIST CSF 2.0 catalog (functions, categories, control counts) |
| `GET`  | `/api/sources` | available evidence sources + descriptions |
| `POST` | `/api/assessments` | start a run; body = `{scope, sources, severity, keyword, max_cves, days_back}` → `{job_id}` |
| `GET`  | `/api/assessments` | list past runs persisted to `backend/output/` |
| `GET`  | `/api/assessments/{job_id}` | job status + the full report once `done` |
| `GET`  | `/api/assessments/{job_id}/events` | **SSE** stream of live progress events |
| `GET`  | `/api/reports/{report_id}` | a saved aggregated report |

Interactive API docs are available at **http://localhost:8000/docs**.

## How It Works

```
┌──────────────────────────────┐
│  Evidence Sources (pluggable) │
│  • NIST NVD (CVEs)            │──┐
│  • Cloud Posture (CSPM)       │  │     ┌─────────────────┐     ┌────────────────────┐     ┌────────────┐
│  • Identity Provider (IdP)    │  ├────>│  GPT-4          │────>│  Aggregate posture │────>│  JSON +    │
│  • …add your own connector    │  │     │  Control-First  │     │  (grade, coverage, │     │  Markdown  │
└──────────────────────────────┘  │     │  Assessor       │     │  pass/fail, gaps)  │     │  Reports   │
                                   │     └────────┬────────┘     └────────────────────┘     └────────────┘
                                   │              │
                                   │     ┌────────┴────────┐
                                   └────>│  NIST CSF 2.0   │
                                         │  Control Catalog│
                                         │  (103 controls) │
                                         └─────────────────┘
```

### Pipeline Steps

1. **Connect & collect** — Each selected `EvidenceSource` gathers data and condenses it into an `EvidenceBundle`. `NVDEvidenceSource` pulls live CVEs; `CloudConfigEvidenceSource` and `IdentityProviderEvidenceSource` ship representative sample findings so the multi-source story demos without extra credentials.
2. **Assess controls (control-first)** — For each source, walking the catalog by CSF function (6 focused GPT-4 calls), the model decides per control:
   - **addressable** — can this source produce evidence relevant to this control at all?
   - **status** — PASS / FAIL / PARTIAL / NOT_ASSESSED based on the evidence
   - **confidence**, the **evidence** cited, the **gap** (what's missing / which other source is needed), and a **recommendation**
3. **Aggregate** — Per-source results merge into one posture: a control is *evidenced* if any source addresses it, and its merged status is the worst any source reports (a failure anywhere means the control isn't satisfied). Each source's coverage contribution is tracked.
4. **Report** — A terminal dashboard plus JSON + Markdown: posture grade, coverage/pass-rate bars, **per-source contribution**, per-function breakdown, a **failing-controls remediation list**, and a **Coverage Gaps** section that names the suggested integration to close each gap.

### Extending with new sources — the integration story

The assessor is source-agnostic; coverage grows by connecting integrations, not by pulling more CVEs. Add a connector (CMDB, EDR, SIEM, GRC, ticketing, backup/DR…) by subclassing `EvidenceSource` in [backend/src/sources.py](backend/src/sources.py) and returning an `EvidenceBundle`. Register it in `DEMO_SOURCES` to expose it via `--sources`. Each new source raises coverage and shrinks the gap list — which the report quantifies.

## CLI Options

```
cd backend
uv run main.py [OPTIONS]

Options:
  --scope        Asset scope for the assessment, framed into the evidence
  --sources      Comma-separated sources: nvd, cloud, idp  [default: nvd,cloud,idp]
  --severity     CVSS severity filter for the NVD source: LOW, MEDIUM, HIGH, CRITICAL  [default: HIGH]
  --keyword      Keyword filter for NVD, used to scope to assets (e.g., "apache", "linux")
  --max-cves     Max CVEs to pull as evidence  [default: 15]
  --days-back    Fetch CVEs from the last N days  [default: 120]
  --output-dir   Output directory  [default: output]
```

## Project Structure

```
backend/                # Python — FastAPI + CLI + pipeline
├── src/
│   ├── pipeline.py     # Reusable orchestration (run_assessment + on_event) — shared by CLI and API
│   ├── cli.py          # Typer CLI: drives the rich terminal dashboard via pipeline events
│   ├── config.py       # Settings via pydantic-settings (env vars)
│   ├── models.py       # Pydantic models (evidence bundle, assessment, aggregated report)
│   ├── nvd_client.py   # NIST NVD API integration (rate limiting, retry, parsing)
│   ├── sources.py      # EvidenceSource abstraction + NVD / Cloud / IdP connectors
│   ├── framework.py    # NIST CSF 2.0 catalog loader and indexer
│   ├── assessor.py     # GPT-4 control-first assessor (addressability + pass/fail per control)
│   ├── analyzer.py     # (legacy) CVE-first analyzer, kept for reference
│   ├── report.py       # Multi-source aggregation + JSON/Markdown posture report
│   └── api/
│       ├── app.py      # FastAPI app: endpoints + CORS + SSE
│       └── jobs.py     # In-memory job store; runs the pipeline on a background thread
├── data/
│   └── nist_csf_2_0.json  # Static NIST CSF 2.0 control catalog
├── pyproject.toml
├── uv.lock
└── main.py

frontend/               # Next.js + React + Tailwind dashboard
├── app/                # Pages: dashboard (/), live run (/assessments/[id]), report (/reports/[id])
├── components/         # AssessmentForm, RunProgress, PostureReport, shared UI
└── lib/                # Typed API client, SSE hook, shared types
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Control-first, not CVE-first** | The pipeline assesses the framework against evidence, rather than mapping vulnerabilities back to controls. This measures *posture and coverage*, and surfaces gaps a CVE feed alone can never reveal |
| **Multi-source aggregation** | Results from every connected source merge into one posture. A control is evidenced if any source covers it; merged status is worst-wins so a failure anywhere is never hidden. Each source's coverage contribution is reported |
| **Pluggable evidence sources** | A source-agnostic `EvidenceSource` abstraction means NVD is just one connector. Coverage grows by adding sources (CMDB, IdP, cloud config, EDR), not by pulling more CVEs |
| **NIST CSF 2.0** over SCF | ~100 controls vs 1,400+. Focused catalog produces higher-quality AI assessments and cleaner demos |
| **Assess by function (6 calls)** | The catalog is walked one CSF function at a time, keeping each prompt focused while covering all controls in 6 API calls regardless of evidence volume |
| **Honest addressability** | The model is explicitly instructed not to inflate coverage; controls it cannot evidence are marked NOT_ASSESSED with a named gap — so the report never implies broad compliance from narrow data |
| **JSON mode + Pydantic validation** | OpenAI JSON mode for reliable structured output, Pydantic for type safety and serialization |
| **Post-validation of control IDs** | Only catalog control IDs are accepted; unknown IDs are dropped and omitted controls default to NOT_ASSESSED, ensuring report accuracy |

## AI Analysis Details

The AI performs genuine assessment work, not formatting. For every control it judges:

- **Addressability** — whether the evidence source can produce evidence relevant to that control at all (the basis of the coverage metric)
- **Pass / fail / partial** — a status judgement grounded in the specific evidence signal, with a confidence score
- **Evidence citation** — the concrete signal in the bundle that drove the call, making the reasoning traceable and auditable
- **Gap analysis** — for controls that fail or can't be assessed, *what is missing* or which other evidence source would be needed — turning the report into a roadmap for closing coverage

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (package manager)
- OpenAI API key (GPT-4o recommended)
- Internet access (for the NVD source; the cloud/idp demo sources run offline)
