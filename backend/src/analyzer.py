from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import openai

from .config import Settings
from .framework import FrameworkCatalog
from .models import (
    CVEAnalysisResult,
    CVEData,
    ControlMapping,
    Remediation,
    RiskAssessment,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior cybersecurity compliance analyst specializing in NIST Cybersecurity Framework (CSF) 2.0 assessments. Your role is to analyze Common Vulnerabilities and Exposures (CVEs) and produce actionable compliance findings.

You will be given a CVE record and the complete NIST CSF 2.0 control catalog. Your analysis MUST follow these steps in order:

STEP 1 — SECURITY DOMAIN CLASSIFICATION
Identify which cybersecurity domains this vulnerability affects (e.g., Access Control, Network Security, Software Supply Chain, Data Protection, Configuration Management, Vulnerability Management, Cryptography, etc.). Provide a brief reasoning for your classification.

STEP 2 — NIST CSF 2.0 CONTROL MAPPING
Map this CVE to 2–5 specific NIST CSF 2.0 controls. For each mapping:
- Use the EXACT control ID from the catalog (e.g., PR.AA-01, ID.RA-01)
- Assign a confidence score (0.0–1.0) reflecting how directly this CVE relates to the control
- Write a one-sentence reasoning chain explaining the connection between the vulnerability and the control requirement
Prefer specificity over breadth. A confidence of 0.9+ means the CVE directly tests whether that control is implemented.

STEP 3 — RISK ASSESSMENT
Evaluate:
- severity: factor in CVSS score, real-world exploitability, and breadth of affected systems (CRITICAL / HIGH / MEDIUM / LOW)
- exploitability: is there a known exploit? Remotely exploitable? Requires authentication?
- business_impact: what organizational functions are at risk?
- urgency: IMMEDIATE (patch now), SHORT_TERM (patch within sprint), MEDIUM_TERM (plan remediation)

STEP 4 — REMEDIATION RECOMMENDATIONS
Provide 1–3 concrete, actionable remediation steps. Each must include:
- action: a specific action (not generic advice like "apply patches")
- priority: P0 / P1 / P2
- effort: LOW / MEDIUM / HIGH
- details: implementation specifics relevant to this vulnerability

IMPORTANT: You MUST only use control IDs that exist in the provided catalog. Do NOT invent control IDs.

Respond ONLY with valid JSON matching this schema:
{
  "security_domains": ["string"],
  "domain_reasoning": "string",
  "control_mappings": [
    {
      "control_id": "string (e.g. PR.AA-01)",
      "control_name": "string (brief name of the control)",
      "confidence": 0.0-1.0,
      "reasoning": "string"
    }
  ],
  "risk_assessment": {
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "exploitability": "string",
    "business_impact": "string",
    "urgency": "IMMEDIATE|SHORT_TERM|MEDIUM_TERM"
  },
  "remediations": [
    {
      "action": "string",
      "priority": "P0|P1|P2",
      "effort": "LOW|MEDIUM|HIGH",
      "details": "string"
    }
  ]
}"""


class CVEAnalyzer:
    def __init__(self, settings: Settings, catalog: FrameworkCatalog):
        self._client = openai.OpenAI(api_key=settings.openai_api_key)
        self._model = settings.openai_model
        self._catalog = catalog
        self._valid_ids = catalog.get_valid_control_ids()
        self._system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        catalog_text = self._catalog.get_catalog_summary_for_prompt()
        return f"{SYSTEM_PROMPT}\n\n--- NIST CSF 2.0 CONTROL CATALOG ---\n{catalog_text}"

    def _build_user_prompt(self, cve: CVEData) -> str:
        parts = [
            f"CVE ID: {cve.cve_id}",
            f"Description: {cve.description}",
            f"CVSS Score: {cve.cvss_score} ({cve.cvss_severity})" if cve.cvss_score else "CVSS Score: Not available",
            f"CVSS Vector: {cve.cvss_vector}" if cve.cvss_vector else "CVSS Vector: Not available",
            f"CWE IDs: {', '.join(cve.cwe_ids)}" if cve.cwe_ids else "CWE IDs: None listed",
            f"Published: {cve.published}",
            f"References: {', '.join(cve.references[:3])}" if cve.references else "References: None",
        ]
        return "Analyze the following CVE:\n\n" + "\n".join(parts)

    def analyze_cve(self, cve: CVEData) -> CVEAnalysisResult:
        user_prompt = self._build_user_prompt(cve)

        raw = self._call_llm(user_prompt)
        return self._parse_response(cve, raw)

    def _call_llm(self, user_prompt: str, retries: int = 2) -> dict:
        for attempt in range(retries):
            try:
                response = self._client.chat.completions.create(
                    model=self._model,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": self._system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.2,
                )
                content = response.choices[0].message.content
                return json.loads(content)
            except json.JSONDecodeError:
                if attempt < retries - 1:
                    logger.warning("LLM returned invalid JSON, retrying...")
                    continue
                raise
            except openai.APIError as e:
                if attempt < retries - 1:
                    logger.warning("OpenAI API error: %s, retrying...", e)
                    continue
                raise

    def _parse_response(self, cve: CVEData, raw: dict) -> CVEAnalysisResult:
        # Validate control IDs against catalog
        mappings = []
        for m in raw.get("control_mappings", []):
            cid = m.get("control_id", "")
            if cid in self._valid_ids:
                mappings.append(ControlMapping(
                    control_id=cid,
                    control_name=m.get("control_name", ""),
                    confidence=float(m.get("confidence", 0.5)),
                    reasoning=m.get("reasoning", ""),
                ))
            else:
                logger.warning("Dropping hallucinated control ID: %s (CVE: %s)", cid, cve.cve_id)

        risk = raw.get("risk_assessment", {})
        risk_assessment = RiskAssessment(
            severity=risk.get("severity", "MEDIUM"),
            exploitability=risk.get("exploitability", "Unknown"),
            business_impact=risk.get("business_impact", "Unknown"),
            urgency=risk.get("urgency", "MEDIUM_TERM"),
        )

        remediations = [
            Remediation(
                action=r.get("action", ""),
                priority=r.get("priority", "P1"),
                effort=r.get("effort", "MEDIUM"),
                details=r.get("details", ""),
            )
            for r in raw.get("remediations", [])
        ]

        return CVEAnalysisResult(
            cve=cve,
            security_domains=raw.get("security_domains", []),
            domain_reasoning=raw.get("domain_reasoning", ""),
            control_mappings=mappings,
            risk_assessment=risk_assessment,
            remediations=remediations,
            analysis_timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def analyze_batch(self, cves: list[CVEData]) -> list[CVEAnalysisResult]:
        results = []
        for cve in cves:
            try:
                result = self.analyze_cve(cve)
                results.append(result)
            except Exception as e:
                logger.error("Failed to analyze %s: %s", cve.cve_id, e)
        return results
