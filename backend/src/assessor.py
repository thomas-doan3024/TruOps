from __future__ import annotations

import json
import logging

import openai

from .config import Settings
from .framework import FrameworkCatalog
from .models import (
    STATUS_NOT_ASSESSED,
    ControlAssessment,
    EvidenceBundle,
)

logger = logging.getLogger(__name__)

VALID_STATUSES = {"PASS", "FAIL", "PARTIAL", "NOT_ASSESSED"}

SYSTEM_PROMPT = """You are a senior NIST Cybersecurity Framework (CSF) 2.0 compliance assessor.

You operate in a CONTROL-FIRST manner. You are given:
1. An EVIDENCE BUNDLE produced by a SINGLE data source / connector.
2. A batch of NIST CSF 2.0 controls.

For EACH control in the batch, decide:

A. addressable (true/false) — Can THIS data source realistically produce evidence
   relevant to this specific control's requirement? Be strict and honest. A single
   source can only evidence a small slice of the framework. Only set addressable=true
   when the evidence genuinely speaks to whether the control is implemented.

B. status — If addressable, judge the evidence:
   - PASS: evidence indicates the control's intent is being met
   - FAIL: evidence indicates the control is NOT met / is actively undermined
   - PARTIAL: evidence partially supports the control or is inconclusive
   If NOT addressable, status MUST be NOT_ASSESSED.

C. confidence (0.0–1.0) — how confident you are in the addressability + status call.

D. evidence — cite the SPECIFIC signal in the bundle that drove your call (one sentence).
   Empty string if not addressable.

E. gap — what is missing, why it FAILs/PARTIALs, or which OTHER kind of data source would
   be needed to assess this control. This is the most valuable field for posture: name the
   coverage gap explicitly.

F. recommendation — one concrete next step. Empty string if none.

CRITICAL GUIDANCE:
- Do NOT inflate coverage. For example, a CVE / vulnerability feed mainly evidences
  vulnerability-identification, risk, and a few continuous-monitoring controls. It does
  NOT evidence governance, supply-chain policy, awareness training, recovery planning,
  identity proofing, etc. Mark those NOT_ASSESSED and name the source that would cover them.
- A vulnerability source showing many unpatched HIGH/CRITICAL CVEs is evidence of a FAILING
  vulnerability-management posture, not a passing one.
- Use the EXACT control IDs given in the batch. Do not invent IDs or assess controls not listed.

Respond ONLY with valid JSON matching this schema:
{
  "assessments": [
    {
      "control_id": "string (exact ID from the batch)",
      "addressable": true,
      "status": "PASS|FAIL|PARTIAL|NOT_ASSESSED",
      "confidence": 0.0,
      "evidence": "string",
      "gap": "string",
      "recommendation": "string"
    }
  ]
}"""


class ControlAssessor:
    """Assesses NIST CSF 2.0 controls against an evidence bundle, control-first.

    Iterates the catalog by function (6 focused LLM calls instead of one call
    per CVE), asking the model which controls the source can evidence and
    whether each passes or fails.
    """

    def __init__(self, settings: Settings, catalog: FrameworkCatalog):
        self._client = openai.OpenAI(api_key=settings.openai_api_key)
        self._model = settings.openai_model
        self._catalog = catalog

    def assess(self, bundle: EvidenceBundle) -> list[ControlAssessment]:
        results: list[ControlAssessment] = []
        for func_id, func_name in self._catalog.get_functions():
            controls = self._catalog.get_controls_by_function(func_id)
            if not controls:
                continue
            results.extend(self._assess_function(bundle, func_id, func_name, controls))
        return results

    def assess_function(self, bundle: EvidenceBundle, func_id: str, func_name: str):
        controls = self._catalog.get_controls_by_function(func_id)
        return self._assess_function(bundle, func_id, func_name, controls)

    def _assess_function(self, bundle, func_id, func_name, controls) -> list[ControlAssessment]:
        control_index = {c.control_id: c for c in controls}
        user_prompt = self._build_user_prompt(bundle, func_id, func_name, controls)

        try:
            raw = self._call_llm(user_prompt)
        except Exception as e:
            logger.error("Assessment failed for function %s: %s", func_id, e)
            raw = {}

        returned: dict[str, dict] = {}
        for a in raw.get("assessments", []):
            cid = a.get("control_id", "")
            if cid in control_index:
                returned[cid] = a
            else:
                logger.warning("Dropping unknown control ID from LLM: %s", cid)

        # Build an assessment for every control; unreturned controls default to NOT_ASSESSED.
        out: list[ControlAssessment] = []
        for ctrl in controls:
            a = returned.get(ctrl.control_id)
            if a is None:
                out.append(ControlAssessment(
                    control_id=ctrl.control_id,
                    control_name=ctrl.description,
                    function_id=ctrl.function_id,
                    function_name=ctrl.function_name,
                    category_id=ctrl.category_id,
                    addressable=False,
                    status=STATUS_NOT_ASSESSED,
                    confidence=0.0,
                    gap="Not assessed by this source.",
                ))
                continue

            addressable = bool(a.get("addressable", False))
            status = str(a.get("status", STATUS_NOT_ASSESSED)).upper()
            if status not in VALID_STATUSES:
                status = STATUS_NOT_ASSESSED
            if not addressable:
                status = STATUS_NOT_ASSESSED

            out.append(ControlAssessment(
                control_id=ctrl.control_id,
                control_name=ctrl.description,
                function_id=ctrl.function_id,
                function_name=ctrl.function_name,
                category_id=ctrl.category_id,
                addressable=addressable,
                status=status,
                confidence=float(a.get("confidence", 0.0)),
                evidence=a.get("evidence", ""),
                gap=a.get("gap", ""),
                recommendation=a.get("recommendation", ""),
            ))
        return out

    def _build_user_prompt(self, bundle: EvidenceBundle, func_id, func_name, controls) -> str:
        control_lines = "\n".join(f"- {c.control_id}: {c.description}" for c in controls)
        scope_line = f"\nASSESSMENT SCOPE: {bundle.scope}" if bundle.scope else ""
        return (
            f"DATA SOURCE: {bundle.source_name}\n"
            f"SOURCE DESCRIPTION: {bundle.source_description}{scope_line}\n\n"
            f"--- EVIDENCE BUNDLE ({bundle.item_count} item(s)) ---\n"
            f"{bundle.summary}\n\n"
            f"--- CONTROLS TO ASSESS: NIST CSF 2.0 function {func_id} ({func_name}) ---\n"
            f"{control_lines}\n\n"
            f"Assess every control listed above against the evidence bundle. "
            f"Return one entry per control."
        )

    def _call_llm(self, user_prompt: str, retries: int = 2) -> dict:
        for attempt in range(retries):
            try:
                response = self._client.chat.completions.create(
                    model=self._model,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.2,
                )
                return json.loads(response.choices[0].message.content)
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
