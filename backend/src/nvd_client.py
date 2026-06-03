from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from .config import Settings
from .models import CVEData

logger = logging.getLogger(__name__)


class NVDClient:
    def __init__(self, settings: Settings):
        self._base_url = settings.nvd_base_url
        self._delay = settings.nvd_request_delay
        self._per_page = settings.nvd_results_per_page
        self._client = httpx.Client(
            timeout=30.0,
            headers={"User-Agent": "nist-csf-vuln-assessor/1.0"},
        )

    def fetch_cves(
        self,
        severity: str | None = "HIGH",
        keyword: str | None = None,
        max_results: int = 10,
        days_back: int = 30,
    ) -> list[CVEData]:
        params: dict[str, str | int] = {"resultsPerPage": min(max_results, self._per_page)}

        if severity:
            params["cvssV3Severity"] = severity.upper()
        if keyword:
            params["keywordSearch"] = keyword

        if days_back and days_back < 365:
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=days_back)
            params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
            params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

        cves: list[CVEData] = []
        start_index = 0

        while len(cves) < max_results:
            params["startIndex"] = start_index
            data = self._request_with_retry(params)
            if data is None:
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                if len(cves) >= max_results:
                    break
                parsed = self._parse_cve(item)
                if parsed:
                    cves.append(parsed)

            total_results = data.get("totalResults", 0)
            start_index += len(vulns)
            if start_index >= total_results:
                break

            time.sleep(self._delay)

        logger.info("Fetched %d CVEs from NVD", len(cves))
        return cves

    def _request_with_retry(self, params: dict, retries: int = 3) -> dict | None:
        for attempt in range(retries):
            try:
                resp = self._client.get(self._base_url, params=params)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (403, 503) and attempt < retries - 1:
                    wait = 2 ** (attempt + 1)
                    logger.warning("NVD rate limited (HTTP %d), retrying in %ds...", e.response.status_code, wait)
                    time.sleep(wait)
                    continue
                logger.error("NVD API error: %s", e)
                return None
            except httpx.TimeoutException:
                if attempt < retries - 1:
                    wait = 2 ** (attempt + 1)
                    logger.warning("NVD timeout, retrying in %ds...", wait)
                    time.sleep(wait)
                    continue
                logger.error("NVD API timed out after %d attempts", retries)
                return None
        return None

    def _parse_cve(self, item: dict) -> CVEData | None:
        try:
            cve = item["cve"]
            cve_id = cve["id"]

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "No description available",
            )

            published = cve.get("published", "")

            cvss_score, cvss_severity, cvss_vector = None, None, None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            cwe_ids = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-"):
                        cwe_ids.append(val)

            references = [
                ref.get("url", "") for ref in cve.get("references", [])[:5]
            ]

            return CVEData(
                cve_id=cve_id,
                description=description,
                published=published,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                references=references,
            )
        except (KeyError, IndexError) as e:
            logger.warning("Skipping malformed CVE entry: %s", e)
            return None

    def close(self) -> None:
        self._client.close()
