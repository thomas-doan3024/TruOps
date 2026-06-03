from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter

from .models import CVEData, EvidenceBundle


class EvidenceSource(ABC):
    """A data source / connector that produces evidence for control assessment.

    Each source is responsible for collecting its raw data and condensing it
    into an EvidenceBundle. The assessor is source-agnostic: it only sees the
    bundle, decides which controls the source can evidence, and scores them.

    Add a new source (CMDB, IdP logs, cloud config, EDR, ticketing, etc.) by
    subclassing this and returning an EvidenceBundle from build_bundle().
    """

    name: str = "Generic Source"
    description: str = ""

    @abstractmethod
    def build_bundle(self) -> EvidenceBundle:
        ...


class NVDEvidenceSource(EvidenceSource):
    """Wraps CVEs fetched from the NIST NVD into an evidence bundle.

    A CVE feed primarily evidences vulnerability-management and a handful of
    detection controls — it intentionally cannot speak to most of the catalog.
    The coverage report makes that gap explicit rather than implying broad
    compliance from vulnerability data alone.
    """

    name = "NIST NVD CVE Feed"
    description = (
        "Live Common Vulnerabilities and Exposures (CVEs) from the NIST National "
        "Vulnerability Database. Evidences the organization's exposure to known "
        "vulnerabilities and the state of vulnerability identification."
    )

    def __init__(self, cves: list[CVEData], scope: str = ""):
        self._cves = cves
        self._scope = scope

    def build_bundle(self) -> EvidenceBundle:
        cves = self._cves
        severity_counts = Counter(c.cvss_severity or "UNKNOWN" for c in cves)
        cwe_counts: Counter[str] = Counter()
        for c in cves:
            cwe_counts.update(c.cwe_ids)

        scores = [c.cvss_score for c in cves if c.cvss_score is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else None
        max_score = max(scores) if scores else None

        lines: list[str] = []
        scope_line = f" within scope: {self._scope}" if self._scope else ""
        lines.append(
            f"This source surfaced {len(cves)} known CVE(s){scope_line} affecting the assessed assets."
        )
        if severity_counts:
            sev_str = ", ".join(f"{k}: {v}" for k, v in severity_counts.most_common())
            lines.append(f"Severity distribution — {sev_str}.")
        if avg_score is not None:
            lines.append(f"CVSS base score: average {avg_score}, max {max_score}.")
        if cwe_counts:
            top_cwe = ", ".join(f"{k} (x{v})" for k, v in cwe_counts.most_common(8))
            lines.append(f"Most common weakness types (CWE): {top_cwe}.")

        lines.append("")
        lines.append("Representative vulnerabilities:")
        excerpt: list[str] = []
        for c in cves[:12]:
            sev = c.cvss_severity or "N/A"
            score = c.cvss_score if c.cvss_score is not None else "N/A"
            desc = c.description[:220].replace("\n", " ")
            entry = f"- {c.cve_id} [{sev}, CVSS {score}]: {desc}"
            lines.append(entry)
            excerpt.append(c.cve_id)

        summary = "\n".join(lines)

        return EvidenceBundle(
            source_name=self.name,
            source_description=self.description,
            scope=self._scope,
            summary=summary,
            item_count=len(cves),
            raw_excerpt=excerpt,
            metadata={
                "severity_counts": dict(severity_counts),
                "avg_cvss": avg_score,
                "max_cvss": max_score,
                "top_cwes": dict(cwe_counts.most_common(10)),
            },
        )


class _StaticEvidenceSource(EvidenceSource):
    """Base for demo connectors that ship with representative sample findings.

    Real connectors would call a vendor API; these return curated, realistic
    evidence so the multi-source coverage story can be demoed without live
    credentials. Findings are clearly labeled as sample data.
    """

    findings: list[str] = []

    def __init__(self, scope: str = ""):
        self._scope = scope

    def build_bundle(self) -> EvidenceBundle:
        body = "\n".join(f"- {f}" for f in self.findings)
        summary = (
            f"[Sample connector data] {len(self.findings)} configuration/state findings "
            f"collected from {self.name}:\n{body}"
        )
        return EvidenceBundle(
            source_name=self.name,
            source_description=self.description,
            scope=self._scope,
            summary=summary,
            item_count=len(self.findings),
            raw_excerpt=list(self.findings),
            metadata={"demo": True},
        )


class CloudConfigEvidenceSource(_StaticEvidenceSource):
    """Cloud security posture (CSPM) connector — AWS/Azure/GCP config state.

    Evidences data-protection, configuration, monitoring, and recovery controls
    that a vulnerability feed cannot speak to.
    """

    name = "Cloud Security Posture (CSPM)"
    description = (
        "Cloud configuration and control-plane state collected from the org's AWS/Azure/GCP "
        "accounts (encryption, logging, network exposure, backups, IAM policy). Sample data."
    )
    findings = [
        "Encryption at rest enabled on 96% of storage volumes and databases; 2 S3 buckets remain unencrypted.",
        "3 security groups allow inbound 0.0.0.0/0 on port 22 (SSH) to production subnets.",
        "CloudTrail / audit logging is enabled across all regions and shipped to a central, immutable log store.",
        "Automated daily snapshots and cross-region backups are configured for all production databases.",
        "Root/owner account has hardware MFA enforced; IAM password policy requires 14+ chars and rotation.",
        "GuardDuty / native threat detection is enabled and alerting to the SOC in all regions.",
        "1 public-facing load balancer is serving traffic over TLS 1.0 (deprecated).",
        "Resource tagging policy is enforced; 88% of resources carry an owner and data-classification tag.",
    ]


class IdentityProviderEvidenceSource(_StaticEvidenceSource):
    """Identity provider (IdP) connector — Okta / Entra ID / Google Workspace.

    Evidences identity, authentication, and access-governance controls.
    """

    name = "Identity Provider (IdP)"
    description = (
        "Identity and access state from the org's IdP (Okta/Entra/Google): SSO coverage, MFA "
        "enforcement, access reviews, privileged access, and joiner/mover/leaver automation. Sample data."
    )
    findings = [
        "SSO is enforced for 142 of 150 onboarded SaaS applications (95%).",
        "MFA is enforced for 98% of active users; 6 service accounts are exempt with documented compensating controls.",
        "Privileged/admin roles require phishing-resistant MFA (FIDO2 hardware keys).",
        "Quarterly access certification campaigns are run and logged; last campaign completed with 100% manager sign-off.",
        "12 user accounts have been inactive for over 90 days and are not yet deprovisioned.",
        "Automated joiner/mover/leaver workflow deprovisions departing staff within 1 hour of HR trigger.",
        "Role-based access control is defined for all production systems; least-privilege baseline documented.",
        "Conditional access blocks logins from anomalous geographies and unmanaged devices.",
    ]


# Registry of available sources for CLI selection.
DEMO_SOURCES = {
    "cloud": CloudConfigEvidenceSource,
    "idp": IdentityProviderEvidenceSource,
}
