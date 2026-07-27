"""Human-facing labels and evidence summaries for triage decisions."""

from __future__ import annotations

from .evalcmp import EvalRow
from .models import Finding


PRIORITY_DEFINITIONS: dict[str, dict[str, str]] = {
    "P1": {
        "label": "Immediate",
        "ssvc_outcome": "Immediate",
        "description": (
            "SSVC calls for immediate action with all necessary resources."
        ),
        "window": "3 days",
    },
    "P2": {
        "label": "Out-of-Cycle",
        "ssvc_outcome": "Out-of-Cycle",
        "description": (
            "Act at the next available opportunity outside normal maintenance."
        ),
        "window": "14 days",
    },
    "P3": {
        "label": "Scheduled",
        "ssvc_outcome": "Scheduled",
        "description": (
            "Handle during regularly scheduled maintenance."
        ),
        "window": "30 days",
    },
    "P4": {
        "label": "Defer",
        "ssvc_outcome": "Defer",
        "description": (
            "Do not act at present; monitor the evidence and reassess changes."
        ),
        "window": "90 days",
    },
}


def priority_definition(priority: str | None) -> dict[str, str]:
    """Return a safe copy of the human definition for a priority code."""
    code = priority if priority in PRIORITY_DEFINITIONS else "P4"
    return {"code": code, **PRIORITY_DEFINITIONS[code]}


def priority_display(priority: str | None) -> str:
    definition = priority_definition(priority)
    return f"{definition['code']} - {definition['label']}"


def priority_evidence(finding: Finding) -> list[dict[str, str]]:
    """Present the exact SSVC decision points without a parallel score model."""
    ssvc = (finding.triage or {}).get("ssvc") or {}
    point_names = (
        ("exploitation", "Exploitation"),
        ("system_exposure", "System Exposure"),
        ("automatable", "Automatable"),
        ("human_impact", "Human Impact"),
    )
    checks: list[dict[str, str]] = []
    for key, label in point_names:
        point = ssvc.get(key) or {}
        confidence = point.get("confidence", "low")
        status = "confirmed" if confidence == "high" else "attention"
        evidence = "; ".join(point.get("evidence") or [])
        checks.append({
            "label": label,
            "status": status,
            "value": (
                f"{point.get('label', 'Unknown')} · {evidence or 'evidence missing'} "
                f"({confidence} confidence)"
            ),
        })
    # Technical Impact is not a Deployer input, so it is shown as supporting
    # evidence rather than as one of the decision points above.
    technical = ssvc.get("technical_impact") or {}
    if technical:
        assessed = technical.get("value") not in (None, "unknown")
        checks.append({
            "label": "Technical Impact",
            "status": "confirmed" if assessed else "unknown",
            "value": (
                f"{technical.get('label', 'Unknown')} · "
                + ("; ".join(technical.get("evidence") or [])
                   or "not published for this CVE")
                + " (not an input to the Deployer decision)"
            ),
        })
    has_fix = bool(finding.package.fixed_version)
    checks.append(
        {"label": "Fix readiness", "status": "confirmed" if has_fix else "attention",
         "value": (f"Fixed version {finding.package.fixed_version} is available"
                   if has_fix else "No fixed version supplied; mitigate or investigate")}
    )
    return checks


def priority_basis(finding: Finding) -> str:
    """Explain the deterministic SSVC path behind the assigned priority."""
    triage = finding.triage or {}
    ssvc = triage.get("ssvc") or {}
    if ssvc.get("decision_path"):
        return (
            "The SSVC Deployer path "
            f"{ssvc['decision_path']} results in {ssvc.get('decision_label', 'this decision')}."
        )
    return (
        "This result is missing its SSVC decision path; rerun triage before relying "
        "on this recommendation."
    )


def evaluation_outcome(row: EvalRow, total_findings: int) -> dict[str, float | int | None]:
    """Translate one evaluation row into user-facing outcome measures."""
    reviewed = min(row.k, total_findings)
    review_reduction = (
        (1 - reviewed / total_findings) * 100 if total_findings else 0.0
    )
    ssvc_coverage = (
        row.kev_ssvc / row.kev_total * 100 if row.kev_total else 0.0
    )
    cvss_coverage = (
        row.kev_baseline / row.kev_total * 100 if row.kev_total else 0.0
    )
    return {
        "reviewed": reviewed,
        "review_reduction_pct": round(review_reduction, 1),
        "kev_coverage_pct": round(ssvc_coverage, 1),
        "kev_gain_points": round(ssvc_coverage - cvss_coverage, 1),
        "additional_kev_vs_cvss": row.kev_ssvc - row.kev_baseline,
        "kev_lift_vs_cvss": (
            round(row.kev_ssvc / row.kev_baseline, 1)
            if row.kev_baseline else None
        ),
        "urgent_coverage_pct": round(
            row.urgent_ssvc / row.urgent_total * 100, 1
        ) if row.urgent_total else 0.0,
    }
