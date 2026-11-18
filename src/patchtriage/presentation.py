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


# Sources that represent someone's published or recorded judgement rather
# than a PatchTriage fallback. A decision resting on one of these is
# defensible without further human work.
_AUTHORITATIVE_SOURCES = (
    "CISA KEV",
    "CISA Vulnrichment",
    "analyst-confirmed SSVC input",
    "asset inventory",
    "CVSS v4 Automatable",
)


def priority_definition(priority: str | None) -> dict[str, str]:
    """Return a safe copy of the human definition for a priority code."""
    code = priority if priority in PRIORITY_DEFINITIONS else "P4"
    return {"code": code, **PRIORITY_DEFINITIONS[code]}


def _point_source(finding: Finding, name: str) -> str:
    point = ((finding.triage or {}).get("ssvc") or {}).get(name) or {}
    return str(point.get("source") or "")


def decision_quality(findings: list[Finding]) -> dict:
    """Summarize how much of this run rests on authority vs assumption.

    Only the two vulnerability-specific points are counted. System Exposure,
    Mission Impact and Safety Impact describe the deployer's own environment,
    so "the operator told us" is the only possible source and including them
    would inflate the number.

    ``de_escalated`` counts findings where a published assessment is *less*
    urgent than the conservative default PatchTriage would otherwise apply.
    Those are the findings that were being over-prioritized, which is the
    part of an authoritative feed that is easy to miss.
    """
    counted = ("exploitation", "automatable")
    sources: dict[str, int] = {}
    authoritative = 0
    de_escalated = 0
    needs_confirmation = 0

    for finding in findings:
        ssvc = (finding.triage or {}).get("ssvc") or {}
        if not ssvc:
            continue
        if ssvc.get("needs_confirmation"):
            needs_confirmation += 1
        for name in counted:
            source = _point_source(finding, name)
            if not source:
                continue
            sources[source] = sources.get(source, 0) + 1
            if source in _AUTHORITATIVE_SOURCES:
                authoritative += 1
        automatable = ssvc.get("automatable") or {}
        if (automatable.get("source") == "CISA Vulnrichment"
                and automatable.get("value") == "no"):
            de_escalated += 1

    assessed = [f for f in findings if (f.triage or {}).get("ssvc")]
    points_total = len(assessed) * len(counted)
    return {
        "findings": len(assessed),
        "points_total": points_total,
        "authoritative": authoritative,
        "assumed": points_total - authoritative,
        "authoritative_pct": (
            round(authoritative / points_total * 100, 1) if points_total else 0.0
        ),
        "needs_confirmation": needs_confirmation,
        "de_escalated": de_escalated,
        "sources": dict(sorted(sources.items(), key=lambda item: -item[1])),
    }


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
    fix = fix_status(finding)
    checks.append(
        {"label": "Fix readiness",
         "status": "confirmed" if fix["available"] else "attention",
         "value": fix["detail"]}
    )
    return checks


_FIX_STATE_TEXT = {
    "fixed": ("Fixed, version not supplied",
              "The scanner reports a fix but no fixed version; confirm the "
              "release in vendor guidance"),
    "wont_fix": ("Won't fix",
                 "The scanner reports that the vendor will not fix this "
                 "package; mitigate or replace the component"),
    "end_of_life": ("End of life",
                    "The scanner reports this release is end of life and "
                    "receives no fixes; move to a supported release or "
                    "replace the component"),
    "fix_deferred": ("Fix deferred",
                     "The scanner reports the vendor has deferred a fix, "
                     "possibly indefinitely; mitigate and review the "
                     "vendor's decision"),
    "not_fixed": ("Not yet fixed",
                  "The scanner reports no fix released yet; mitigate and "
                  "track the vendor fix"),
    "not_affected": ("Reported not affected",
                     "The scanner reports the vendor considers this package "
                     "not affected; confirm before closing the finding"),
    "unknown": ("Fix status unknown",
                "The scanner could not determine whether a fix exists; "
                "mitigate or investigate"),
    "": ("Not supplied",
         "No fixed version supplied; mitigate or investigate"),
}


def advisory_fixed_versions(finding: Finding) -> list[str]:
    """Fixed releases named by enriched vendor advisories for this CVE."""
    return sorted({
        version for advisory in finding.enrichment.vendor_advisories
        for version in advisory.fixed_versions if version
    })


def fix_status(finding: Finding) -> dict:
    """One fix label for CLI, GUI and HTML.

    A fixed version decides availability, as it does for the SSVC action;
    the scanner's fix state only explains why no version is available.
    Disagreeing scanners, or a vendor advisory that names a fix the
    scanner did not, are stated rather than resolved by picking a side.
    """
    package = finding.package
    conflict = list(package.fix_states_reported)
    if package.fixed_version:
        label = "Available"
        detail = f"Fixed version {package.fixed_version} is available"
    elif conflict:
        label = "Scanners disagree"
        detail = ("Scanners report different fix states ("
                  + ", ".join(_FIX_STATE_TEXT[s][0] for s in conflict)
                  + "); confirm with vendor guidance")
    else:
        label, detail = _FIX_STATE_TEXT.get(
            package.fix_state, _FIX_STATE_TEXT[""])
    advisory_fixes = advisory_fixed_versions(finding)
    if advisory_fixes and not package.fixed_version:
        detail += ("; vendor advisories list fixed releases ("
                   + ", ".join(advisory_fixes[:3])
                   + "), confirm which applies to this package")
    return {"available": bool(package.fixed_version),
            "state": package.fix_state, "label": label, "detail": detail}


def ai_explanation(triage: dict) -> dict | None:
    """The AI explanation, kept apart from the deterministic decision.

    None when no AI text was produced (rules backend, or the provider failed
    and the deterministic result was used). ``verified`` is None until the
    audit has run.
    """
    ai = triage.get("ai_recommendation")
    if not isinstance(ai, dict):
        return None
    text = str(ai.get("rationale") or "").strip()
    steps = [str(step) for step in ai.get("remediation_steps") or []]
    uncertainties = [str(item) for item in ai.get("uncertainties") or []]
    if not (text or steps or uncertainties):
        return None
    from .triage.audit import AUDIT_LIMITATIONS, is_ai_flag

    audit = triage.get("audit") if isinstance(triage.get("audit"), dict) else {}
    flags = [flag for flag in audit.get("flags") or [] if is_ai_flag(flag)]
    return {
        "text": text,
        "remediation_steps": steps,
        "uncertainties": uncertainties,
        "backend": str(triage.get("backend") or ""),
        # Only checks of the AI text and action count here; problems with
        # the deterministic result are shown with the decision itself.
        "verified": (not flags) if audit else None,
        "flags": flags,
        "limitations": AUDIT_LIMITATIONS,
    }


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
