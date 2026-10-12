"""CISA BOD 26-04 response-policy evaluation, separate from the SSVC Deployer.

The CERT/CC SSVC Deployer result (``ssvc:DT_DP:1.0.0``) answers "how urgently
should this organization deploy?".  BOD 26-04 is a different, policy-specific
question: "what remediation timeline does the directive assign?".  It uses the
published CERT/CC response model ``cisa:DT_BOD2604:1.0.0`` whose four inputs
are *not* the Deployer inputs:

    In KEV (cisa:KEV:1.0.0)            vulnerability
    Publicly Exposed (cisa:PE:1.0.0)   asset state -- not SSVC System Exposure
    Automatable (ssvc:A:2.0.0)         vulnerability -- same point the Deployer uses
    Technical Impact (ssvc:TI:1.0.0)   vulnerability -- not Human Impact

This module never changes the Deployer result.  It records the policy result
next to it, and ``resolve_effective`` combines both through explicit, named
rules so the operational deadline always says which rule produced it.

Input rules implemented here, all taken from CISA's implementation guidance
(retrieved 2026-10-11) and nothing else:

* In KEV comes only from a completed KEV lookup.  A failed or stale-miss
  lookup leaves it unresolved; it never becomes "No".
* Automatable and Technical Impact come from analyst confirmation (Automatable
  only), CISA Vulnrichment, or a CVSS v4 ``AU`` metric (Automatable only).
  CISA's documented defaults -- Automatable "No" and Technical Impact "Total"
  -- are applied *only* when both values are unpublished, the Vulnrichment
  lookup completed, and the CVE is confirmed not to be in KEV.  For KEV CVEs
  CISA states it always publishes Vulnrichment data, so a gap stays
  unresolved instead of being defaulted.
* Publicly Exposed comes from an explicit operator answer.  Positive internet
  exposure evidence establishes "Yes" (CISA: any method that finds exposure
  sets "Yes"); negative or missing evidence does not establish "No".  CISA's
  best-effort chain for unknown exposure needs routable-IP and asset-type tags
  and CISA's public-facing analysis, which PatchTriage does not have, so its
  final "treat as internal" step is not applied automatically.

Unresolved inputs produce every candidate outcome.  When candidates disagree,
the result is ``unresolved`` with a clearly labelled *provisional* outcome
(the most urgent candidate); it is never presented as a compliance result.
"""

from __future__ import annotations

from itertools import product
from typing import Optional

from .models import Finding

POLICY_ID = "cisa:DT_BOD2604:1.0.0"
OUTCOME_GROUP = "cisa:BOD2604:1.0.0"

SOURCES = {
    "directive": {
        "title": "BOD 26-04: Prioritizing Security Updates Based on Risk",
        "url": "https://www.cisa.gov/news-events/directives/"
               "bod-26-04-prioritizing-security-updates-based-risk",
        "issued": "2026-06-10",
        "retrieved": "2026-10-11",
    },
    "implementation_guidance": {
        "title": "BOD 26-04 Implementation Guidance",
        "url": "https://www.cisa.gov/news-events/directives/"
               "bod-26-04-implementation-guidance-prioritizing-security-"
               "updates-based-risk",
        "retrieved": "2026-10-11",
    },
    "decision_model": {
        "title": "CERT/CC SSVC: CISA BOD 26-04 decision table",
        "url": "https://certcc.github.io/SSVC/howto/cisa_response/",
        "data": "https://github.com/CERTCC/SSVC/blob/main/data/csv/cisa/"
                "cisa_bod_26_04_1_0_0.csv",
        "retrieved": "2026-10-11",
    },
}

APPLICABILITY = {
    "unknown": "Applicability not recorded; BOD 26-04 is shown for reference only.",
    "not_applicable": "BOD 26-04 does not apply to this target; shown for reference only.",
    "required": "Federal civilian executive branch system: BOD 26-04 is a binding directive.",
    "voluntary": "Organization voluntarily adopts BOD 26-04 timelines; not a legal obligation.",
}
APPLIED = frozenset({"required", "voluntary"})

# Outcome definitions from cisa:BOD2604:1.0.0. ``days`` is a calendar-day
# maximum; FSU deliberately has no number.
OUTCOMES = {
    "FSU": {
        "label": "Fix on system upgrade",
        "days": None,
        "definition": "Remediate the next time the asset receives a scheduled "
                      "major upgrade or rebuild, unless conditions change.",
        "obligations": ["remediate_at_next_major_upgrade"],
    },
    "60D": {"label": "60 days", "days": 60,
            "definition": "Remediate within 60 calendar days.",
            "obligations": ["remediate"]},
    "14D": {"label": "14 days", "days": 14,
            "definition": "Remediate within 14 calendar days.",
            "obligations": ["remediate"]},
    "3D": {"label": "3 days", "days": 3,
           "definition": "Remediate within 3 calendar days.",
           "obligations": ["remediate"]},
    "3DF": {
        "label": "3 days & forensic triage",
        "days": 3,
        "definition": "Remediate or mitigate within 3 calendar days and carry "
                      "out a forensic triage of the asset to assess whether "
                      "it is compromised.",
        "obligations": ["remediate", "forensic_triage"],
    },
}
_URGENCY = {"FSU": 0, "60D": 1, "14D": 2, "3D": 3, "3DF": 4}

OBLIGATION_LABELS = {
    "remediate": "Remediate (patch, decommission, or otherwise eliminate)",
    "remediate_at_next_major_upgrade":
        "Remediate at the next scheduled major upgrade or rebuild",
    "forensic_triage":
        "Perform forensic triage per CISA's Forensic Triage Guidance",
}

DEADLINE_ANCHOR = (
    "Calendar days from the earlier of: CISA adding the CVE to KEV, or the "
    "agency identifying it on the asset and updating the CDM dashboards "
    "(BOD 23-01). Timelines are maximums and change when inputs change."
)

# cisa:DT_BOD2604:1.0.0, keyed (In KEV, Publicly Exposed, Automatable,
# Technical Impact). All 16 rows are explicit; conformance is tested against
# separately pinned data in data/bod2604_validation.json.
_TABLE: dict[tuple[str, str, str, str], str] = {
    ("no", "no", "no", "partial"): "FSU",
    ("yes", "no", "no", "partial"): "14D",
    ("no", "yes", "no", "partial"): "60D",
    ("no", "no", "yes", "partial"): "60D",
    ("no", "no", "no", "total"): "FSU",
    ("yes", "yes", "no", "partial"): "14D",
    ("yes", "no", "yes", "partial"): "14D",
    ("no", "yes", "yes", "partial"): "14D",
    ("yes", "no", "no", "total"): "14D",
    ("no", "yes", "no", "total"): "14D",
    ("no", "no", "yes", "total"): "60D",
    ("yes", "yes", "yes", "partial"): "3D",
    ("yes", "yes", "no", "total"): "3DF",
    ("yes", "no", "yes", "total"): "3DF",
    ("no", "yes", "yes", "total"): "3D",
    ("yes", "yes", "yes", "total"): "3DF",
}

_DOMAINS = {
    "in_kev": ("no", "yes"),
    "publicly_exposed": ("no", "yes"),
    "automatable": ("no", "yes"),
    "technical_impact": ("partial", "total"),
}
_POINT_IDS = {
    "in_kev": "cisa:KEV:1.0.0",
    "publicly_exposed": "cisa:PE:1.0.0",
    "automatable": "ssvc:A:2.0.0",
    "technical_impact": "ssvc:TI:1.0.0",
}


def bod_outcome(in_kev: str, publicly_exposed: str, automatable: str,
                technical_impact: str) -> str:
    """Look up one fully specified row of cisa:DT_BOD2604:1.0.0."""
    return _TABLE[(in_kev, publicly_exposed, automatable, technical_impact)]


def _input(name: str, value: str, source: str, basis: str,
           *, defaulted: bool = False) -> dict:
    return {
        "point": _POINT_IDS[name],
        "value": value,
        "source": source,
        "basis": basis,
        "defaulted": defaulted,
        "resolved": value != "unknown",
    }


def _in_kev(finding: Finding) -> dict:
    status = finding.enrichment.retrieval_status.get("kev", "")
    if finding.enrichment.in_cisa_kev or status in {"listed", "listed_stale"}:
        return _input("in_kev", "yes", "CISA KEV",
                      "CVE is listed in the CISA KEV catalog")
    if status == "not_listed":
        return _input("in_kev", "no", "CISA KEV",
                      "Completed KEV lookup did not list this CVE")
    reason = {
        "failed": "KEV lookup failed; non-membership is not established",
        "unknown_stale": "Only a stale KEV catalog was available; a miss "
                         "there does not establish non-membership",
        "not_applicable": "Identifier is not a CVE, so KEV membership "
                          "cannot be looked up",
    }.get(status, "No completed KEV lookup is recorded")
    return _input("in_kev", "unknown", "unresolved", reason)


def _publicly_exposed(finding: Finding) -> dict:
    explicit = str(getattr(finding.asset, "publicly_exposed", "unknown")
                   or "unknown")
    if explicit in ("yes", "no"):
        return _input("publicly_exposed", explicit, "operator-confirmed",
                      "Publicly Exposed answered for this target")
    if finding.asset.internet_exposed is True:
        return _input(
            "publicly_exposed", "yes", "internet exposure evidence",
            "Target is marked internet exposed; CISA sets Publicly Exposed "
            "to Yes when any method identifies exposure")
    return _input(
        "publicly_exposed", "unknown", "unresolved",
        "Publicly Exposed is not recorded. SSVC System Exposure is a "
        "different decision point and is not used. CISA's best-effort "
        "fallback needs routable-IP and asset-type tags PatchTriage does "
        "not hold")


def _vulnrichment_completed(finding: Finding) -> bool:
    return finding.enrichment.retrieval_status.get("vulnrichment") in {
        "found", "not_found"}


def _published_automatable(finding: Finding) -> Optional[dict]:
    explicit = (finding.ssvc_inputs or {}).get("automatable")
    if explicit in ("yes", "no"):
        return _input("automatable", explicit, "analyst-confirmed",
                      "Automatable confirmed by an analyst for this CVE")
    published = str(finding.enrichment.ssvc_automatable or "").casefold()
    if published in ("yes", "no"):
        return _input("automatable", published, "CISA Vulnrichment",
                      "CISA Vulnrichment publishes Automatable")
    for part in (finding.enrichment.nvd_cvss_vector or "").upper().split("/"):
        if part in ("AU:Y", "AU:N"):
            return _input("automatable", "yes" if part == "AU:Y" else "no",
                          "CVSS v4 Automatable",
                          f"CVSS v4 vector contains {part}")
    return None


def _published_technical_impact(finding: Finding) -> Optional[dict]:
    published = str(finding.enrichment.ssvc_technical_impact or "").casefold()
    if published in ("partial", "total"):
        return _input("technical_impact", published, "CISA Vulnrichment",
                      "CISA Vulnrichment publishes Technical Impact")
    return None


def _vulnerability_points(finding: Finding, in_kev: dict) -> tuple[dict, dict]:
    automatable = _published_automatable(finding)
    technical = _published_technical_impact(finding)
    if automatable and technical:
        return automatable, technical
    if (automatable is None and technical is None
            and in_kev["value"] == "no" and _vulnrichment_completed(finding)):
        basis = ("Neither value is published and the CVE is not in KEV; "
                 "CISA's implementation guidance applies this default "
                 "until metadata is published")
        return (
            _input("automatable", "no", "CISA guidance default", basis,
                   defaulted=True),
            _input("technical_impact", "total", "CISA guidance default",
                   basis, defaulted=True),
        )
    if in_kev["value"] == "yes":
        gap = ("CISA states it publishes Vulnrichment data for every KEV "
               "CVE; awaiting enrichment")
    elif not _vulnrichment_completed(finding):
        gap = "Vulnrichment lookup did not complete"
    elif in_kev["value"] == "unknown":
        gap = ("CISA's default applies only to CVEs confirmed not in KEV, "
               "and KEV membership is unresolved")
    else:
        gap = ("Only one of Automatable / Technical Impact is published; "
               "CISA's default covers the case where both are missing")
    return (
        automatable or _input("automatable", "unknown", "unresolved", gap),
        technical or _input("technical_impact", "unknown", "unresolved", gap),
    )


def _kev_date_added(finding: Finding) -> str:
    return str(getattr(finding.enrichment, "kev_date_added", "") or "")


def evaluate(finding: Finding) -> dict:
    """Return the BOD 26-04 policy result for one finding.

    The result is a plain dict so it can be stored in JSON reports and
    summaries without any further mapping.
    """
    applicability = str(getattr(finding.asset, "bod2604_applicability",
                                "unknown") or "unknown")
    in_kev = _in_kev(finding)
    exposed = _publicly_exposed(finding)
    automatable, technical = _vulnerability_points(finding, in_kev)
    inputs = {
        "in_kev": in_kev,
        "publicly_exposed": exposed,
        "automatable": automatable,
        "technical_impact": technical,
    }
    unresolved = [name for name, point in inputs.items()
                  if not point["resolved"]]
    choices = [
        _DOMAINS[name] if name in unresolved else (inputs[name]["value"],)
        for name in ("in_kev", "publicly_exposed", "automatable",
                     "technical_impact")
    ]
    candidates = sorted({bod_outcome(*row) for row in product(*choices)},
                        key=lambda key: _URGENCY[key], reverse=True)
    resolved = len(candidates) == 1
    outcome = candidates[0] if resolved else None
    provisional = None if resolved else candidates[0]
    shown = outcome or provisional
    result = {
        "policy": POLICY_ID,
        "outcome_group": OUTCOME_GROUP,
        "applicability": applicability,
        "applicability_note": APPLICABILITY.get(applicability,
                                                APPLICABILITY["unknown"]),
        "applied": applicability in APPLIED,
        "inputs": inputs,
        "unresolved_inputs": unresolved,
        "status": "resolved" if resolved else "unresolved",
        "outcome": outcome,
        "outcome_label": OUTCOMES[outcome]["label"] if outcome else None,
        "provisional_outcome": provisional,
        "provisional_label": (OUTCOMES[provisional]["label"]
                              if provisional else None),
        "candidate_outcomes": candidates,
        "deadline_days": OUTCOMES[shown]["days"],
        "definition": OUTCOMES[shown]["definition"],
        "obligations": list(OUTCOMES[shown]["obligations"]),
        "deadline_anchor": DEADLINE_ANCHOR,
        "kev_date_added": _kev_date_added(finding),
        "kev_due_date": str(finding.enrichment.kev_due_date or ""),
    }
    if unresolved and not resolved:
        result["rationale"] = (
            "BOD 26-04 outcome unresolved: "
            + ", ".join(name.replace("_", " ") for name in unresolved)
            + " not established. Candidate outcomes: "
            + ", ".join(OUTCOMES[c]["label"] for c in candidates)
            + f". Provisional (most urgent): {OUTCOMES[provisional]['label']}."
        )
    else:
        path = " / ".join(
            f"{name.replace('_', ' ').title()}:{inputs[name]['value']}"
            if inputs[name]["resolved"] else
            f"{name.replace('_', ' ').title()}:any"
            for name in inputs)
        result["rationale"] = (
            f"{POLICY_ID} path {path} => {OUTCOMES[outcome]['label']}.")
    return result


def resolve_effective(ssvc: dict, policy: dict) -> dict:
    """Combine the SSVC workflow target and the BOD result by explicit rules.

    Rules, in order:

    ``ssvc_only``                  BOD not applied to the target; the SSVC
                                   workflow target governs and BOD is a
                                   reference only.
    ``bod_unresolved_provisional`` BOD applied but inputs are missing; the
                                   earlier of the workflow target and the
                                   provisional BOD timeline is used and the
                                   result requires confirmation.
    ``bod_fix_on_upgrade``         BOD assigns no numeric deadline; the
                                   workflow target sets the working deadline
                                   and the next-upgrade obligation remains.
    ``bod_maximum``                BOD timeline is not later than the workflow
                                   target and is a regulatory maximum.
    ``workflow_target_stricter``   the organization's own target is earlier;
                                   it also satisfies the BOD maximum.

    Every applicable obligation (e.g. forensic triage) is preserved even when
    a shorter numeric deadline comes from another source.
    """
    ssvc_days = ssvc.get("suggested_deadline_days")
    ssvc_label = ssvc.get("decision_label", "")
    base = {
        "ssvc_outcome": ssvc_label,
        "ssvc_workflow_days": ssvc_days,
        "bod_outcome": policy.get("outcome") or policy.get("provisional_outcome"),
        "bod_status": policy.get("status"),
        "obligations": [],
        "requires_confirmation": False,
    }
    if not policy.get("applied"):
        base.update(
            rule="ssvc_only",
            deadline_days=ssvc_days,
            deadline_source="SSVC workflow target",
            explanation=(
                f"SSVC {ssvc_label}: PatchTriage workflow target "
                f"{ssvc_days} days. BOD 26-04 is not applied to this target "
                f"({policy.get('applicability', 'unknown')}); its result is "
                "shown for reference only."),
            obligations=["remediate"],
        )
        return base

    key = policy.get("outcome") or policy.get("provisional_outcome")
    bod_days = OUTCOMES[key]["days"]
    obligations = list(OUTCOMES[key]["obligations"])
    if "remediate" not in obligations and ssvc_days is not None:
        obligations.insert(0, "remediate")
    base["obligations"] = obligations
    label = OUTCOMES[key]["label"]
    if policy.get("status") != "resolved":
        days = (min(d for d in (ssvc_days, bod_days) if d is not None)
                if (ssvc_days is not None or bod_days is not None) else None)
        base.update(
            rule="bod_unresolved_provisional",
            deadline_days=days,
            deadline_source="provisional",
            requires_confirmation=True,
            explanation=(
                f"Provisional: BOD 26-04 inputs "
                f"{', '.join(policy.get('unresolved_inputs') or [])} are "
                f"unresolved. Using the most urgent candidate ({label}) "
                f"against the SSVC workflow target ({ssvc_days} days) until "
                "they are confirmed."),
        )
        return base
    if bod_days is None:
        base.update(
            rule="bod_fix_on_upgrade",
            deadline_days=ssvc_days,
            deadline_source="SSVC workflow target",
            explanation=(
                f"BOD 26-04 assigns {label}: remediate at the next scheduled "
                f"major upgrade or rebuild. The SSVC {ssvc_label} workflow "
                f"target ({ssvc_days} days) sets the working deadline; the "
                "upgrade obligation still applies."),
        )
    elif ssvc_days is None or bod_days <= ssvc_days:
        base.update(
            rule="bod_maximum",
            deadline_days=bod_days,
            deadline_source="BOD 26-04 maximum",
            explanation=(
                f"BOD 26-04 assigns {label}, a calendar-day maximum not later "
                f"than the SSVC {ssvc_label} workflow target ({ssvc_days} "
                "days)."),
        )
    else:
        base.update(
            rule="workflow_target_stricter",
            deadline_days=ssvc_days,
            deadline_source="SSVC workflow target",
            explanation=(
                f"The SSVC {ssvc_label} workflow target ({ssvc_days} days) is "
                f"earlier than the BOD 26-04 maximum ({label}) and satisfies "
                "it."),
        )
    return base


def apply_policy(findings: list[Finding]) -> list[Finding]:
    """Attach the BOD result and effective action to each triaged finding.

    The SSVC result in ``triage["ssvc"]`` and the triage priority are left
    untouched.
    """
    for finding in findings:
        if finding.triage is None:
            continue
        policy = evaluate(finding)
        # Only the deterministic SSVC record is consulted; free-form triage
        # fields (including any AI text) never reach the effective deadline.
        ssvc = dict(finding.triage.get("ssvc") or {})
        finding.triage["bod2604"] = policy
        finding.triage["effective"] = resolve_effective(ssvc, policy)
    return findings


def action_policy(group: list[Finding]) -> dict:
    """Aggregate the policy view for one package action.

    The most urgent BOD outcome among the action's findings is reported, and
    every obligation of every finding is kept (a forensic triage required by
    one finding is never dropped because another finding is more urgent).
    The effective deadline is the earliest effective deadline of the findings
    and records which rule produced it.
    """
    policies = [(f.triage or {}).get("bod2604") for f in group]
    effectives = [(f.triage or {}).get("effective") for f in group]
    pairs = [(p, e) for p, e in zip(policies, effectives) if p and e]
    if not pairs:
        return {}
    unresolved = sum(1 for p, _ in pairs if p["status"] != "resolved")
    keys = [p["outcome"] or p["provisional_outcome"] for p, _ in pairs]
    top = max(keys, key=lambda key: _URGENCY[key])
    obligations: list[str] = []
    for _, effective in pairs:
        for item in effective["obligations"]:
            if item not in obligations:
                obligations.append(item)
    timed = [e for _, e in pairs if e.get("deadline_days") is not None]
    governing = min(timed, key=lambda e: e["deadline_days"]) if timed else         pairs[0][1]
    first = pairs[0][0]
    return {
        "bod2604": {
            "policy": POLICY_ID,
            "outcome": top,
            "label": OUTCOMES[top]["label"],
            "status": "resolved" if not unresolved else "unresolved",
            "unresolved_findings": unresolved,
            "applicability": first["applicability"],
            "applied": first["applied"],
            "forensic_triage": any(
                "forensic_triage" in OUTCOMES[k]["obligations"] for k in keys),
        },
        "effective_deadline_days": governing.get("deadline_days"),
        "effective_rule": governing["rule"],
        "obligations": obligations,
    }


def summarize(findings: list[Finding]) -> dict:
    """Counts used by the GUI, CLI and report. Never a compliance verdict."""
    results = [(f.triage or {}).get("bod2604") for f in findings]
    results = [r for r in results if r]
    outcomes = {key: 0 for key in OUTCOMES}
    for r in results:
        if r["status"] == "resolved":
            outcomes[r["outcome"]] += 1
    applicability = sorted({r["applicability"] for r in results})
    return {
        "policy": POLICY_ID,
        "evaluated": len(results),
        "resolved": sum(1 for r in results if r["status"] == "resolved"),
        "unresolved": sum(1 for r in results if r["status"] != "resolved"),
        "outcomes": outcomes,
        "forensic_triage": sum(
            1 for r in results if "forensic_triage" in r["obligations"]),
        "applicability": applicability,
        "applied": any(r["applied"] for r in results),
        "sources": SOURCES,
    }
