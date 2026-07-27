"""Deterministic SSVC Deployer decision support.

PatchTriage is a deployer: it receives vulnerable software and decides how
quickly to apply a remediation or mitigation in *this* environment.  The
implementation below follows the CERT/CC SSVC Deployer decision table
(`ssvc:DT_DP:1.0.0`) and keeps inference provenance next to every value.

KEV and exploit references inform the current Exploitation state.  EPSS is
retained as supplemental predictive evidence, but does not get silently
converted into an observed exploitation state.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from .models import Finding


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Exploitation(str, Enum):
    NONE = "none"
    PUBLIC_POC = "public_poc"
    ACTIVE = "active"


class SystemExposure(str, Enum):
    SMALL = "small"
    CONTROLLED = "controlled"
    OPEN = "open"


class Automatable(str, Enum):
    NO = "no"
    YES = "yes"


class MissionImpact(str, Enum):
    DEGRADED = "degraded"
    MEF_SUPPORT_CRIPPLED = "mef_support_crippled"
    MEF_FAILURE = "mef_failure"
    MISSION_FAILURE = "mission_failure"


class SafetyImpact(str, Enum):
    NEGLIGIBLE = "negligible"
    MARGINAL = "marginal"
    CRITICAL = "critical"
    CATASTROPHIC = "catastrophic"


class HumanImpact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class TechnicalImpact(str, Enum):
    """Control an adversary gains over the component after exploitation.

    Not an input to the CERT/CC Deployer tree, which uses Human Impact
    instead. It is modeled because CISA publishes it authoritatively through
    Vulnrichment and because CISA BOD 26-04 prioritizes on it.
    """

    PARTIAL = "partial"
    TOTAL = "total"
    UNKNOWN = "unknown"


class DeployerDecision(str, Enum):
    DEFER = "defer"
    SCHEDULED = "scheduled"
    OUT_OF_CYCLE = "out_of_cycle"
    IMMEDIATE = "immediate"


_LABELS = {
    Exploitation.NONE.value: "None",
    Exploitation.PUBLIC_POC.value: "Public PoC",
    Exploitation.ACTIVE.value: "Active",
    SystemExposure.SMALL.value: "Small",
    SystemExposure.CONTROLLED.value: "Controlled",
    SystemExposure.OPEN.value: "Open",
    Automatable.NO.value: "No",
    Automatable.YES.value: "Yes",
    MissionImpact.DEGRADED.value: "Degraded",
    MissionImpact.MEF_SUPPORT_CRIPPLED.value: "MEF Support Crippled",
    MissionImpact.MEF_FAILURE.value: "MEF Failure",
    MissionImpact.MISSION_FAILURE.value: "Mission Failure",
    SafetyImpact.NEGLIGIBLE.value: "Negligible",
    SafetyImpact.MARGINAL.value: "Marginal",
    SafetyImpact.CRITICAL.value: "Critical",
    SafetyImpact.CATASTROPHIC.value: "Catastrophic",
    HumanImpact.LOW.value: "Low",
    HumanImpact.MEDIUM.value: "Medium",
    HumanImpact.HIGH.value: "High",
    HumanImpact.VERY_HIGH.value: "Very High",
    TechnicalImpact.PARTIAL.value: "Partial",
    TechnicalImpact.TOTAL.value: "Total",
    TechnicalImpact.UNKNOWN.value: "Unknown",
    DeployerDecision.DEFER.value: "Defer",
    DeployerDecision.SCHEDULED.value: "Scheduled",
    DeployerDecision.OUT_OF_CYCLE.value: "Out-of-Cycle",
    DeployerDecision.IMMEDIATE.value: "Immediate",
}

# CISA publishes Vulnrichment decision points with its own spelling. Mapping
# them explicitly keeps the wire format out of the decision logic.
_VULNRICHMENT_EXPLOITATION = {
    "none": Exploitation.NONE,
    "poc": Exploitation.PUBLIC_POC,
    "active": Exploitation.ACTIVE,
}

_VULNRICHMENT_AUTOMATABLE = {
    "yes": Automatable.YES,
    "no": Automatable.NO,
}

_VULNRICHMENT_TECHNICAL_IMPACT = {
    "partial": TechnicalImpact.PARTIAL,
    "total": TechnicalImpact.TOTAL,
}


class DecisionPoint(BaseModel):
    key: str
    version: str
    value: str
    label: str
    confidence: Confidence
    source: str
    evidence: list[str] = Field(default_factory=list)
    inferred: bool = True
    needs_confirmation: bool = False


class SSVCAssessment(BaseModel):
    model: str = "ssvc:DT_DP:1.0.0"
    exploitation: DecisionPoint
    system_exposure: DecisionPoint
    automatable: DecisionPoint
    mission_impact: DecisionPoint
    safety_impact: DecisionPoint
    human_impact: DecisionPoint
    # Supplemental, never an input to `decision`: the CERT/CC Deployer tree
    # takes Human Impact, not Technical Impact. Recorded for evidence and for
    # the CISA BOD 26-04 model, which does prioritize on it.
    technical_impact: Optional[DecisionPoint] = None
    decision: DeployerDecision
    decision_label: str
    priority: str
    suggested_deadline_days: int
    recommended_action: str
    confidence: Confidence
    needs_confirmation: list[str] = Field(default_factory=list)
    decision_path: str
    rationale: str
    supplemental: dict = Field(default_factory=dict)


_HUMAN_ORDER = (
    HumanImpact.LOW,
    HumanImpact.MEDIUM,
    HumanImpact.HIGH,
    HumanImpact.VERY_HIGH,
)

# Official Human Impact v2.0.2 compound decision table. Keeping all 16 rows
# explicit avoids accidentally treating the prose summary as a formula.
_HUMAN_IMPACT_TABLE = {
    (SafetyImpact.NEGLIGIBLE, MissionImpact.DEGRADED): HumanImpact.LOW,
    (SafetyImpact.NEGLIGIBLE, MissionImpact.MEF_SUPPORT_CRIPPLED): HumanImpact.LOW,
    (SafetyImpact.NEGLIGIBLE, MissionImpact.MEF_FAILURE): HumanImpact.MEDIUM,
    (SafetyImpact.NEGLIGIBLE, MissionImpact.MISSION_FAILURE): HumanImpact.VERY_HIGH,
    (SafetyImpact.MARGINAL, MissionImpact.DEGRADED): HumanImpact.LOW,
    (SafetyImpact.MARGINAL, MissionImpact.MEF_SUPPORT_CRIPPLED): HumanImpact.LOW,
    (SafetyImpact.MARGINAL, MissionImpact.MEF_FAILURE): HumanImpact.MEDIUM,
    (SafetyImpact.MARGINAL, MissionImpact.MISSION_FAILURE): HumanImpact.VERY_HIGH,
    (SafetyImpact.CRITICAL, MissionImpact.DEGRADED): HumanImpact.MEDIUM,
    (SafetyImpact.CRITICAL, MissionImpact.MEF_SUPPORT_CRIPPLED): HumanImpact.HIGH,
    (SafetyImpact.CRITICAL, MissionImpact.MEF_FAILURE): HumanImpact.HIGH,
    (SafetyImpact.CRITICAL, MissionImpact.MISSION_FAILURE): HumanImpact.VERY_HIGH,
    (SafetyImpact.CATASTROPHIC, MissionImpact.DEGRADED): HumanImpact.VERY_HIGH,
    (SafetyImpact.CATASTROPHIC, MissionImpact.MEF_SUPPORT_CRIPPLED): HumanImpact.VERY_HIGH,
    (SafetyImpact.CATASTROPHIC, MissionImpact.MEF_FAILURE): HumanImpact.VERY_HIGH,
    (SafetyImpact.CATASTROPHIC, MissionImpact.MISSION_FAILURE): HumanImpact.VERY_HIGH,
}

# Official SSVC Deployer decision table, compacted to one four-value row for
# each Exploitation / Exposure / Automatable path. Values are ordered by Human
# Impact: Low, Medium, High, Very High.
_DEPLOYER_TABLE: dict[
    tuple[Exploitation, SystemExposure, Automatable],
    tuple[DeployerDecision, DeployerDecision, DeployerDecision, DeployerDecision],
] = {
    (Exploitation.NONE, SystemExposure.SMALL, Automatable.NO):
        (DeployerDecision.DEFER, DeployerDecision.DEFER,
         DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED),
    (Exploitation.NONE, SystemExposure.SMALL, Automatable.YES):
        (DeployerDecision.DEFER, DeployerDecision.SCHEDULED,
         DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED),
    (Exploitation.NONE, SystemExposure.CONTROLLED, Automatable.NO):
        (DeployerDecision.DEFER, DeployerDecision.SCHEDULED,
         DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED),
    (Exploitation.NONE, SystemExposure.CONTROLLED, Automatable.YES):
        (DeployerDecision.SCHEDULED,) * 4,
    (Exploitation.NONE, SystemExposure.OPEN, Automatable.NO):
        (DeployerDecision.DEFER, DeployerDecision.SCHEDULED,
         DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED),
    (Exploitation.NONE, SystemExposure.OPEN, Automatable.YES):
        (DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED,
         DeployerDecision.SCHEDULED, DeployerDecision.OUT_OF_CYCLE),
    (Exploitation.PUBLIC_POC, SystemExposure.SMALL, Automatable.NO):
        (DeployerDecision.DEFER, DeployerDecision.SCHEDULED,
         DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED),
    (Exploitation.PUBLIC_POC, SystemExposure.SMALL, Automatable.YES):
        (DeployerDecision.SCHEDULED,) * 4,
    (Exploitation.PUBLIC_POC, SystemExposure.CONTROLLED, Automatable.NO):
        (DeployerDecision.DEFER, DeployerDecision.SCHEDULED,
         DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED),
    (Exploitation.PUBLIC_POC, SystemExposure.CONTROLLED, Automatable.YES):
        (DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED,
         DeployerDecision.SCHEDULED, DeployerDecision.OUT_OF_CYCLE),
    (Exploitation.PUBLIC_POC, SystemExposure.OPEN, Automatable.NO):
        (DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED,
         DeployerDecision.SCHEDULED, DeployerDecision.OUT_OF_CYCLE),
    (Exploitation.PUBLIC_POC, SystemExposure.OPEN, Automatable.YES):
        (DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED,
         DeployerDecision.OUT_OF_CYCLE, DeployerDecision.OUT_OF_CYCLE),
    (Exploitation.ACTIVE, SystemExposure.SMALL, Automatable.NO):
        (DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED,
         DeployerDecision.OUT_OF_CYCLE, DeployerDecision.OUT_OF_CYCLE),
    (Exploitation.ACTIVE, SystemExposure.SMALL, Automatable.YES):
        (DeployerDecision.SCHEDULED, DeployerDecision.OUT_OF_CYCLE,
         DeployerDecision.OUT_OF_CYCLE, DeployerDecision.OUT_OF_CYCLE),
    (Exploitation.ACTIVE, SystemExposure.CONTROLLED, Automatable.NO):
        (DeployerDecision.SCHEDULED, DeployerDecision.SCHEDULED,
         DeployerDecision.OUT_OF_CYCLE, DeployerDecision.OUT_OF_CYCLE),
    (Exploitation.ACTIVE, SystemExposure.CONTROLLED, Automatable.YES):
        (DeployerDecision.OUT_OF_CYCLE,) * 4,
    (Exploitation.ACTIVE, SystemExposure.OPEN, Automatable.NO):
        (DeployerDecision.SCHEDULED, DeployerDecision.OUT_OF_CYCLE,
         DeployerDecision.OUT_OF_CYCLE, DeployerDecision.IMMEDIATE),
    (Exploitation.ACTIVE, SystemExposure.OPEN, Automatable.YES):
        (DeployerDecision.OUT_OF_CYCLE, DeployerDecision.OUT_OF_CYCLE,
         DeployerDecision.IMMEDIATE, DeployerDecision.IMMEDIATE),
}


_DECISION_POLICY = {
    DeployerDecision.IMMEDIATE: ("P1", 3),
    DeployerDecision.OUT_OF_CYCLE: ("P2", 14),
    DeployerDecision.SCHEDULED: ("P3", 30),
    DeployerDecision.DEFER: ("P4", 90),
}

_CONFIDENCE_RANK = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


def _point(key: str, version: str, value: Enum, confidence: Confidence,
           source: str, evidence: list[str], *, inferred: bool = True,
           needs_confirmation: bool = False) -> DecisionPoint:
    return DecisionPoint(
        key=key,
        version=version,
        value=value.value,
        label=_LABELS[value.value],
        confidence=confidence,
        source=source,
        evidence=evidence,
        inferred=inferred,
        needs_confirmation=needs_confirmation,
    )


def _infer_exploitation(finding: Finding) -> DecisionPoint:
    explicit = (finding.ssvc_inputs or {}).get("exploitation")
    e = finding.enrichment
    if e.in_cisa_kev:
        evidence = ["CISA KEV confirms exploitation in the wild"]
        if e.kev_ransomware:
            evidence.append("CISA KEV reports ransomware campaign use")
        conflict = explicit in {
            Exploitation.NONE.value, Exploitation.PUBLIC_POC.value,
        }
        if conflict:
            evidence.append(
                "Analyst input conflicts with CISA KEV and cannot downgrade "
                f"Active exploitation to {_LABELS[explicit]}"
            )
        elif explicit == Exploitation.ACTIVE.value:
            evidence.append("Analyst-confirmed input agrees with CISA KEV")
        return _point(
            "E", "1.1.0", Exploitation.ACTIVE, Confidence.HIGH,
            "CISA KEV", evidence, inferred=True,
            needs_confirmation=conflict,
        )
    if explicit in {value.value for value in Exploitation}:
        value = Exploitation(explicit)
        return _point(
            "E", "1.1.0", value, Confidence.HIGH,
            "analyst-confirmed SSVC input",
            [f"Exploitation confirmed as {_LABELS[value.value]}"],
            inferred=False,
        )
    published = _VULNRICHMENT_EXPLOITATION.get(
        str(e.ssvc_exploitation or "").casefold())
    if published is not None:
        evidence = [
            f"CISA Vulnrichment publishes Exploitation as "
            f"{_LABELS[published.value]}"
        ]
        if e.ssvc_timestamp:
            evidence.append(f"CISA assessment timestamp {e.ssvc_timestamp}")
        if published is Exploitation.NONE and e.exploit_references:
            # Do not let an authoritative "none" silently bury contradicting
            # local evidence; surface both and ask for a human decision.
            evidence.append(
                f"{len(e.exploit_references)} public exploit reference(s) were "
                "also found and disagree with the published assessment"
            )
            return _point(
                "E", "1.1.0", Exploitation.PUBLIC_POC, Confidence.MEDIUM,
                "public exploit references (conflicts with CISA Vulnrichment)",
                evidence, inferred=True, needs_confirmation=True,
            )
        return _point(
            "E", "1.1.0", published, Confidence.HIGH,
            "CISA Vulnrichment", evidence, inferred=True,
        )
    if e.exploit_references:
        return _point(
            "E", "1.1.0", Exploitation.PUBLIC_POC, Confidence.MEDIUM,
            "public exploit references",
            [f"{len(e.exploit_references)} public exploit reference(s) found"],
            inferred=True,
        )
    coverage = sorted(set(e.exploit_sources_checked))
    # Existing integrations may predate exploit_sources_checked. Non-empty
    # NVD record fields still prove that the record and its references were
    # retrieved; generic sources/enriched_at alone do not.
    if not coverage and (
        e.nvd_cvss_score is not None or e.nvd_cvss_vector or e.cwe_ids
    ):
        coverage = ["nvd-record"]
    searched = bool(coverage)
    evidence = (
        ["No active exploitation or public PoC evidence was found in: "
         + ", ".join(coverage)]
        if searched else
        ["No completed exploit-source search is recorded; absence of "
         "evidence is not evidence of absence"]
    )
    return _point(
        "E", "1.1.0", Exploitation.NONE,
        Confidence.MEDIUM if searched else Confidence.LOW,
        "exploit-source coverage" if searched else "unconfirmed default",
        evidence,
        inferred=True,
        needs_confirmation=not searched,
    )


def _infer_system_exposure(finding: Finding) -> DecisionPoint:
    asset = finding.asset
    explicit = str(getattr(asset, "system_exposure", "unknown") or "unknown")
    try:
        value = SystemExposure(explicit)
    except ValueError:
        value = None
    if value is not None:
        return _point(
            "EXP", "1.0.1", value, Confidence.HIGH,
            "asset inventory", [f"System exposure confirmed as {_LABELS[value.value]}"],
            inferred=False,
        )
    if asset.internet_exposed is True:
        return _point(
            "EXP", "1.0.1", SystemExposure.OPEN, Confidence.MEDIUM,
            "legacy internet_exposed context",
            ["Asset is marked internet-exposed"],
            needs_confirmation=True,
        )
    if asset.internet_exposed is False:
        return _point(
            "EXP", "1.0.1", SystemExposure.CONTROLLED, Confidence.MEDIUM,
            "legacy internet_exposed context",
            ["Asset is marked non-internet-facing; access controls are not described"],
            needs_confirmation=True,
        )
    return _point(
        "EXP", "1.0.1", SystemExposure.OPEN, Confidence.LOW,
        "SSVC conservative default",
        ["Exposure is unknown; SSVC recommends assuming Open"],
        needs_confirmation=True,
    )


def _cvss_metrics(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in (vector or "").upper().split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    return metrics


def _infer_automatable(finding: Finding) -> DecisionPoint:
    explicit = (finding.ssvc_inputs or {}).get("automatable")
    if explicit in {value.value for value in Automatable}:
        value = Automatable(explicit)
        return _point(
            "A", "2.0.0", value, Confidence.HIGH,
            "analyst-confirmed SSVC input",
            [f"Automatable confirmed as {_LABELS[value.value]}"],
            inferred=False,
        )
    asset_value = str(getattr(finding.asset, "automatable", "unknown") or "unknown")
    if asset_value in (Automatable.YES.value, Automatable.NO.value):
        value = Automatable(asset_value)
        return _point(
            "A", "2.0.0", value, Confidence.HIGH,
            "asset inventory", [f"Automatable confirmed as {_LABELS[value.value]}"],
            inferred=False,
        )

    enrichment = finding.enrichment
    published = _VULNRICHMENT_AUTOMATABLE.get(
        str(enrichment.ssvc_automatable or "").casefold())
    if published is not None:
        evidence = [
            f"CISA Vulnrichment publishes Automatable as "
            f"{_LABELS[published.value]}"
        ]
        if enrichment.ssvc_timestamp:
            evidence.append(
                f"CISA assessment timestamp {enrichment.ssvc_timestamp}")
        return _point(
            "A", "2.0.0", published, Confidence.HIGH,
            "CISA Vulnrichment", evidence, inferred=True,
        )

    vector = enrichment.nvd_cvss_vector
    metrics = _cvss_metrics(vector)
    if metrics.get("AU") in ("Y", "N"):
        value = Automatable.YES if metrics["AU"] == "Y" else Automatable.NO
        return _point(
            "A", "2.0.0", value, Confidence.HIGH,
            "CVSS v4 Automatable", [f"CVSS vector contains AU:{metrics['AU']}"],
            inferred=True,
        )
    return _point(
        "A", "2.0.0", Automatable.YES, Confidence.LOW,
        "SSVC conservative default",
        ["Automation evidence is unknown; SSVC recommends assuming Yes"],
        needs_confirmation=True,
    )


def _infer_technical_impact(finding: Finding) -> DecisionPoint:
    """Record CISA's published Technical Impact, or an explicit Unknown.

    This point is supplemental: the CERT/CC Deployer tree does not consume
    it, so an Unknown here never changes a deployment decision. It is
    recorded as evidence and as the input CISA BOD 26-04 prioritizes on.
    """
    enrichment = finding.enrichment
    published = _VULNRICHMENT_TECHNICAL_IMPACT.get(
        str(enrichment.ssvc_technical_impact or "").casefold())
    if published is not None:
        evidence = [
            f"CISA Vulnrichment publishes Technical Impact as "
            f"{_LABELS[published.value]}"
        ]
        if enrichment.ssvc_timestamp:
            evidence.append(
                f"CISA assessment timestamp {enrichment.ssvc_timestamp}")
        return _point(
            "TI", "2.0.0", published, Confidence.HIGH,
            "CISA Vulnrichment", evidence, inferred=True,
        )
    return _point(
        "TI", "2.0.0", TechnicalImpact.UNKNOWN, Confidence.LOW,
        "not assessed",
        ["No published Technical Impact assessment was found for this CVE"],
        inferred=True,
    )


def _infer_mission_impact(finding: Finding) -> DecisionPoint:
    asset = finding.asset
    explicit = str(getattr(asset, "mission_impact", "unknown") or "unknown")
    try:
        value = MissionImpact(explicit)
    except ValueError:
        value = None
    if value is not None:
        return _point(
            "MI", "2.0.0", value, Confidence.HIGH,
            "asset inventory", [f"Mission impact confirmed as {_LABELS[value.value]}"],
            inferred=False,
        )

    criticality_map = {
        "critical": MissionImpact.MEF_FAILURE,
        "high": MissionImpact.MEF_SUPPORT_CRIPPLED,
        "medium": MissionImpact.DEGRADED,
        "low": MissionImpact.DEGRADED,
    }
    if asset.criticality in criticality_map:
        value = criticality_map[asset.criticality]
        return _point(
            "MI", "2.0.0", value, Confidence.MEDIUM,
            "business criticality fallback",
            [f"Legacy criticality '{asset.criticality}' maps to {_LABELS[value.value]}"],
            needs_confirmation=True,
        )
    return _point(
        "MI", "2.0.0", MissionImpact.MEF_SUPPORT_CRIPPLED, Confidence.LOW,
        "SSVC conservative default",
        ["Mission impact is unknown; SSVC recommends MEF Support Crippled"],
        needs_confirmation=True,
    )


def _infer_safety_impact(finding: Finding) -> DecisionPoint:
    explicit = str(getattr(finding.asset, "safety_impact", "unknown") or "unknown")
    try:
        value = SafetyImpact(explicit)
    except ValueError:
        value = None
    if value is not None:
        return _point(
            "SI", "2.0.1", value, Confidence.HIGH,
            "asset inventory", [f"Safety impact confirmed as {_LABELS[value.value]}"],
            inferred=False,
        )
    return _point(
        "SI", "2.0.1", SafetyImpact.MARGINAL, Confidence.LOW,
        "SSVC conservative default",
        ["Safety impact is unknown; SSVC recommends assuming Marginal"],
        needs_confirmation=True,
    )


def derive_human_impact(mission: MissionImpact,
                        safety: SafetyImpact) -> HumanImpact:
    """Apply the official Human Impact v2.0.2 combination table."""
    return _HUMAN_IMPACT_TABLE[(safety, mission)]


def deployer_decision(exploitation: Exploitation,
                      exposure: SystemExposure,
                      automatable: Automatable,
                      human_impact: HumanImpact) -> DeployerDecision:
    row = _DEPLOYER_TABLE[(exploitation, exposure, automatable)]
    return row[_HUMAN_ORDER.index(human_impact)]


def assess(finding: Finding) -> SSVCAssessment:
    exploitation = _infer_exploitation(finding)
    exposure = _infer_system_exposure(finding)
    automatable = _infer_automatable(finding)
    technical = _infer_technical_impact(finding)
    mission = _infer_mission_impact(finding)
    safety = _infer_safety_impact(finding)
    human_value = derive_human_impact(
        MissionImpact(mission.value), SafetyImpact(safety.value))
    human_confidence = min(
        (mission.confidence, safety.confidence),
        key=lambda value: _CONFIDENCE_RANK[value],
    )
    human = _point(
        "HI", "2.0.2", human_value, human_confidence,
        "SSVC Human Impact table",
        [f"{mission.label} mission impact + {safety.label} safety impact"],
        inferred=True,
        needs_confirmation=(mission.needs_confirmation or safety.needs_confirmation),
    )
    decision = deployer_decision(
        Exploitation(exploitation.value),
        SystemExposure(exposure.value),
        Automatable(automatable.value),
        human_value,
    )
    priority, days = _DECISION_POLICY[decision]
    has_fix = bool(finding.package.fixed_version)
    if not has_fix and decision != DeployerDecision.DEFER:
        action = "mitigate"
    elif decision == DeployerDecision.IMMEDIATE:
        action = "patch_immediately"
    elif decision == DeployerDecision.OUT_OF_CYCLE:
        action = "patch_out_of_cycle"
    elif decision == DeployerDecision.SCHEDULED:
        action = "patch_scheduled" if has_fix else "investigate"
    else:
        action = "monitor"

    points = (exploitation, exposure, automatable, mission, safety, human)
    confirmation = [
        name for name, point in (
            ("exploitation", exploitation),
            ("system_exposure", exposure),
            ("automatable", automatable),
            ("mission_impact", mission),
            ("safety_impact", safety),
        ) if point.needs_confirmation
    ]
    overall_confidence = min(
        (point.confidence for point in points),
        key=lambda value: _CONFIDENCE_RANK[value],
    )
    path = (
        f"E:{exploitation.label} / EXP:{exposure.label} / "
        f"A:{automatable.label} / HI:{human.label}"
    )
    rationale = (
        f"SSVC Deployer decision: {path} => {_LABELS[decision.value]}. "
        f"PatchTriage's example service target is {days} days; the SSVC "
        "standard itself defines the categorical outcome, not this deadline."
    )
    e = finding.enrichment
    return SSVCAssessment(
        exploitation=exploitation,
        system_exposure=exposure,
        automatable=automatable,
        mission_impact=mission,
        safety_impact=safety,
        human_impact=human,
        technical_impact=technical,
        decision=decision,
        decision_label=_LABELS[decision.value],
        priority=priority,
        suggested_deadline_days=days,
        recommended_action=action,
        confidence=overall_confidence,
        needs_confirmation=confirmation,
        decision_path=path,
        rationale=rationale,
        supplemental={
            "kev": e.in_cisa_kev,
            "epss": e.epss_score,
            "cvss": e.nvd_cvss_score or finding.cvss_score,
            "reachable": finding.asset.reachable,
            "runtime_observed": finding.asset.runtime_observed,
        },
    )


def triage_from_assessment(assessment: SSVCAssessment,
                           backend: str = "ssvc") -> dict:
    return {
        "priority": assessment.priority,
        "action": assessment.recommended_action,
        "rationale": assessment.rationale,
        "suggested_deadline_days": assessment.suggested_deadline_days,
        "backend": backend,
        "ssvc": assessment.model_dump(mode="json"),
    }


def ssvc_sort_key(finding: Finding) -> tuple[int, int, int, int, float, float]:
    """Return an ordinal-only tie-break key for findings in one priority.

    SSVC values are categories, not arithmetic scores.  The tuple preserves
    that property: each decision point is compared in order and is never added
    to or multiplied by another decision point.
    """
    assessment = (finding.triage or {}).get("ssvc") or assess(finding).model_dump(
        mode="json")
    exploitation_rank = {"none": 0, "public_poc": 1, "active": 2}
    human_rank = {"low": 0, "medium": 1, "high": 2, "very_high": 3}
    exposure_rank = {"small": 0, "controlled": 1, "open": 2}
    return (
        exploitation_rank.get(assessment["exploitation"]["value"], 0),
        human_rank.get(assessment["human_impact"]["value"], 0),
        exposure_rank.get(assessment["system_exposure"]["value"], 0),
        1 if assessment["automatable"]["value"] == "yes" else 0,
        finding.enrichment.epss_score or 0.0,
        finding.enrichment.nvd_cvss_score or finding.cvss_score or 0.0,
    )


def ssvc_order_key(finding: Finding) -> tuple[int, int, int, int, int, float, float]:
    """Sort highest-action-timing findings first without inventing a score."""
    priority_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    priority = (finding.triage or {}).get("priority", "P4")
    return (
        priority_rank.get(priority, 9),
        *(-value for value in ssvc_sort_key(finding)),
    )
