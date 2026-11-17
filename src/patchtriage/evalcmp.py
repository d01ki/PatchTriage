"""Practicality evaluation.

Question to measure: under the same review budget, how do severity-only,
probability-only, observed-exploitation-first, and environment-specific SSVC
orderings differ? SSVC is allowed to place a KEV finding behind a more urgent
deployment decision; the comparison makes that tradeoff visible.

Method: for the same finding set, produce four orderings —
    CVSS baseline: CVSS descending
    EPSS baseline: EPSS descending (the strongest simple alternative)
    KEV baseline : known-exploited first, then EPSS
    SSVC         : Deployer decision, then deterministic context tie-breaker
and compare, at each budget k ("you only have time to fix k findings"):

    KEV@k    — how many known-exploited (CISA KEV) findings are inside top-k
    EPSS@k   — sum of exploitation probability captured inside top-k
    Urgent@k — how many SSVC Immediate / Out-of-Cycle decisions are inside top-k

KEV and EPSS are third-party data (CISA / FIRST). Urgent@k is deliberately
reported as a context-consistency measure, not independent ground truth:
its label comes from SSVC itself, so SSVC's own ordering always captures it
and is shown as a reference column, never as a winner. Measuring whether the
ordering actually reduced harm needs labels fixed independently of the
engine (for example later exploitation or incident records).

``boundary_ties`` names the orderings whose top-k cut falls inside a group
of findings with identical ordering keys; there the counts depend on input
order. ``evaluation_context`` records the denominator and missing signals.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .models import Finding
from .ssvc import ssvc_order_key


class EvalRow(BaseModel):
    k: int
    kev_baseline: int
    kev_epss: int
    kev_kev: int
    kev_ssvc: int
    kev_patchtriage: int
    kev_total: int
    epss_baseline: float
    epss_epss: float
    epss_kev: float
    epss_ssvc: float
    epss_patchtriage: float
    epss_total: float
    urgent_cvss: int
    urgent_epss: int
    urgent_kev: int
    urgent_ssvc: int
    urgent_total: int
    boundary_ties: list[str] = Field(default_factory=list)


def _cvss(f: Finding) -> float:
    return f.enrichment.nvd_cvss_score or f.cvss_score or 0.0


# Each ordering's key, highest first. One definition serves both the sort
# and the tie check, so they cannot drift apart.
_ORDER_KEYS = {
    "cvss": lambda f: (_cvss(f),),
    "epss": lambda f: (f.enrichment.epss_score or 0.0, _cvss(f)),
    "kev": lambda f: (f.enrichment.in_cisa_kev,
                      f.enrichment.epss_score or 0.0, _cvss(f)),
}


def _order(findings: list[Finding], name: str) -> list[Finding]:
    return sorted(findings, key=_ORDER_KEYS[name], reverse=True)


def _order_baseline(findings: list[Finding]) -> list[Finding]:
    return _order(findings, "cvss")


def _order_ssvc(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=ssvc_order_key)


def _order_kev(findings: list[Finding]) -> list[Finding]:
    return _order(findings, "kev")


def _is_urgent(finding: Finding) -> bool:
    return (finding.triage or {}).get("priority") in ("P1", "P2")


def _order_epss(findings: list[Finding]) -> list[Finding]:
    return _order(findings, "epss")


def _boundary_ties(orders: dict[str, tuple[list[Finding], object]],
                   k: int) -> list[str]:
    """Orderings whose top-k counts depend on input order.

    That happens only when the cut splits findings with equal ordering keys
    that differ in something the row counts (KEV, urgency, or EPSS).
    """
    tied = []
    for name, (ordered, key) in orders.items():
        if not 0 < k < len(ordered):
            continue
        boundary = key(ordered[k - 1])
        group = {(f.enrichment.in_cisa_kev, _is_urgent(f),
                  f.enrichment.epss_score or 0.0)
                 for f in ordered if key(f) == boundary}
        if key(ordered[k]) == boundary and len(group) > 1:
            tied.append(name)
    return tied


_KEV_RESOLVED = frozenset({"listed", "listed_stale", "not_listed"})


def evaluation_context(findings: list[Finding]) -> dict:
    """What the comparison rests on, so its counts can be interpreted."""
    return {
        "findings": len(findings),
        "kev_listed": sum(1 for f in findings if f.enrichment.in_cisa_kev),
        # A failed or stale lookup proves nothing about membership, so these
        # findings are not known to be outside KEV even though they count as
        # not listed in the KEV columns.
        "kev_unknown": sum(
            1 for f in findings if not f.enrichment.in_cisa_kev
            and f.enrichment.retrieval_status.get("kev") not in _KEV_RESOLVED),
        "epss_missing": sum(
            1 for f in findings if f.enrichment.epss_score is None),
        "cvss_missing": sum(
            1 for f in findings
            if f.enrichment.nvd_cvss_score is None and f.cvss_score is None),
        "missing_signal_rule": "a missing EPSS or CVSS sorts as 0",
        "urgent_label": (
            "SSVC Immediate/Out-of-Cycle from this same run; a "
            "self-consistency check, not independent ground truth"),
    }


def evaluate(findings: list[Finding],
             budgets: list[int] | None = None) -> list[EvalRow]:
    if not findings:
        return []
    base = _order_baseline(findings)
    epss_order = _order_epss(findings)
    kev_order = _order_kev(findings)
    ssvc_order = _order_ssvc(findings)
    orders = {
        "cvss": (base, _ORDER_KEYS["cvss"]),
        "epss": (epss_order, _ORDER_KEYS["epss"]),
        "kev": (kev_order, _ORDER_KEYS["kev"]),
        "ssvc": (ssvc_order, ssvc_order_key),
    }
    kev_total = sum(1 for f in findings if f.enrichment.in_cisa_kev)
    epss_total = sum(f.enrichment.epss_score or 0.0 for f in findings)
    urgent_total = sum(1 for f in findings if _is_urgent(f))
    n = len(findings)
    budgets = budgets or sorted({max(1, n // 4), max(1, n // 2), n})

    rows = []
    for k in budgets:
        k = min(k, n)
        rows.append(EvalRow(
            k=k,
            kev_baseline=sum(1 for f in base[:k] if f.enrichment.in_cisa_kev),
            kev_epss=sum(1 for f in epss_order[:k] if f.enrichment.in_cisa_kev),
            kev_kev=sum(1 for f in kev_order[:k] if f.enrichment.in_cisa_kev),
            kev_ssvc=sum(1 for f in ssvc_order[:k] if f.enrichment.in_cisa_kev),
            kev_patchtriage=sum(
                1 for f in ssvc_order[:k] if f.enrichment.in_cisa_kev),
            kev_total=kev_total,
            epss_baseline=round(sum(f.enrichment.epss_score or 0 for f in base[:k]), 3),
            epss_epss=round(sum(f.enrichment.epss_score or 0 for f in epss_order[:k]), 3),
            epss_kev=round(sum(
                f.enrichment.epss_score or 0 for f in kev_order[:k]), 3),
            epss_ssvc=round(sum(
                f.enrichment.epss_score or 0 for f in ssvc_order[:k]), 3),
            epss_patchtriage=round(sum(
                f.enrichment.epss_score or 0 for f in ssvc_order[:k]), 3),
            epss_total=round(epss_total, 3),
            urgent_cvss=sum(1 for f in base[:k] if _is_urgent(f)),
            urgent_epss=sum(1 for f in epss_order[:k] if _is_urgent(f)),
            urgent_kev=sum(1 for f in kev_order[:k] if _is_urgent(f)),
            urgent_ssvc=sum(1 for f in ssvc_order[:k] if _is_urgent(f)),
            urgent_total=urgent_total,
            boundary_ties=_boundary_ties(orders, k),
        ))
    return rows
