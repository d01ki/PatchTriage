"""Run the triage pipeline for one registered target and summarize it."""

from __future__ import annotations

import json
import os
import time
from importlib import resources

from ..assess import assess
from ..assess import result_message as _result_message
from ..models import Asset
from ..bod2604 import summarize as summarize_response_policy
from ..presentation import (
    decision_quality,
    evaluation_outcome,
    priority_basis,
    priority_definition,
    priority_evidence,
)
from ..report.html import render_html
from ..ssvc import human_impact_branches, ssvc_order_key
from .. import targets as tstore


MAX_WEB_SSVC_INPUTS = max(
    1, int(os.environ.get("PATCHTRIAGE_MAX_WEB_SSVC_INPUTS", 250)))

# Per-target ceiling for the serialized action queue kept in the stored
# summary. Fleet aggregation merges these queues across targets, so the cap
# bounds fleet memory without hiding a target's most urgent work.
MAX_SUMMARY_ACTIONS = max(
    1, int(os.environ.get("PATCHTRIAGE_MAX_SUMMARY_ACTIONS", 25)))

# Findings whose Deployer path is serialized for the GUI decision-tree view.
MAX_DECISION_PATHS = max(
    1, int(os.environ.get("PATCHTRIAGE_MAX_DECISION_PATHS", 100)))

_SOURCE_NAMES = {
    "msrc": "Microsoft", "rhsa": "Red Hat", "usn": "Ubuntu",
    "debian": "Debian", "ghsa": "GitHub", "exploitdb": "Exploit-DB",
}


def _evidence_links(finding) -> list[dict]:
    """NVD, CISA KEV and vendor/exploit records for one finding."""
    links: list[dict] = []
    if finding.vuln_id.startswith("CVE-"):
        links.append({
            "source": "NVD", "label": finding.vuln_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{finding.vuln_id}"})
        if finding.enrichment.in_cisa_kev:
            links.append({
                "source": "CISA KEV", "label": "Known exploited",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-"
                       f"catalog?search_api_fulltext={finding.vuln_id}"})
    # Group by source so one prolific feed cannot hide another; public
    # exploit evidence comes first because it moves SSVC Exploitation.
    by_source: dict[str, list] = {}
    for advisory in finding.enrichment.vendor_advisories:
        by_source.setdefault(advisory.source, []).append(advisory)
    for source in ("exploitdb", "msrc", "rhsa", "debian", "usn", "ghsa"):
        records = by_source.get(source) or []
        for index, advisory in enumerate(records[:2]):
            url = advisory.url if advisory.url.startswith("https://") else ""
            links.append({
                "source": _SOURCE_NAMES.get(source, source),
                "label": advisory.advisory_id, "url": url,
                "more": len(records) - 2 if index == 1 and len(records) > 2
                else 0})
    return links


def decision_path(finding) -> dict | None:
    """The finding's Deployer path plus the Human Impact branches below it."""
    ssvc = (finding.triage or {}).get("ssvc") or {}
    if not ssvc:
        return None
    points = {
        key: {
            "value": (ssvc.get(key) or {}).get("value", ""),
            "label": (ssvc.get(key) or {}).get("label", ""),
            "source": (ssvc.get(key) or {}).get("source", ""),
            "confidence": (ssvc.get(key) or {}).get("confidence", ""),
            "needs_confirmation": bool(
                (ssvc.get(key) or {}).get("needs_confirmation")),
        }
        for key in ("exploitation", "system_exposure", "automatable",
                    "mission_impact", "safety_impact", "human_impact")
    }
    policy = (finding.triage or {}).get("bod2604") or {}
    return {
        "finding_key": finding.key,
        "vuln_id": finding.vuln_id,
        "package": finding.package.name,
        "version": finding.package.version,
        "version_source": finding.package.version_source,
        "fixed_version": finding.package.fixed_version,
        "asset": finding.asset.identifier,
        "model": ssvc.get("model", ""),
        "decision": ssvc.get("decision", ""),
        "decision_label": ssvc.get("decision_label", ""),
        "points": points,
        "branches": human_impact_branches(
            points["exploitation"]["value"],
            points["system_exposure"]["value"],
            points["automatable"]["value"]),
        "bod2604": ({
            "label": policy.get("outcome_label")
            or f"provisional {policy.get('provisional_label')}",
            "status": policy.get("status"),
            "applied": policy.get("applied"),
        } if policy else None),
        "evidence": _evidence_links(finding),
    }


def asset_from_target(target: dict) -> Asset:
    """Build the exact asset context consumed by the SSVC engine.

    Keeping this conversion pure makes it possible to verify that values
    entered in the GUI reach the decision engine unchanged. Automatable is a
    vulnerability-specific SSVC point, so the web target never applies one
    value to every finding; the engine derives it per vulnerability instead.
    """
    return Asset(
        identifier=target["name"],
        kind=("repository" if target.get("source_kind") == "repository" else
              "sbom" if target.get("source_format") in ("cyclonedx", "spdx")
              else "host"),
        criticality=target.get("criticality", "unknown"),
        internet_exposed=target.get("internet_exposed"),
        reachable=target.get("reachable"),
        runtime_observed=target.get("runtime_observed"),
        system_exposure=target.get("system_exposure", "unknown"),
        automatable="unknown",
        mission_impact=target.get("mission_impact", "unknown"),
        safety_impact=target.get("safety_impact", "unknown"),
        publicly_exposed=target.get("publicly_exposed", "unknown"),
        bod2604_applicability=target.get("bod2604_applicability", "unknown"),
        context_sources=target.get("context_sources") or [],
    )


def run_target(target: dict, backend: str = "rules", use_nvd: bool = True,
               nvd_api_key: str | None = None,
               vendor_sources: str | None = "auto",
               workspace_id: str | None = None) -> dict:
    """Ingest -> enrich -> triage -> plan -> report for one target.

    Returns a summary dict and writes the target's HTML report to disk.
    Raises ValueError if the target has no attached scan/SBOM.
    """
    started = time.perf_counter()
    expected_revision = int(target.get("input_revision") or 0)
    expected_source_sha256 = str(target.get("source_sha256") or "")
    source = target.get("source_file")
    if not source:
        raise ValueError("no scan or SBOM attached to this target")

    override = asset_from_target(target)
    source_provenance = dict(target.get("source_provenance") or {})
    provider_status = str(source_provenance.get("coverage_status") or "")
    if not provider_status and target.get("source_kind") in {"", "upload", None}:
        provider_status = "provider_reported"
    snapshot = None
    if target.get("demo"):
        data = resources.files("patchtriage") / "data"
        snapshot = {
            name: json.loads((data / f"demo_{name}.json").read_text(encoding="utf-8"))
            for name in ("epss", "kev", "nvd", "vulnrichment")
        }

    def record_coverage(coverage: dict) -> None:
        source_provenance["coverage"] = coverage
        source_provenance["coverage_status"] = coverage["status"]
        tstore.update_source_provenance_if_current(
            target["id"], source_provenance, expected_revision,
            expected_source_sha256, workspace_id)

    result = assess(
        [source], asset=override,
        ssvc_overrides=target.get("ssvc_overrides") or {},
        declared_coverage=dict(source_provenance.get("coverage") or {}),
        provider_status=provider_status, snapshot=snapshot,
        use_nvd=use_nvd, nvd_api_key=nvd_api_key,
        vendor_sources=vendor_sources,
        github_token=(os.environ.get("GITHUB_TOKEN") or
                      os.environ.get("GH_TOKEN")),
        backend=backend, on_coverage=record_coverage,
    )
    findings, actions, eval_rows = (
        result.findings, result.actions, result.eval_rows)
    run_coverage, audit = result.coverage, result.audit

    title = f"PatchTriage - {target['name']}"
    html = render_html(
        findings, actions, eval_rows, title=title,
        coverage=run_coverage,
        coverage_warnings=list(source_provenance.get("warnings") or []),
    )
    outcomes = {
        "immediate": 0, "out_of_cycle": 0, "scheduled": 0, "defer": 0,
    }
    for f in findings:
        decision = ((f.triage or {}).get("ssvc") or {}).get("decision", "defer")
        outcomes[decision if decision in outcomes else "defer"] += 1
    kev = sum(1 for f in findings if f.enrichment.in_cisa_kev)
    top = actions[0] if actions else None
    top_candidates = [
        f for f in findings if top and f.key in top.finding_keys]
    priority_candidates = [
        f for f in top_candidates
        if (f.triage or {}).get("priority", "P4") == top.top_priority
    ] if top else []
    top_finding_pool = priority_candidates or top_candidates
    top_finding = (
        min(top_finding_pool, key=ssvc_order_key) if top_finding_pool else None
    )
    explanation = None
    if top_finding:
        e = top_finding.enrichment
        priority = (top_finding.triage or {}).get("priority", "P4")
        priority_info = priority_definition(priority)
        ssvc = (top_finding.triage or {}).get("ssvc") or {}
        explanation = {
            "vuln_id": top_finding.vuln_id,
            "package": top_finding.package.name,
            "outcome_label": priority_info["ssvc_outcome"],
            "outcome_description": priority_info["description"],
            "basis": priority_basis(top_finding),
            "checks": priority_evidence(top_finding),
            "rationale": (top_finding.triage or {}).get("rationale", ""),
            "ssvc": ssvc,
            "bod2604": (top_finding.triage or {}).get("bod2604"),
            "effective": (top_finding.triage or {}).get("effective"),
            "confidence": ssvc.get("confidence", "low"),
            "needs_confirmation": ssvc.get("needs_confirmation", []),
            "cvss": e.nvd_cvss_score or top_finding.cvss_score,
            "epss": e.epss_score,
            "kev": e.in_cisa_kev,
            "retrieval_status": e.retrieval_status,
            "retrieval_errors": e.retrieval_errors,
            "ransomware": e.kev_ransomware,
            "has_fix": bool(top_finding.package.fixed_version),
            "advisories": [
                advisory.model_dump(mode="json")
                for advisory in e.vendor_advisories[:5]
            ],
        }
    comparison = None
    if eval_rows:
        row = eval_rows[0]
        comparison = {
            "k": row.k,
            "kev_total": row.kev_total,
            "kev": {
                "cvss": row.kev_baseline,
                "epss": row.kev_epss,
                "kev": row.kev_kev,
                "ssvc": row.kev_ssvc,
                "patchtriage": row.kev_patchtriage,
            },
            "epss_mass": {
                "cvss": row.epss_baseline,
                "epss": row.epss_epss,
                "kev": row.epss_kev,
                "ssvc": row.epss_ssvc,
                "patchtriage": row.epss_patchtriage,
            },
            "urgent": {
                "total": row.urgent_total,
                "cvss": row.urgent_cvss,
                "epss": row.urgent_epss,
                "kev": row.urgent_kev,
                "ssvc": row.urgent_ssvc,
            },
            "outcome": evaluation_outcome(row, len(findings)),
        }

    advisory_keys = {
        (advisory.source, advisory.advisory_id)
        for finding in findings
        for advisory in finding.enrichment.vendor_advisories
    }
    vendor_sources_checked = sorted({
        source for finding in findings
        for source in finding.enrichment.vendor_sources_checked
    })
    vendor_errors = sorted({
        error for finding in findings
        for error in finding.enrichment.vendor_lookup_errors
    })
    enrichment_errors = sorted({
        error for finding in findings
        for error in finding.enrichment.retrieval_errors
    })
    confirmation_fields = sorted({
        field
        for finding in findings
        for field in ((finding.triage or {}).get("ssvc") or {}).get(
            "needs_confirmation", [])
    })
    ordered_input_findings = sorted(findings, key=ssvc_order_key)
    ssvc_inputs = []
    review_total = 0
    for finding in ordered_input_findings:
        assessment = ((finding.triage or {}).get("ssvc") or {})
        exploitation = assessment.get("exploitation") or {}
        automatable = assessment.get("automatable") or {}
        needs_review = bool(
            exploitation.get("needs_confirmation")
            or automatable.get("needs_confirmation")
        )
        review_total += int(needs_review)
        if len(ssvc_inputs) >= MAX_WEB_SSVC_INPUTS:
            continue
        ssvc_inputs.append({
            "finding_key": finding.key,
            "vuln_id": finding.vuln_id,
            "package": finding.package.name,
            "exploitation": exploitation,
            "automatable": automatable,
            "override": finding.ssvc_inputs,
            "needs_review": needs_review,
        })

    coverage = source_provenance.get("coverage") or {}
    coverage_status = str(
        coverage.get("status") or source_provenance.get("coverage_status") or
        ("complete" if target.get("source_format") not in ("cyclonedx", "spdx")
         else "unknown")
    )
    incomplete = coverage_status != "complete"
    result = {
        "target_id": target["id"],
        "name": target["name"],
        "url": target.get("url", ""),
        "total": len(findings),
        "outcomes": outcomes,
        "kev": kev,
        "vendor_advisories": len(advisory_keys),
        "vendor_sources": vendor_sources_checked,
        "vendor_errors": vendor_errors,
        "enrichment_errors": enrichment_errors,
        "actions": len(actions),
        "decision_quality": decision_quality(findings),
        "audit_verified": audit["verified"],
        "audit_flagged": len(audit["flagged"]),
        "audit_rate": round(audit["verified"] / len(findings) * 100, 1)
        if findings else 100.0,
        "top_action": (top.summary if top else ""),
        "top_deadline_days": (top.deadline_days if top else None),
        "top_ssvc_decision": (
            ((top_finding.triage or {}).get("ssvc") or {}).get(
                "decision_label", "") if top_finding else ""
        ),
        "action_queue": [
            {
                "action_id": action.action_id,
                "kind": action.kind,
                "summary": action.summary,
                "package": action.package,
                "ecosystem": action.ecosystem,
                "installed_version": action.installed_version,
                "target_version": action.target_version,
                "top_priority": action.top_priority,
                "outcome_label": priority_definition(
                    action.top_priority)["ssvc_outcome"],
                "deadline_days": action.deadline_days,
                "kev_count": action.kev_count,
                "cves": action.cves[:8],
                "finding_count": len(action.finding_keys),
                "bod2604": action.bod2604,
                "effective_deadline_days": action.effective_deadline_days,
                "effective_rule": action.effective_rule,
                "obligations": action.obligations,
            }
            for action in actions[:MAX_SUMMARY_ACTIONS]
        ],
        "action_queue_truncated": len(actions) > MAX_SUMMARY_ACTIONS,
        "response_policy": summarize_response_policy(findings),
        "evaluated_context": {
            "system_exposure": override.system_exposure,
            "mission_impact": override.mission_impact,
            "safety_impact": override.safety_impact,
            "publicly_exposed": override.publicly_exposed,
            "bod2604_applicability": override.bod2604_applicability,
            "context_sources": override.context_sources,
        },
        "result_state": (
            "coverage_incomplete" if not findings and incomplete else
            "no_findings" if not findings else
            "assessed_incomplete" if incomplete and actions else
            "assessed" if actions else "no_plan"
        ),
        "result_message": _result_message(
            findings, actions, incomplete, coverage_status, run_coverage),
        "source": {
            "kind": target.get("source_kind") or "upload",
            "format": target.get("source_format", ""),
            "name": target.get("source_name", ""),
            "sha256": target.get("source_sha256", ""),
            "size": target.get("source_size", 0),
            "provenance": source_provenance,
            "coverage_status": coverage_status,
        },
        "ssvc_confirmation_fields": confirmation_fields,
        "ssvc_inputs": ssvc_inputs,
        "decision_paths": [
            path for path in (
                decision_path(f)
                for f in ordered_input_findings[:MAX_DECISION_PATHS])
            if path
        ],
        "decision_paths_truncated": (
            len(ordered_input_findings) > MAX_DECISION_PATHS),
        "ssvc_inputs_total": len(ordered_input_findings),
        "ssvc_inputs_review_total": review_total,
        "ssvc_inputs_truncated": len(ordered_input_findings) > len(ssvc_inputs),
        "explanation": explanation,
        "comparison": comparison,
        "demo": bool(target.get("demo")),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "report_url": f"/report/{target['id']}",
    }
    tstore.save_run_artifacts(
        target["id"], result, html, expected_revision,
        expected_source_sha256, workspace_id)
    return result
