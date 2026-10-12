"""One assessment core shared by the CLI and the web GUI.

ingest -> dedup -> context -> enrich -> SSVC -> (AI) -> audit -> BOD 26-04
-> plan -> evaluate. Entry points only gather inputs and present the result,
so the same evidence and context always reach the same decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .bod2604 import apply_policy as apply_response_policy
from .context import apply_context, load_inventory
from .dedup import dedup
from .enrich.clients import enrich, enrich_from_snapshot
from .evalcmp import evaluate
from .ingest.parsers import load_file_with_metadata
from .models import Asset
from .plan import build_plan
from .ssvc import ssvc_order_key
from .triage.audit import audit_all
from .triage.engine import get_backend, run_triage, run_triage_batch

_ASSET_CONTEXT_FIELDS = (
    "criticality", "internet_exposed", "reachable", "runtime_observed",
    "system_exposure", "automatable", "mission_impact", "safety_impact",
    "publicly_exposed", "bod2604_applicability",
)


@dataclass
class Assessment:
    findings: list
    subset: list            # findings reported: top-N after SSVC screening
    actions: list
    eval_rows: list
    coverage: dict
    audit: dict = field(default_factory=dict)


def combine_coverage(declared: dict, observed: dict,
                     provider_status: str) -> dict:
    """Merge coverage without letting one successful parser erase a boundary."""
    coverage = {**declared, **observed}
    complete = (
        observed.get("complete") is True
        and declared.get("complete") is not False
        and provider_status in {"", "complete"}
    )
    if provider_status and provider_status != "complete":
        status = provider_status
    elif complete:
        status = "complete"
    else:
        status = "incomplete"
    coverage["status"] = status
    coverage["complete"] = status == "complete"
    return coverage


def merge_file_coverage(coverages: list[dict]) -> dict:
    """Combine per-file coverage; one incomplete file keeps the whole bounded."""
    if len(coverages) == 1:
        return coverages[0]
    merged: dict[str, Any] = {
        "source_type": "+".join(
            str(c.get("source_type") or "unknown") for c in coverages),
        "complete": all(c.get("complete") is True for c in coverages),
    }
    for coverage in coverages:
        for key, value in coverage.items():
            if key in ("source_type", "complete"):
                continue
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                merged[key] = merged.get(key, 0) + value
            elif isinstance(value, list):
                merged.setdefault(key, [])
                merged[key] += [v for v in value if v not in merged[key]]
    return merged


def result_message(findings: list, actions: list, incomplete: bool,
                   coverage_status: str, coverage: dict) -> str:
    """Say what was actually checked, not just that coverage was bounded.

    "No findings" is the most dangerous result a scanner can show, because it
    reads as safety. When components were skipped it has to say which ones
    and why, otherwise a run that checked only CI actions -- while every
    application dependency went unqueryable for want of a resolved version --
    looks identical to a genuinely clean repository.
    """
    total = int(coverage.get("total_components") or 0)
    checked = int(coverage.get("queried_components") or 0)
    skipped = int(coverage.get("unqueryable_components") or 0)
    names = [str(name) for name in (coverage.get("unqueryable_names") or [])]
    checked_ecosystems = [
        str(eco) for eco in (coverage.get("queried_ecosystems") or [])]
    inferred = int(coverage.get("inferred_components") or 0)
    inferred_note = (
        f" {inferred} component(s) had only a declared constraint or none, "
        "so each was checked at a registry release chosen from it (the "
        "oldest a lower-bounded range permits, otherwise the newest), not "
        "necessarily the deployed version." if inferred else "")

    if findings:
        if incomplete and actions:
            return ("Assessment completed, but evidence coverage is bounded: "
                    f"{checked} of {total} component(s) could be checked."
                    + inferred_note
                    if total else
                    "Assessment completed with bounded or incomplete "
                    "evidence coverage.")
        if not actions:
            return ("Assessment completed, but no remediation action could "
                    "be built.")
        return ""

    if inferred and total and not skipped:
        return (f"{checked} of {total} component(s) were checked against OSV "
                "and none had a known vulnerability." + inferred_note
                + " Commit a lockfile or upload scanner output to assess the "
                "exact deployed versions.")
    if skipped and total:
        examples = ", ".join(names[:5])
        more = f" and {len(names) - 5} more" if len(names) > 5 else ""
        detail = (
            f"{checked} of {total} component(s) were checked against OSV and "
            f"none had a known vulnerability. {skipped} component(s) could "
            "not be checked because the source lists them without a resolved "
            "version"
        )
        if examples:
            detail += f": {examples}{more}"
        if inferred:
            detail += "." + inferred_note.rstrip(".")
        if checked and not any(
                eco.lower() not in {"githubactions", "github"}
                for eco in checked_ecosystems):
            detail += (
                ". Everything that could be checked was CI/workflow tooling, "
                "so no application dependency was actually assessed"
            )
        return detail + (
            ". Commit a lockfile (uv.lock, poetry.lock, package-lock.json, "
            "pinned requirements.txt) or upload scanner output for full "
            "coverage."
        )
    if coverage_status == "provider_reported":
        return ("No findings were reported. The evidence scope is what the "
                "provider chose to report and was not independently "
                "verified.")
    if incomplete:
        return ("No findings were reported, but dependency or selector "
                "coverage is incomplete.")
    return "The attached evidence reported no vulnerability findings."


def _load(path: Path, fmt: str | None, asset: Asset | None, progress):
    """Load one file, applying target context the same way for every caller.

    A named asset replaces the scanner's asset; an unnamed one only fills in
    the context values that were actually supplied.
    """
    replace_identity = bool(asset and asset.identifier)
    loaded = load_file_with_metadata(
        path, fmt=fmt, asset=asset if replace_identity else None,
        progress=progress)
    if asset and not replace_identity:
        updates = {
            key: getattr(asset, key) for key in _ASSET_CONTEXT_FIELDS
            if getattr(asset, key) is not None
            and getattr(asset, key) != "unknown"
        }
        for raw in loaded.findings:
            raw.asset = raw.asset.model_copy(update=updates)
    return loaded


def assess(
    files: list[Path],
    *,
    fmt: str | None = None,
    asset: Asset | None = None,
    inventory: Path | None = None,
    ssvc_overrides: dict | None = None,
    declared_coverage: dict | None = None,
    provider_status: str = "",
    snapshot: dict | None = None,
    use_nvd: bool = True,
    nvd_api_key: str | None = None,
    vendor_sources: str | None = "auto",
    github_token: str | None = None,
    use_vulnrichment: bool = True,
    backend: str = "rules",
    model: str | None = None,
    escalation_model: str | None = None,
    ai_provider: str | None = None,
    ai_base_url: str | None = None,
    jobs: int = 4,
    batch: bool = False,
    limit: int | None = None,
    progress: Callable[[str], None] = lambda message: None,
    on_coverage: Callable[[dict], None] | None = None,
) -> Assessment:
    """Assess scanner/SBOM files for one target context."""
    raw = []
    file_coverage = []
    for path in files:
        progress(f"reading {path} (SBOMs are resolved online via OSV.dev)...")
        loaded = _load(Path(path), fmt, asset, progress)
        progress(f"ingested {len(loaded.findings):>5} findings from {path}")
        raw += loaded.findings
        file_coverage.append(dict(loaded.coverage or {}))
    coverage = combine_coverage(
        dict(declared_coverage or {}),
        merge_file_coverage(file_coverage) if file_coverage else {},
        provider_status)
    if on_coverage:
        on_coverage(coverage)

    findings = dedup(raw)
    progress(f"{len(raw)} raw -> {len(findings)} deduplicated findings")
    for finding in findings:
        values = (ssvc_overrides or {}).get(finding.key)
        if isinstance(values, dict):
            finding.ssvc_inputs = {
                key: str(value) for key, value in values.items()
                if key in ("exploitation", "automatable")
            }

    # Context before triage so the AI sees it.
    if inventory:
        matched = apply_context(findings, load_inventory(inventory))
        progress(f"asset context applied to {matched} findings "
                 f"from {inventory}")

    if findings:
        if snapshot is not None:
            enrich_from_snapshot(findings, **snapshot)
        else:
            progress("enriching with EPSS / CISA KEV / Vulnrichment / NVD"
                     + (" + vendor advisories" if vendor_sources else "")
                     + "...")
            enrich(findings, nvd_api_key=nvd_api_key, use_nvd=use_nvd,
                   vendor_sources=vendor_sources, github_token=github_token,
                   use_vulnrichment=use_vulnrichment)

    # Deterministic SSVC screening comes before --limit. Scanner severity
    # alone must never exclude a low-CVSS KEV or context-urgent item.
    run_triage(findings, get_backend("rules"), jobs=1)
    subset = sorted(findings, key=ssvc_order_key)
    if limit:
        subset = subset[:limit]
    if batch and backend in {"ai", "claude"}:
        run_triage_batch(
            subset, model, progress=progress,
            provider="anthropic" if backend == "claude" else ai_provider)
    elif batch:
        raise ValueError(
            "--batch is supported only with the 'ai' backend and the "
            "Anthropic provider")
    elif backend != "rules":
        workers = max(1, jobs)
        progress(f"triaging {len(subset)} findings via '{backend}' "
                 f"({workers} workers)...")
        run_triage(subset, get_backend(
            backend, model, escalation_model,
            provider=ai_provider, base_url=ai_base_url), jobs=workers)

    audit = audit_all(subset)
    # Separate response policy: CISA BOD 26-04 is evaluated next to, never
    # instead of, the SSVC Deployer result.
    apply_response_policy(findings)
    actions = build_plan(subset)
    eval_rows = evaluate(subset)
    return Assessment(findings, subset, actions, eval_rows, coverage, audit)
