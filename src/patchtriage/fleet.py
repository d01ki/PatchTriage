"""Fleet import and organization-wide aggregation.

One deployed system is a *target*; an organization's repositories are a
*fleet*.  This module turns a GitHub account URL into many evidence-attached
targets (via the existing single-repository import path) and rolls the stored
per-target SSVC summaries up into one organization-wide action queue.

Aggregation never re-decides anything: the SSVC outcome of every finding was
produced per target by the deterministic engine, and the fleet view only
merges and orders those results while keeping per-target coverage boundaries
visible.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from . import targets as tstore
from .org import (
    DEFAULT_REPO_LIMIT,
    OwnerListing,
    list_owner_repositories,
    normalize_owner_url,
)
from .repository import (
    RepositoryError,
    RepositoryRateLimitError,
    RepositorySbom,
    fetch_github_sbom,
)

# Order for the merged queue and outcome rollups: most urgent first.
_PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_OUTCOME_KEYS = ("immediate", "out_of_cycle", "scheduled", "defer")

#: SSVC context fields a fleet import may apply to every created target.
FLEET_CONTEXT_FIELDS = (
    "criticality", "system_exposure", "automatable",
    "mission_impact", "safety_impact",
)


def _clean_context(context: dict | None) -> dict:
    """Keep only shared SSVC context; target identity fields are per-repo."""
    if not context:
        return {}
    unknown = set(context) - set(FLEET_CONTEXT_FIELDS)
    if unknown:
        raise ValueError(
            "unsupported fleet context fields: " + ", ".join(sorted(unknown)))
    return {key: str(value) for key, value in context.items()
            if value is not None}


def _existing_repository_targets(workspace_id: str | None) -> dict[str, dict]:
    """Map normalized repository URL -> target for idempotent reruns."""
    existing: dict[str, dict] = {}
    for target in tstore.load_targets(workspace_id):
        if target.get("source_kind") != "repository":
            continue
        url = str(target.get("url") or "").rstrip("/")
        if url:
            existing[url.lower()] = target
    return existing


def import_fleet(
    owner_url: str,
    *,
    workspace_id: str | None = None,
    limit: int = DEFAULT_REPO_LIMIT,
    include_forks: bool = False,
    include_archived: bool = False,
    github_token: str | None = None,
    context: dict | None = None,
    max_targets: int | None = None,
    max_workspace_source_bytes: int | None = None,
    client: httpx.Client | None = None,
    list_fn: Callable[..., OwnerListing] = list_owner_repositories,
    fetch_fn: Callable[..., RepositorySbom] = fetch_github_sbom,
    should_stop: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Import up to ``limit`` repositories of one GitHub account as targets.

    Each repository becomes a target with its provider SBOM attached through
    the same code path as a single-repository import, so provenance, coverage
    warnings, and quota rules are identical.  One repository's failure never
    aborts the rest; a provider rate limit or a target/quota ceiling stops the
    remainder *visibly* (``stopped_reason``) instead of half-succeeding in
    silence.  Reruns are idempotent: a repository already imported into this
    workspace is reported as ``already_imported`` and not duplicated.
    ``should_stop`` returns a non-empty reason (time budget, cancellation)
    to stop before the next repository the same visible way.
    """
    reference = normalize_owner_url(owner_url)
    shared_context = _clean_context(context)
    listing = list_fn(
        reference,
        github_token=github_token,
        client=client,
        limit=limit,
        include_forks=include_forks,
        include_archived=include_archived,
    )

    existing = _existing_repository_targets(workspace_id)
    results: list[dict[str, Any]] = []
    imported = 0
    stopped_reason = ""

    for repo in listing.repositories:
        if not stopped_reason and should_stop is not None:
            stopped_reason = should_stop()
        if stopped_reason:
            results.append({
                "repository": repo.full_name, "status": "not_attempted",
                "error": stopped_reason,
            })
            continue
        already = existing.get(repo.html_url.rstrip("/").lower())
        if already is not None:
            results.append({
                "repository": repo.full_name, "status": "already_imported",
                "target_id": already["id"],
            })
            continue

        try:
            target = tstore.add_target(
                name=repo.full_name, url=repo.html_url,
                workspace_id=workspace_id, max_targets=max_targets,
                **shared_context,
            )
        except tstore.TargetLimitError as exc:
            stopped_reason = str(exc)
            results.append({
                "repository": repo.full_name, "status": "not_attempted",
                "error": stopped_reason,
            })
            continue

        try:
            fetched = fetch_fn(repo.html_url, github_token=github_token,
                               client=client)
            provenance = fetched.provenance.to_dict()
            filename = repo.full_name.replace("/", "_") + ".spdx.json"
            tstore.save_source(
                target["id"], fetched.content, "spdx", workspace_id,
                filename=filename, source_kind="repository",
                provenance=provenance,
                max_workspace_source_bytes=max_workspace_source_bytes,
            )
        except RepositoryRateLimitError as exc:
            tstore.delete_target(target["id"], workspace_id)
            stopped_reason = str(exc)
            results.append({
                "repository": repo.full_name, "status": "failed",
                "error": stopped_reason,
            })
            continue
        except tstore.SourceQuotaError as exc:
            tstore.delete_target(target["id"], workspace_id)
            stopped_reason = str(exc)
            results.append({
                "repository": repo.full_name, "status": "failed",
                "error": stopped_reason,
            })
            continue
        except RepositoryError as exc:
            # This repository alone failed (no SBOM, too large, transient
            # provider error). Remove the evidence-less target and move on.
            tstore.delete_target(target["id"], workspace_id)
            results.append({
                "repository": repo.full_name, "status": "failed",
                "error": str(exc),
            })
            continue

        imported += 1
        results.append({
            "repository": repo.full_name, "status": "imported",
            "target_id": target["id"],
            "component_count": provenance.get("component_count", 0),
            "coverage_status": provenance.get("coverage_status", ""),
        })

    return {
        "owner": reference.owner,
        "owner_url": reference.normalized_url,
        "listing": {
            "total_listed": listing.total_listed,
            "skipped_forks": listing.skipped_forks,
            "skipped_archived": listing.skipped_archived,
            "truncated": listing.truncated,
            "warnings": list(listing.warnings),
        },
        "imported": imported,
        "already_imported": sum(
            1 for row in results if row["status"] == "already_imported"),
        "failed": sum(1 for row in results if row["status"] == "failed"),
        "not_attempted": sum(
            1 for row in results if row["status"] == "not_attempted"),
        "stopped_reason": stopped_reason,
        "results": results,
        "imported_target_ids": [
            row["target_id"] for row in results
            if row["status"] == "imported"
        ],
    }


def _queue_sort_key(entry: dict[str, Any]) -> tuple:
    return (
        _PRIORITY_ORDER.get(str(entry.get("top_priority")), 4),
        int(entry.get("deadline_days") or 90),
        -int(entry.get("kev_count") or 0),
        -int(entry.get("finding_count") or 0),
        str(entry.get("package") or ""),
    )


def aggregate_fleet(
    workspace_id: str | None = None,
    target_ids: list[str] | None = None,
    *,
    max_queue: int = 50,
) -> dict[str, Any]:
    """Merge stored per-target summaries into one fleet rollup.

    Purely a read of results the engine already produced: outcome totals, a
    priority-ordered cross-target action queue, and the coverage/assessment
    state of every target so an incomplete fleet can never look complete.
    """
    targets = tstore.load_targets(workspace_id)
    if target_ids is not None:
        wanted = set(target_ids)
        targets = [t for t in targets if t["id"] in wanted]

    outcomes = dict.fromkeys(_OUTCOME_KEYS, 0)
    queue: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    findings_total = 0
    kev_total = 0
    assessed = 0
    queue_truncated_targets = 0

    for target in targets:
        summary = tstore.load_summary(target["id"], workspace_id)
        row = {
            "target_id": target["id"],
            "name": target.get("name", ""),
            "url": target.get("url", ""),
            "source_kind": target.get("source_kind", ""),
            "assessed": summary is not None,
        }
        if summary is None:
            row["result_state"] = "not_assessed"
            rows.append(row)
            continue
        assessed += 1
        findings_total += int(summary.get("total") or 0)
        kev_total += int(summary.get("kev") or 0)
        for key in _OUTCOME_KEYS:
            outcomes[key] += int((summary.get("outcomes") or {}).get(key) or 0)
        if summary.get("action_queue_truncated"):
            queue_truncated_targets += 1
        for entry in summary.get("action_queue") or []:
            queue.append({**entry, "target_id": target["id"],
                          "target_name": target.get("name", "")})
        row.update({
            "result_state": summary.get("result_state", ""),
            "coverage_status": (summary.get("source") or {}).get(
                "coverage_status", ""),
            "total": summary.get("total", 0),
            "outcomes": summary.get("outcomes") or {},
            "kev": summary.get("kev", 0),
            "top_action": summary.get("top_action", ""),
            "report_url": summary.get("report_url", ""),
        })
        rows.append(row)

    queue.sort(key=_queue_sort_key)
    incomplete = [
        row for row in rows
        if row["assessed"] and row.get("coverage_status") not in ("complete",)
    ]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets_total": len(rows),
        "targets_assessed": assessed,
        "targets_unassessed": len(rows) - assessed,
        "findings_total": findings_total,
        "kev_total": kev_total,
        "outcomes": outcomes,
        "queue": queue[:max_queue],
        "queue_total": len(queue),
        "queue_truncated": (
            len(queue) > max_queue or queue_truncated_targets > 0),
        "targets": rows,
        "coverage_incomplete_targets": len(incomplete),
    }
