"""Fleet import and aggregation: listing, batch import, rollup, endpoints."""

from __future__ import annotations

import json

import httpx
import pytest

from patchtriage import targets as tstore
from patchtriage.fleet import aggregate_fleet, import_fleet
from patchtriage.org import (
    list_owner_repositories,
    normalize_owner_url,
)
from patchtriage.report.fleet import render_fleet_html
from patchtriage.repository import (
    RepositoryNotFoundError,
    RepositoryRateLimitError,
    RepositorySbom,
    RepositoryProvenance,
    RepositoryURLValidationError,
)


# --------------------------------------------------------------- owner URLs

def test_normalize_owner_url_accepts_account_root():
    reference = normalize_owner_url("https://github.com/Example-Org")
    assert reference.owner == "Example-Org"
    assert reference.normalized_url == "https://github.com/Example-Org"


@pytest.mark.parametrize("url", [
    "https://github.com/owner/repository",   # repository, not an account
    "https://github.com/",                    # no owner
    "https://gitlab.com/owner",               # unsupported host
    "http://github.com/owner",                # not HTTPS
    "https://github.com/owner?tab=repos",     # query string
    "https://user:pass@github.com/owner",     # credentials
    "https://github.com/-bad-",               # invalid account name
    "",
])
def test_normalize_owner_url_rejects_ambiguity(url):
    with pytest.raises(RepositoryURLValidationError):
        normalize_owner_url(url)


# ------------------------------------------------------------------ listing

def _repo(name, *, fork=False, archived=False, owner="acme"):
    return {
        "full_name": f"{owner}/{name}",
        "html_url": f"https://github.com/{owner}/{name}",
        "default_branch": "main",
        "pushed_at": "2026-07-01T00:00:00Z",
        "fork": fork,
        "archived": archived,
    }


def _listing_client(pages, status=200, headers=None):
    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        if status != 200:
            return httpx.Response(status, json=[], headers=headers or {})
        body = pages[page - 1] if page <= len(pages) else []
        return httpx.Response(200, json=body)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_listing_filters_forks_and_archived_by_default():
    pages = [[
        _repo("app"), _repo("fork-of-lib", fork=True),
        _repo("museum", archived=True), _repo("api"),
    ]]
    with _listing_client(pages) as client:
        listing = list_owner_repositories(
            "https://github.com/acme", client=client, limit=10)
    assert [r.full_name for r in listing.repositories] == [
        "acme/app", "acme/api"]
    assert listing.skipped_forks == 1
    assert listing.skipped_archived == 1
    assert listing.total_listed == 4
    assert listing.truncated is False


def test_listing_respects_limit_and_reports_truncation():
    pages = [[_repo(f"repo{i}") for i in range(5)]]
    with _listing_client(pages) as client:
        listing = list_owner_repositories(
            "https://github.com/acme", client=client, limit=2)
    assert len(listing.repositories) == 2
    assert listing.truncated is True
    assert any("capped" in warning for warning in listing.warnings)


def test_listing_maps_rate_limit_and_not_found():
    with _listing_client([], status=404) as client:
        with pytest.raises(RepositoryNotFoundError):
            list_owner_repositories(
                "https://github.com/ghost", client=client, limit=5)
    headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9"}
    with _listing_client([], status=403, headers=headers) as client:
        with pytest.raises(RepositoryRateLimitError):
            list_owner_repositories(
                "https://github.com/acme", client=client, limit=5)


# ------------------------------------------------------------- fleet import

def _spdx(name="acme/app", packages=1):
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "name": name,
        "packages": [
            {"name": f"pkg{i}", "versionInfo": "1.0.0"}
            for i in range(packages)
        ],
    }
    return json.dumps(sbom)


def _fake_fetch(url, **_kwargs):
    repository = url.removeprefix("https://github.com/")
    if repository.endswith("broken"):
        raise RepositoryNotFoundError("no dependency graph")
    provenance = RepositoryProvenance(
        provider="github_dependency_graph", repository=repository,
        ref="default_branch", resolved_url=url, api_url="test://sbom",
        format="spdx", component_count=2, coverage_status="provider_reported",
        warnings=(), retrieved_at="2026-07-20T00:00:00+00:00",
    )
    return RepositorySbom(content=_spdx(repository, 2), provenance=provenance)


def _fake_list(pages):
    def list_fn(reference, **kwargs):
        with _listing_client(pages) as client:
            return list_owner_repositories(
                reference, client=client,
                limit=kwargs.get("limit", 10),
                include_forks=kwargs.get("include_forks", False),
                include_archived=kwargs.get("include_archived", False),
            )
    return list_fn


def test_import_fleet_creates_evidence_attached_targets(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    pages = [[_repo("app"), _repo("api"), _repo("broken")]]
    report = import_fleet(
        "https://github.com/acme",
        list_fn=_fake_list(pages), fetch_fn=_fake_fetch,
        context={"system_exposure": "open"},
    )
    assert report["imported"] == 2
    assert report["failed"] == 1
    assert report["stopped_reason"] == ""
    statuses = {row["repository"]: row["status"] for row in report["results"]}
    assert statuses == {"acme/app": "imported", "acme/api": "imported",
                        "acme/broken": "failed"}
    stored = tstore.load_targets()
    assert {t["name"] for t in stored} == {"acme/app", "acme/api"}
    for target in stored:
        assert target["source_kind"] == "repository"
        assert target["source_format"] == "spdx"
        assert target["system_exposure"] == "open"
        assert target["source_sha256"]
    # a failed repository must not leave an evidence-less target behind
    assert all(t["name"] != "acme/broken" for t in stored)


def test_import_fleet_is_idempotent_across_reruns(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    pages = [[_repo("app")]]
    first = import_fleet("https://github.com/acme",
                         list_fn=_fake_list(pages), fetch_fn=_fake_fetch)
    second = import_fleet("https://github.com/acme",
                          list_fn=_fake_list(pages), fetch_fn=_fake_fetch)
    assert first["imported"] == 1
    assert second["imported"] == 0
    assert second["already_imported"] == 1
    assert len(tstore.load_targets()) == 1
    assert (second["results"][0]["target_id"]
            == first["results"][0]["target_id"])


def test_import_fleet_stops_visibly_at_target_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    pages = [[_repo("one"), _repo("two"), _repo("three")]]
    report = import_fleet(
        "https://github.com/acme", max_targets=2,
        list_fn=_fake_list(pages), fetch_fn=_fake_fetch,
    )
    assert report["imported"] == 2
    assert report["not_attempted"] == 1
    assert "target limit" in report["stopped_reason"]


def test_import_fleet_rate_limit_stops_remaining(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))

    calls = {"n": 0}

    def limited_fetch(url, **kwargs):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RepositoryRateLimitError("rate limit reached")
        return _fake_fetch(url, **kwargs)

    pages = [[_repo("one"), _repo("two"), _repo("three")]]
    report = import_fleet(
        "https://github.com/acme",
        list_fn=_fake_list(pages), fetch_fn=limited_fetch,
    )
    assert report["imported"] == 1
    assert report["failed"] == 1
    assert report["not_attempted"] == 1
    assert "rate limit" in report["stopped_reason"]
    # the rate-limited repository's placeholder target was rolled back
    assert {t["name"] for t in tstore.load_targets()} == {"acme/one"}


def test_import_fleet_stops_visibly_when_asked(tmp_path, monkeypatch):
    # The GUI's time budget and cancel button stop between repositories.
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    fetched = []

    def counting_fetch(url, **kwargs):
        fetched.append(url)
        return _fake_fetch(url, **kwargs)

    pages = [[_repo("one"), _repo("two"), _repo("three")]]
    report = import_fleet(
        "https://github.com/acme",
        list_fn=_fake_list(pages), fetch_fn=counting_fetch,
        should_stop=lambda: "time budget reached" if fetched else "",
    )
    assert report["imported"] == 1
    assert report["not_attempted"] == 2
    assert report["stopped_reason"] == "time budget reached"
    assert len(fetched) == 1
    assert {t["name"] for t in tstore.load_targets()} == {"acme/one"}


def test_import_fleet_rejects_unknown_context_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    with pytest.raises(ValueError, match="unsupported fleet context"):
        import_fleet("https://github.com/acme",
                     list_fn=_fake_list([[]]), fetch_fn=_fake_fetch,
                     context={"name": "evil"})


# -------------------------------------------------------------- aggregation

def _summary(target_id, *, immediate=0, out_of_cycle=0, scheduled=0,
             defer=0, kev=0, queue=(), coverage="complete"):
    total = immediate + out_of_cycle + scheduled + defer
    return {
        "target_id": target_id,
        "total": total,
        "outcomes": {"immediate": immediate, "out_of_cycle": out_of_cycle,
                     "scheduled": scheduled, "defer": defer},
        "kev": kev,
        "action_queue": list(queue),
        "action_queue_truncated": False,
        "result_state": "assessed",
        "source": {"coverage_status": coverage},
        "top_action": "upgrade something",
        "report_url": f"/report/{target_id}",
    }


def _queue_entry(package, priority, deadline, *, kev=0):
    return {
        "action_id": f"a-{package}", "kind": "upgrade",
        "summary": f"Upgrade {package}", "package": package,
        "ecosystem": "pypi", "installed_version": "1.0",
        "target_version": "2.0", "top_priority": priority,
        "outcome_label": {"P1": "Immediate", "P2": "Out-of-Cycle",
                          "P3": "Scheduled", "P4": "Defer"}[priority],
        "deadline_days": deadline, "kev_count": kev,
        "cves": ["CVE-2026-0001"], "finding_count": 1,
    }


def test_aggregate_fleet_merges_outcomes_and_orders_queue(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    a = tstore.add_target("acme/app")
    b = tstore.add_target("acme/api")
    c = tstore.add_target("acme/unassessed")
    for target, summary in (
        (a, _summary(a["id"], immediate=1, defer=2, kev=1,
                     queue=[_queue_entry("django", "P3", 30),
                            _queue_entry("openssl", "P1", 3, kev=1)])),
        (b, _summary(b["id"], out_of_cycle=1, kev=0,
                     queue=[_queue_entry("lodash", "P2", 14)],
                     coverage="provider_reported")),
    ):
        tstore.save_source(
            target["id"], '{"SchemaVersion":2,"ArtifactName":"x","Results":[]}',
            "trivy", filename="scan.json")
        refreshed = tstore.get_target(target["id"])
        tstore.save_run_artifacts(
            target["id"], summary, "<html></html>",
            refreshed["input_revision"], refreshed["source_sha256"])

    rollup = aggregate_fleet(
        target_ids=[a["id"], b["id"], c["id"]])
    assert rollup["targets_total"] == 3
    assert rollup["targets_assessed"] == 2
    assert rollup["targets_unassessed"] == 1
    assert rollup["outcomes"] == {
        "immediate": 1, "out_of_cycle": 1, "scheduled": 0, "defer": 2}
    assert rollup["kev_total"] == 1
    # queue merged across targets and ordered by priority
    packages = [entry["package"] for entry in rollup["queue"]]
    assert packages == ["openssl", "lodash", "django"]
    assert rollup["queue"][0]["target_name"] == "acme/app"
    assert rollup["coverage_incomplete_targets"] == 1
    unassessed_states = {
        row["target_id"]: row["result_state"] for row in rollup["targets"]}
    assert unassessed_states[c["id"]] == "not_assessed"


def test_fleet_html_renders_rollup(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    a = tstore.add_target("acme/app")
    tstore.save_source(
        a["id"], '{"SchemaVersion":2,"ArtifactName":"x","Results":[]}',
        "trivy", filename="scan.json")
    refreshed = tstore.get_target(a["id"])
    tstore.save_run_artifacts(
        a["id"],
        _summary(a["id"], immediate=1,
                 queue=[_queue_entry("openssl", "P1", 3, kev=2)]),
        "<html></html>",
        refreshed["input_revision"], refreshed["source_sha256"])
    html = render_fleet_html(aggregate_fleet(target_ids=[a["id"]]))
    assert "Immediate" in html
    assert "openssl" in html
    assert "acme/app" in html
    # untrusted names must be escaped
    evil = tstore.add_target("<script>alert(1)</script>")
    html = render_fleet_html(
        aggregate_fleet(target_ids=[a["id"], evil["id"]]))
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html
