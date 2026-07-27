"""Failure, cache, and NVD reference handling for deterministic enrichment."""

import json
import os
import threading
import time

import httpx
import pytest

from patchtriage.enrich import clients
from patchtriage.models import Asset, Finding, Package


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.request = httpx.Request("GET", "https://example.test/")

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            response = httpx.Response(self.status_code, request=self.request)
            raise httpx.HTTPStatusError(
                f"status {self.status_code}", request=self.request,
                response=response)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)

    def get(self, *args, **kwargs):
        return self.responses.pop(0)


def test_kev_invalid_refresh_uses_stale_last_known_good(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    known = {"CVE-2024-0001": {"cveID": "CVE-2024-0001"}}
    clients._save_cache("kev.json", known)
    old = time.time() - 48 * 3600
    os.utime(tmp_path / "kev.json", (old, old))

    result = clients.fetch_kev(FakeClient([FakeResponse(
        {"vulnerabilities": []})]))
    assert result.entries == known
    assert result.stale is True
    assert "invalid or empty catalog" in result.refresh_error
    assert json.loads((tmp_path / "kev.json").read_text()) == known


def test_kev_invalid_schema_without_last_good_is_not_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    with pytest.raises(ValueError, match="invalid or empty"):
        clients.fetch_kev(FakeClient([FakeResponse({"vulnerabilities": []})]))
    assert not (tmp_path / "kev.json").exists()


def test_nvd_non_200_and_valid_empty_are_not_negative_cached(tmp_path,
                                                             monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(clients.time, "sleep", lambda _: None)
    with pytest.raises(httpx.HTTPStatusError):
        clients.fetch_nvd(
            "CVE-2024-0001", FakeClient([FakeResponse({}, 500)]))
    assert not (tmp_path / "nvd.json").exists()

    assert clients.fetch_nvd(
        "CVE-2024-0001",
        FakeClient([FakeResponse({"vulnerabilities": []})]),
    ) == {}
    assert not (tmp_path / "nvd.json").exists()


def test_nvd_preserves_reference_tags_and_prefers_exploit_tag(tmp_path,
                                                              monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(clients.time, "sleep", lambda _: None)
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2024-0001",
        "metrics": {},
        "weaknesses": [],
        "references": [
            {"url": "https://example.test/advisory/epoch-poc-policy",
             "tags": ["Vendor Advisory"]},
            {"url": "https://research.example.test/reproducer",
             "tags": ["Exploit", "Third Party Advisory"]},
            {"url": "https://www.exploit-db.com/exploits/123",
             "tags": []},
        ],
    }}]}
    entry = clients.fetch_nvd(
        "CVE-2024-0001", FakeClient([FakeResponse(payload)]))
    assert entry["reference_records"][1]["tags"] == [
        "Exploit", "Third Party Advisory"]
    assert clients._exploit_reference_urls(entry) == [
        "https://research.example.test/reproducer"]

    cached = clients._load_entry_cache("nvd.json", 24 * 7)
    assert cached["CVE-2024-0001"]["reference_records"] == \
        entry["reference_records"]


def test_poc_substring_alone_is_not_exploit_evidence():
    assert clients._exploit_reference_urls({
        "references": ["https://example.test/advisory/epoch-poc-policy"],
    }) == []


def test_atomic_entry_cache_merges_concurrent_thread_updates(tmp_path,
                                                             monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    threads = [threading.Thread(
        target=clients._merge_entry_cache,
        args=("nvd.json", {f"CVE-2024-{i:04d}": {"score": i}}),
    ) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    data = clients._load_entry_cache("nvd.json", 1)
    assert len(data) == 20
    # Atomic writes must never leave sidecar temp files behind.
    assert list(tmp_path.glob("*.tmp")) == []


def test_entry_cache_ttl_is_per_record_not_file_mtime(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    now = time.time()
    clients._save_cache("nvd.json", {
        "_schema": clients._ENTRY_CACHE_SCHEMA,
        "entries": {
            "old": {"value": {"score": 1},
                    "fetched_at": now - 10 * 3600},
            "new": {"value": {"score": 2}, "fetched_at": now},
        },
    })
    assert clients._load_entry_cache("nvd.json", 1) == {
        "new": {"score": 2}}


def test_invalid_epss_response_does_not_create_negative_cache(tmp_path,
                                                               monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    with pytest.raises(ValueError, match="invalid response schema"):
        clients.fetch_epss(
            ["CVE-2024-0001"], FakeClient([FakeResponse({"unexpected": []})]))
    assert not (tmp_path / "epss.json").exists()


def test_snapshot_marks_exploit_coverage_only_when_nvd_record_exists():
    def finding(cve):
        return Finding(
            key=cve, vuln_id=cve, package=Package(name="pkg"),
            asset=Asset(identifier="asset"),
        )

    found = finding("CVE-2024-0001")
    missing = finding("CVE-2024-0002")
    clients.enrich_from_snapshot(
        [found, missing], epss={}, kev={},
        nvd={"CVE-2024-0001": {"references": []}},
    )
    assert found.enrichment.exploit_sources_checked == ["nvd:snapshot"]
    assert missing.enrichment.exploit_sources_checked == []


def test_enrichment_source_outages_are_isolated_and_visible(monkeypatch):
    finding = Finding(
        key="x", vuln_id="CVE-2024-0001", package=Package(name="pkg"),
        asset=Asset(identifier="asset"),
    )
    monkeypatch.setattr(
        clients, "fetch_epss",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad EPSS")),
    )
    monkeypatch.setattr(
        clients, "fetch_kev",
        lambda *args, **kwargs: {
            "CVE-2024-0001": {
                "cveID": "CVE-2024-0001",
                "knownRansomwareCampaignUse": "Unknown",
            },
        },
    )
    monkeypatch.setattr(
        clients, "fetch_nvd",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad NVD")),
    )
    monkeypatch.setattr(
        clients, "fetch_vulnrichment",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ValueError("bad Vulnrichment")),
    )
    clients.enrich([finding], vendor_sources=None)
    enrichment = finding.enrichment
    assert enrichment.in_cisa_kev is True
    assert enrichment.retrieval_status == {
        "epss": "failed", "kev": "listed", "nvd": "failed",
        "vulnrichment": "failed",
    }
    assert any(error.startswith("EPSS:") for error in enrichment.retrieval_errors)
    assert any(error.startswith("NVD:") for error in enrichment.retrieval_errors)
    assert any(error.startswith("CISA Vulnrichment:")
               for error in enrichment.retrieval_errors)
    # A failed lookup must never leave the finding looking assessed.
    assert enrichment.ssvc_exploitation is None
    assert enrichment.ssvc_automatable is None
    assert enrichment.ssvc_technical_impact is None


def test_stale_kev_catalog_confirms_only_positive_matches(monkeypatch):
    def finding(cve):
        return Finding(
            key=cve, vuln_id=cve, package=Package(name="pkg"),
            asset=Asset(identifier="asset"),
        )

    listed = finding("CVE-2024-0001")
    absent = finding("CVE-2024-0002")
    monkeypatch.setattr(clients, "fetch_epss", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        clients, "fetch_kev",
        lambda *args, **kwargs: clients.KevCatalogResult(
            entries={"CVE-2024-0001": {"cveID": "CVE-2024-0001"}},
            stale=True,
            refresh_error="ReadTimeout: timed out",
        ),
    )

    clients.enrich([listed, absent], use_nvd=False, vendor_sources=None,
                   use_vulnrichment=False)

    assert listed.enrichment.in_cisa_kev is True
    assert listed.enrichment.retrieval_status["kev"] == "listed_stale"
    assert absent.enrichment.in_cisa_kev is False
    assert absent.enrichment.retrieval_status["kev"] == "unknown_stale"
    assert absent.enrichment.retrieval_status["kev"] != "not_listed"
    for finding_result in (listed, absent):
        assert "kev:stale" in finding_result.enrichment.sources
        assert any(
            "stale catalog" in error
            for error in finding_result.enrichment.retrieval_errors
        )
