"""Normalization and failure-isolation tests for official vendor feeds."""

import httpx
import pytest

from patchtriage.enrich.vendors import (
    auto_sources,
    enrich_vendor_advisories,
    parse_debian,
    parse_exploitdb,
    parse_ghsa,
    parse_msrc,
    parse_rhsa,
    parse_sources,
    parse_usn,
)
from patchtriage.models import Asset, Finding, Package

CVE = "CVE-2021-44228"


def _finding(ecosystem="maven", purl="pkg:maven/org.apache.logging.log4j/log4j-core"):
    return Finding(
        key="finding-1", vuln_id=CVE,
        package=Package(name="log4j-core", version="2.14.1",
                        ecosystem=ecosystem, purl=purl),
        asset=Asset(identifier="checkout", kind="repository"),
        cvss_score=10.0,
    )


def _payloads():
    return {
        "msrc": {"value": [{
            "ID": "2021-Dec", "DocumentTitle": "December 2021 Security Updates",
            "InitialReleaseDate": "2021-12-14T08:00:00Z",
            "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2021-Dec",
        }]},
        "rhsa": [{
            "RHSA": "RHSA-2021:5206", "severity": "important",
            "released_on": "2021-12-15T00:00:00Z", "CVEs": [CVE],
            "released_packages": ["log4j-core-2.16.0-1.el8"],
        }],
        "usn": {
            "id": f"UBUNTU-{CVE}", "summary": "Log4j vulnerability",
            "published": "2021-12-13T00:00:00Z", "related": ["USN-5192-1"],
            "references": [{"type": "ADVISORY",
                            "url": "https://ubuntu.com/security/notices/USN-5192-1"}],
            "affected": [{
                "package": {"name": "apache-log4j2"},
                "ranges": [{"events": [{"introduced": "0"},
                                         {"fixed": "2.15.0-0.21.04.1"}]}],
            }],
        },
        "debian": {
            "apache-log4j2": {CVE: {
                "description": "Apache Log4j2 remote code execution",
                "releases": {"bookworm": {
                    "status": "resolved", "fixed_version": "2.17.1-1",
                    "urgency": "high",
                }},
            }},
        },
        "ghsa": [{
            "ghsa_id": "GHSA-jfh8-c2jp-5v3q", "cve_id": CVE,
            "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
            "summary": "Log4Shell", "severity": "critical",
            "published_at": "2021-12-10T00:00:00Z",
            "vulnerabilities": [{
                "package": {"ecosystem": "maven", "name": "log4j-core"},
                "first_patched_version": "2.15.0",
                "vulnerable_functions": ["JndiManager.lookup"],
            }],
        }],
    }


def test_each_official_feed_is_normalized():
    payloads = _payloads()
    assert parse_msrc(payloads["msrc"], CVE)[0]["advisory_id"] == "2021-Dec"
    rhsa = parse_rhsa(payloads["rhsa"], CVE)[0]
    assert rhsa["advisory_id"] == "RHSA-2021:5206"
    assert rhsa["fixed_versions"] == ["log4j-core-2.16.0-1.el8"]
    usn = parse_usn(payloads["usn"], CVE)[0]
    assert usn["advisory_id"] == "USN-5192-1"
    assert "apache-log4j2 2.15.0-0.21.04.1" in usn["fixed_versions"]
    debian = parse_debian(payloads["debian"], CVE)[0]
    assert debian["fixed_versions"] == ["apache-log4j2 bookworm: 2.17.1-1"]
    ghsa = parse_ghsa(payloads["ghsa"], CVE)[0]
    assert ghsa["advisory_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert ghsa["vulnerable_functions"] == ["JndiManager.lookup"]


def test_source_selection_and_validation():
    # Red Hat, Microsoft and Exploit-DB are queried for every CVE; the
    # ecosystem decides the remaining distribution/package sources.
    assert auto_sources(_finding()) == ("rhsa", "msrc", "exploitdb", "ghsa")
    assert auto_sources(_finding("ubuntu", "pkg:deb/ubuntu/apache-log4j2")) == (
        "rhsa", "msrc", "exploitdb", "usn")
    assert parse_sources("all") == (
        "msrc", "rhsa", "usn", "debian", "ghsa", "exploitdb")
    with pytest.raises(ValueError, match="unknown vendor source"):
        parse_sources("oracle")
    with pytest.raises(ValueError, match="cannot be combined"):
        parse_sources("auto,ghsa")


def test_all_connectors_attach_evidence_with_one_normalized_model(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    payloads = _payloads()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith(f"/updates/{CVE}"):
            return httpx.Response(200, json=payloads["msrc"])
        if path.endswith("/csaf.json"):
            return httpx.Response(200, json=payloads["rhsa"])
        if path.endswith(f"/vulns/UBUNTU-{CVE}"):
            return httpx.Response(200, json=payloads["usn"])
        if path.endswith("/tracker/data/json"):
            return httpx.Response(200, json=payloads["debian"])
        if path.endswith("/advisories"):
            return httpx.Response(200, json=payloads["ghsa"])
        if path == "/search" and request.url.host == "www.exploit-db.com":
            return httpx.Response(200, json=_exploitdb_payload())
        return httpx.Response(404)

    finding = _finding()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        summary = enrich_vendor_advisories(
            [finding], sources="all", client=client)
    assert summary == {
        "sources": ["msrc", "rhsa", "usn", "debian", "ghsa", "exploitdb"],
        "checked_cves": 1, "advisories": 6, "errors": 0, "truncated": 0,
    }
    assert finding.enrichment.vendor_sources_checked == [
        "msrc", "rhsa", "usn", "debian", "ghsa", "exploitdb"]
    assert {a.source for a in finding.enrichment.vendor_advisories} == {
        "msrc", "rhsa", "usn", "debian", "ghsa", "exploitdb"}
    msrc = next(a for a in finding.enrichment.vendor_advisories
                if a.source == "msrc")
    assert msrc.url == (
        f"https://msrc.microsoft.com/update-guide/vulnerability/{CVE}")
    assert finding.enrichment.vendor_lookup_errors == []


def test_connector_failure_is_visible_but_non_fatal(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))

    def unavailable(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"message": "maintenance"})

    finding = _finding()
    with httpx.Client(transport=httpx.MockTransport(unavailable)) as client:
        summary = enrich_vendor_advisories(
            [finding], sources="ghsa", client=client)
    assert summary["errors"] == 1
    assert finding.enrichment.vendor_advisories == []
    assert finding.enrichment.vendor_sources_checked == ["ghsa"]
    assert finding.enrichment.vendor_lookup_errors


def _exploitdb_payload(cve_number="2021-44228", exploit_id="50592"):
    """Shape of the JSON returned by Exploit-DB's per-CVE search."""
    return {"draw": 1, "recordsTotal": 2, "recordsFiltered": 2, "data": [
        {"id": exploit_id,
         "description": [exploit_id, "Apache Log4j 2 - RCE"],
         "date_published": "2021-12-14", "verified": 1,
         "type": {"display": "Remote"}, "platform": {"platform": "Java"},
         "code": [{"code_type": "cve", "code": cve_number}]},
        # A loosely matching row for another CVE must not be attached.
        {"id": "1", "description": ["1", "Other"], "verified": 0,
         "code": [{"code_type": "cve", "code": "2020-0001"}]},
    ]}


def test_exploitdb_search_keeps_exact_cve_hits_and_links_the_exploit():
    [record] = parse_exploitdb(_exploitdb_payload(), CVE)
    assert record["advisory_id"] == "EDB-50592"
    assert record["url"] == "https://www.exploit-db.com/exploits/50592"
    assert record["title"] == "Apache Log4j 2 - RCE"
    assert record["severity"] == "verified"
    with pytest.raises(ValueError, match="unexpected search response"):
        parse_exploitdb({"error": "blocked"}, CVE)


def test_exploitdb_is_queried_live_and_never_written_to_disk(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.exploit-db.com":
            requests.append(request.url.params["cve"])
            hit = request.url.params["cve"] == "2021-44228"
            return httpx.Response(200, json=_exploitdb_payload() if hit else
                                  {"draw": 1, "data": []})
        return httpx.Response(404)

    hit, miss = _finding(), _finding()
    miss.vuln_id = "CVE-2020-0002"
    for _ in range(2):  # a second run must query again, not reuse a cache
        for finding in (hit, miss):
            finding.enrichment.exploit_references = []
            finding.enrichment.exploit_sources_checked = []
            finding.enrichment.vendor_advisories = []
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            enrich_vendor_advisories([hit, miss], sources="exploitdb",
                                     client=client)
    assert sorted(requests) == sorted(["2021-44228", "2020-0002"] * 2)
    assert hit.enrichment.exploit_references == [
        "https://www.exploit-db.com/exploits/50592"]
    assert "exploitdb" in hit.enrichment.exploit_sources_checked
    # A completed search with no entry is coverage, not a PoC.
    assert miss.enrichment.exploit_references == []
    assert "exploitdb" in miss.enrichment.exploit_sources_checked
    stored = (tmp_path / "vendor_advisories.json")
    assert "exploitdb" not in (
        stored.read_text(encoding="utf-8") if stored.exists() else "")
    assert not list(tmp_path.glob("exploitdb*"))
    from patchtriage.ssvc import assess
    assert assess(hit).exploitation.value == "public_poc"


def test_per_cve_lookups_overlap_within_the_concurrency_bound(
        tmp_path, monkeypatch):
    # Sequential per-CVE lookups pushed a 33-CVE SBOM past the GUI's
    # synchronous request timeout; they must overlap, but only boundedly.
    import threading
    import time

    from patchtriage.enrich import vendors

    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    lock = threading.Lock()
    active: dict[str, int] = {}
    peak: dict[str, int] = {}
    msrc_started_before_exploitdb_done = threading.Event()
    exploitdb_done = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exploitdb_done
        host = request.url.host
        with lock:
            active[host] = active.get(host, 0) + 1
            peak[host] = max(peak.get(host, 0), active[host])
            if host == "api.msrc.microsoft.com" and exploitdb_done < 12:
                msrc_started_before_exploitdb_done.set()
        # Exploit-DB is the slow source in production.
        time.sleep(0.1 if host == "www.exploit-db.com" else 0.02)
        with lock:
            active[host] -= 1
            if host == "www.exploit-db.com":
                exploitdb_done += 1
        if host == "www.exploit-db.com":
            return httpx.Response(200, json={"draw": 1, "data": []})
        return httpx.Response(404)

    findings = []
    for n in range(12):
        finding = _finding()
        finding.vuln_id = f"CVE-2020-{n:04d}"
        findings.append(finding)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        summary = enrich_vendor_advisories(
            findings, sources="exploitdb,msrc", client=client)
    assert summary["errors"] == 0
    assert 1 < peak["www.exploit-db.com"] <= vendors.EXPLOITDB_CONCURRENCY
    assert 1 < peak["api.msrc.microsoft.com"] <= vendors.PER_CVE_CONCURRENCY
    # Slow Exploit-DB searches must not hold the other sources back.
    assert msrc_started_before_exploitdb_done.is_set()
    assert all("exploitdb" in f.enrichment.exploit_sources_checked
               for f in findings)


def test_failed_exploitdb_search_is_not_reported_as_searched(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    finding = _finding()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        summary = enrich_vendor_advisories([finding], sources="exploitdb",
                                           client=client)
    assert summary["errors"] == 1
    assert "exploitdb" not in finding.enrichment.exploit_sources_checked
    assert finding.enrichment.vendor_lookup_errors


def test_microsoft_without_a_record_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    finding = _finding()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        summary = enrich_vendor_advisories([finding], sources="msrc",
                                           client=client)
    assert summary["errors"] == 0
    assert finding.enrichment.vendor_lookup_errors == []


# ------------------------------------------------------------------ cache
def _msrc_finding(cve):
    finding = _finding()
    finding.vuln_id = cve
    return finding


def _msrc_handler(calls, during=None):
    def handler(request: httpx.Request) -> httpx.Response:
        cve = request.url.path.rsplit("/", 1)[-1]
        calls.append(cve)
        if during is not None:
            during(cve)
        return httpx.Response(200, json={"value": [{
            "ID": f"ADV-{cve}", "DocumentTitle": cve}]})
    return handler


def _run_msrc(cves, calls, during=None):
    findings = [_msrc_finding(cve) for cve in cves]
    with httpx.Client(transport=httpx.MockTransport(
            _msrc_handler(calls, during))) as client:
        summary = enrich_vendor_advisories(findings, sources="msrc",
                                           client=client)
    return findings, summary


def test_concurrent_runs_do_not_drop_each_others_cache_entries(
        tmp_path, monkeypatch):
    # Run B finishes while run A is still fetching. A must not overwrite
    # the file with the snapshot it loaded before B saved.
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    calls: list[str] = []
    nested: list[str] = []

    def run_b_during_a(cve):
        if cve == "CVE-2020-0001" and not nested:
            nested.append(cve)
            _run_msrc(["CVE-2020-0002"], calls)

    _run_msrc(["CVE-2020-0001"], calls, during=run_b_during_a)
    calls.clear()
    findings, summary = _run_msrc(["CVE-2020-0001", "CVE-2020-0002"], calls)
    assert calls == []  # both served from cache
    assert summary["errors"] == 0
    assert all(f.enrichment.vendor_advisories for f in findings)


def test_reusing_a_cached_entry_does_not_extend_its_lifetime(
        tmp_path, monkeypatch):
    import json
    import time

    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    calls: list[str] = []
    _run_msrc(["CVE-2020-0001"], calls)
    path = tmp_path / "vendor_advisories.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    entry = stored["entries"]["msrc:CVE-2020-0001"]
    entry["fetched_at"] = time.time() - 23 * 3600
    path.write_text(json.dumps(stored), encoding="utf-8")

    calls.clear()
    _run_msrc(["CVE-2020-0001", "CVE-2020-0002"], calls)
    assert calls == ["CVE-2020-0002"]
    entries = json.loads(path.read_text(encoding="utf-8"))["entries"]
    assert entries["msrc:CVE-2020-0001"]["fetched_at"] == entry["fetched_at"]

    # Past 24 hours it is fetched again rather than served stale.
    entries["msrc:CVE-2020-0001"]["fetched_at"] = time.time() - 25 * 3600
    path.write_text(json.dumps({"_schema": stored["_schema"],
                                "entries": entries}), encoding="utf-8")
    calls.clear()
    _run_msrc(["CVE-2020-0001"], calls)
    assert calls == ["CVE-2020-0001"]


def test_corrupt_vendor_cache_is_refetched_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    (tmp_path / "vendor_advisories.json").write_text("{not json",
                                                     encoding="utf-8")
    calls: list[str] = []
    findings, summary = _run_msrc(["CVE-2020-0001"], calls)
    assert calls == ["CVE-2020-0001"]
    assert summary["errors"] == 0
    assert findings[0].enrichment.vendor_advisories
    calls.clear()
    _run_msrc(["CVE-2020-0001"], calls)
    assert calls == []


def test_legacy_vendor_cache_is_still_read(tmp_path, monkeypatch):
    import json

    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    (tmp_path / "vendor_advisories.json").write_text(json.dumps({
        "msrc": {"CVE-2020-0001": parse_msrc(
            {"value": [{"ID": "OLD"}]}, "CVE-2020-0001")},
        "exploitdb": {"CVE-2020-0001": [{"advisory_id": "EDB-1"}]},
    }), encoding="utf-8")
    calls: list[str] = []
    findings, _ = _run_msrc(["CVE-2020-0001"], calls)
    assert calls == []
    assert [a.advisory_id for a in findings[0].enrichment.vendor_advisories] \
        == ["OLD"]

def test_cached_debian_records_skip_the_tracker_download(tmp_path, monkeypatch):
    import json
    import os
    import time

    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    tracker = {"apache-log4j2": {CVE: {"releases": {}}}}
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        return httpx.Response(200, json=tracker)

    finding = _finding("debian", "pkg:deb/debian/apache-log4j2")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        enrich_vendor_advisories([finding], sources="debian", client=client)
    assert requests == ["/tracker/data/json"]
    path = tmp_path / "vendor_advisories.json"
    entry = json.loads(path.read_text(encoding="utf-8"))["entries"][
        f"debian:{CVE}"]
    # The record is dated by the tracker it came from, not by this save.
    tracker_mtime = (tmp_path / "debian_security_tracker.json").stat().st_mtime
    assert abs(entry["fetched_at"] - tracker_mtime) < 1

    # The tracker is now stale, but the record is cached: no download, and
    # an unreachable tracker must not be reported as a lookup error.
    old = time.time() - 30 * 3600
    os.utime(tmp_path / "debian_security_tracker.json", (old, old))
    requests.clear()

    def unavailable(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        return httpx.Response(503)

    finding = _finding("debian", "pkg:deb/debian/apache-log4j2")
    with httpx.Client(transport=httpx.MockTransport(unavailable)) as client:
        summary = enrich_vendor_advisories([finding], sources="debian",
                                           client=client)
    assert requests == []
    assert summary["errors"] == 0
    assert finding.enrichment.vendor_lookup_errors == []


def test_legacy_vendor_cache_survives_the_first_save(tmp_path, monkeypatch):
    import json

    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    (tmp_path / "vendor_advisories.json").write_text(json.dumps({
        "msrc": {"CVE-2020-0001": parse_msrc(
            {"value": [{"ID": "OLD"}]}, "CVE-2020-0001")},
    }), encoding="utf-8")
    calls: list[str] = []
    _run_msrc(["CVE-2020-0002"], calls)  # fetches and saves one new record
    assert calls == ["CVE-2020-0002"]
    calls.clear()
    findings, _ = _run_msrc(["CVE-2020-0001"], calls)
    assert calls == []
    assert [a.advisory_id for a in findings[0].enrichment.vendor_advisories] \
        == ["OLD"]

def test_advisory_links_are_limited_to_web_urls():
    from patchtriage.models import VendorAdvisory

    def url(value):
        return VendorAdvisory(source="ghsa", advisory_id="X", url=value).url

    assert url("javascript:alert(1)") == ""
    assert url(" data:text/html,x") == ""
    assert url("https://github.com/advisories/GHSA-x") == (
        "https://github.com/advisories/GHSA-x")


def test_withdrawn_github_advisory_is_not_attached():
    rows = [{"ghsa_id": "GHSA-live", "withdrawn_at": None,
             "html_url": "https://github.com/advisories/GHSA-live"},
            {"ghsa_id": "GHSA-gone", "withdrawn_at": "2026-01-01T00:00:00Z",
             "html_url": "https://github.com/advisories/GHSA-gone"}]
    assert [r["advisory_id"] for r in parse_ghsa(rows, CVE)] == ["GHSA-live"]


@pytest.mark.parametrize("value, kept", [
    ("HTTPS://github.com/advisories/GHSA-x", True),
    ("https://", False), ("http:///x", False),
    ("https://user:pw@example.test/x", False)])
def test_advisory_url_rule_matches_target_urls(value, kept):
    from patchtriage.models import VendorAdvisory

    url = VendorAdvisory(source="ghsa", advisory_id="X", url=value).url
    assert (url == value) is kept and (url == "") is (not kept)


def test_unsafe_usn_reference_falls_back_to_the_notice_url():
    payload = {"id": f"UBUNTU-{CVE}", "related": ["USN-1234-1"],
               "references": [{"url": "javascript:/security/notices/USN-1234-1"}],
               "affected": []}
    [record] = parse_usn(payload, CVE)
    assert record["url"] == "https://ubuntu.com/security/notices/USN-1234-1"
