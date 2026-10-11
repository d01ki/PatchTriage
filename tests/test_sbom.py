"""SBOM ingestion: format detection, component extraction, OSV mapping.

Network is not exercised here — OSV lookup is covered by mapping a canned
OSV vulnerability record onto a RawFinding.
"""

import json
from pathlib import Path

import httpx
import pytest

from patchtriage.ingest.parsers import (detect_sbom, load_file,
                                        load_file_with_metadata, parse_osv,
                                        select_osv_fixed_version)
from patchtriage.ingest.sbom import (_fetch_vuln, _osv_cache_load,
                                      _resolve_unversioned,
                                      _osv_cache_save, _query_ids,
                                      IncompleteOsvCoverageError, is_sbom,
                                      parse_sbom_components,
                                      raw_from_osv_vuln)
from patchtriage.models import Asset, Package

FIX = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def test_detects_cyclonedx_and_spdx():
    assert is_sbom(_load("sbom_cyclonedx.json")) == "cyclonedx"
    assert is_sbom(_load("sbom_spdx.json")) == "spdx"
    assert detect_sbom(_load("sbom_spdx.json")) == "SPDX"
    # a scanner file is not an SBOM
    assert is_sbom(_load("trivy_sample.json")) is None


def test_cyclonedx_components_including_nested():
    comps = parse_sbom_components(_load("sbom_cyclonedx.json"))
    names = {c.name for c in comps}
    assert names == {"lodash", "django", "sqlparse"}  # nested picked up
    django = next(c for c in comps if c.name == "django")
    assert django.version == "3.2.0"
    assert django.ecosystem == "pypi"          # derived from purl
    assert django.purl == "pkg:pypi/django@3.2.0"


def test_spdx_components_and_purl_from_externalrefs():
    comps = parse_sbom_components(_load("sbom_spdx.json"))
    names = {c.name for c in comps}
    assert names == {"lodash", "django"}
    lodash = next(c for c in comps if c.name == "lodash")
    assert lodash.purl == "pkg:npm/lodash@4.17.20"
    assert lodash.ecosystem == "npm"


def test_osv_vuln_maps_to_raw_finding_with_cve_and_fix():
    vuln = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command injection in lodash",
        "details": "long description",
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"ranges": [{"type": "SEMVER",
                                  "events": [{"introduced": "0"},
                                             {"fixed": "4.17.21"}]}],
                      "database_specific": {"severity": "HIGH"}}],
        "references": [{"url": "https://example.com/advisory"}],
    }
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm")
    asset = Asset(identifier="demo-app", kind="sbom")
    raw = raw_from_osv_vuln(vuln, pkg, asset)
    assert raw.vuln_id == "CVE-2021-23337"          # CVE preferred over GHSA
    assert "GHSA-xxxx-yyyy-zzzz" in raw.aliases
    assert raw.package.fixed_version == "4.17.21"    # from affected ranges
    assert raw.severity.value == "high"             # from database_specific
    assert raw.source_scanner == "osv-sbom"


def test_load_file_routes_sbom(monkeypatch):
    """load_file should dispatch SBOMs to the OSV resolver, not the parsers."""
    called = {}

    def fake_load_sbom(path, asset=None, progress=None):
        called["path"] = str(path)
        return []

    import patchtriage.ingest.sbom as sbom
    monkeypatch.setattr(sbom, "load_sbom", fake_load_sbom)
    load_file(FIX / "sbom_spdx.json")
    assert called["path"].endswith("sbom_spdx.json")


def test_fixed_version_matches_package_ecosystem_and_installed_range():
    vuln = {
        "affected": [
            {
                "package": {"name": "widget", "ecosystem": "Maven"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "99.0"},
                ]}],
            },
            {
                "package": {"name": "widget", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "2.0.0"},
                    {"introduced": "3.0.0"}, {"fixed": "4.0.0"},
                ]}],
            },
        ],
    }
    assert select_osv_fixed_version(
        vuln, Package(name="widget", ecosystem="npm", version="1.5.0"),
    ) == "2.0.0"
    assert select_osv_fixed_version(
        vuln, Package(name="widget", ecosystem="npm", version="3.2.0"),
    ) == "4.0.0"


def test_fix_selection_treats_rc_as_prerelease_and_never_crosses_branches():
    vuln = {
        "affected": [{
            "package": {"name": "widget", "ecosystem": "npm"},
            "versions": ["2.0.6rc1"],
            "ranges": [
                {"type": "SEMVER", "events": [
                    {"introduced": "1.9.0"}, {"fixed": "1.9.1"},
                ]},
                {"type": "SEMVER", "events": [
                    {"introduced": "2.0.0"}, {"fixed": "2.0.6"},
                ]},
            ],
        }],
    }
    assert select_osv_fixed_version(
        vuln,
        Package(name="widget", ecosystem="npm", version="2.0.6rc1"),
    ) == "2.0.6"

    ambiguous = {
        "affected": [{
            "package": {"name": "widget", "ecosystem": "npm"},
            "versions": ["custom-build"],
            "ranges": vuln["affected"][0]["ranges"],
        }],
    }
    assert select_osv_fixed_version(
        ambiguous,
        Package(name="widget", ecosystem="npm", version="custom-build"),
    ) == ""


def test_parse_osv_reuses_package_specific_fixed_version_selection():
    data = {"results": [{"source": {"path": "repo"}, "packages": [{
        "package": {"name": "widget", "ecosystem": "npm",
                    "version": "10.1.0"},
        "vulnerabilities": [{
            "id": "OSV-TEST-1",
            "affected": [
                {"package": {"name": "widget", "ecosystem": "PyPI"},
                 "ranges": [{"events": [{"introduced": "0"},
                                           {"fixed": "999.0"}]}]},
                {"package": {"name": "widget", "ecosystem": "npm"},
                 "ranges": [{"type": "SEMVER", "events": [
                     {"introduced": "10.0.0"}, {"fixed": "10.2.0"},
                 ]}]},
            ],
        }],
    }]}]}
    finding = list(parse_osv(data))[0]
    assert finding.package.fixed_version == "10.2.0"


class _BatchResponse:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _BatchClient:
    def __init__(self, payload):
        self.payload = payload

    def post(self, *args, **kwargs):
        return _BatchResponse(self.payload)


def test_osv_querybatch_short_response_is_incomplete_not_empty_success():
    packages = [
        Package(name="one", version="1", ecosystem="npm"),
        Package(name="two", version="1", ecosystem="npm"),
    ]
    result = _query_ids(packages, _BatchClient({"results": [{}]}))
    assert result.ids == [[], []]
    assert result.coverage.failed_components == 2
    assert result.coverage.queried_components == 0
    assert result.coverage.complete is False
    assert "2 queries" in result.coverage.errors[0]


def test_osv_querybatch_valid_empty_results_are_complete():
    packages = [
        Package(name="one", version="1", ecosystem="npm"),
        Package(name="two", version="1", ecosystem="npm"),
    ]
    result = _query_ids(packages, _BatchClient({"results": [{}, {}]}))
    assert result.ids == [[], []]
    assert result.coverage.queried_components == 2
    assert result.coverage.failed_components == 0
    assert result.coverage.complete is True


def test_metadata_loader_distinguishes_complete_empty_sbom(monkeypatch,
                                                           tmp_path):
    class ContextClient(_BatchClient):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    import patchtriage.ingest.sbom as sbom
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(
        sbom.httpx, "Client",
        lambda **kwargs: ContextClient({"results": [{}, {}]}),
    )
    result = load_file_with_metadata(FIX / "sbom_spdx.json")
    assert result.findings == []
    assert result.coverage["complete"] is True
    assert result.coverage["queried_components"] == 2


def test_legacy_loader_fails_closed_on_incomplete_osv_batch(monkeypatch,
                                                            tmp_path):
    class ContextClient(_BatchClient):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    import patchtriage.ingest.sbom as sbom
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(
        sbom.httpx, "Client",
        lambda **kwargs: ContextClient({"results": [{}]}),
    )
    with pytest.raises(IncompleteOsvCoverageError) as exc:
        load_file(FIX / "sbom_spdx.json")
    assert exc.value.coverage.failed_components == 2


def test_osv_coverage_counts_versionless_unqueryable_components():
    packages = [Package(name="no-version", ecosystem="npm",
                        purl="pkg:npm/no-version")]
    result = _query_ids(packages, _BatchClient({"results": []}))
    assert result.coverage.unqueryable_components == 1
    assert result.coverage.queryable_components == 0
    assert result.coverage.complete is False


class _DetailResponse(_BatchResponse):
    def __init__(self, payload, status_code=200):
        super().__init__(payload)
        self.status_code = status_code
        self.request = httpx.Request("GET", "https://api.osv.dev/v1/vulns/X")

    def raise_for_status(self):
        if self.status_code >= 400:
            response = httpx.Response(self.status_code, request=self.request)
            raise httpx.HTTPStatusError(
                f"status {self.status_code}", request=self.request,
                response=response)

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class _DetailClient:
    def __init__(self, response):
        self.response = response

    def get(self, *args, **kwargs):
        return self.response


@pytest.mark.parametrize("response", [
    _DetailResponse({}, 429),
    _DetailResponse({}, 500),
    _DetailResponse({}),
    _DetailResponse(json.JSONDecodeError("invalid", "x", 0)),
])
def test_osv_detail_failures_are_not_negative_cached(tmp_path, monkeypatch,
                                                      response):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    cache = {}
    updates = {}
    with pytest.raises((httpx.HTTPStatusError, ValueError)):
        _fetch_vuln("OSV-TEST", _DetailClient(response), cache, updates)
    _osv_cache_save(updates)
    assert cache == {}
    assert _osv_cache_load() == {}
    assert not (tmp_path / "osv_vulns.json").exists()


def test_osv_detail_success_is_timestamped_and_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    cache = {}
    updates = {}
    vuln = {"id": "OSV-TEST", "affected": []}
    assert _fetch_vuln(
        "OSV-TEST", _DetailClient(_DetailResponse(vuln)), cache, updates,
    ) == vuln
    _osv_cache_save(updates)
    assert _osv_cache_load() == {"OSV-TEST": vuln}
    stored = json.loads((tmp_path / "osv_vulns.json").read_text())
    assert stored["_schema"] == "patchtriage-entry-cache-v1"
    assert stored["entries"]["OSV-TEST"]["fetched_at"] > 0


def test_osv_detail_rejects_network_record_for_different_id(tmp_path,
                                                            monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    cache = {}
    updates = {}
    response = _DetailResponse({"id": "OSV-DIFFERENT", "affected": []})

    with pytest.raises(ValueError, match="does not match OSV-REQUESTED"):
        _fetch_vuln(
            "OSV-REQUESTED", _DetailClient(response), cache, updates)

    assert cache == {}
    assert updates == {}


def test_osv_detail_discards_mismatched_cache_before_valid_refresh():
    cache = {"OSV-REQUESTED": {"id": "OSV-DIFFERENT", "affected": []}}
    updates = {}
    expected = {"id": "OSV-REQUESTED", "affected": []}

    result = _fetch_vuln(
        "OSV-REQUESTED", _DetailClient(_DetailResponse(expected)),
        cache, updates,
    )

    assert result == expected
    assert cache == {"OSV-REQUESTED": expected}
    assert updates == {"OSV-REQUESTED": expected}


@pytest.mark.parametrize("package", [
    Package(name="actions/checkout", ecosystem="githubactions",
            purl="pkg:githubactions/actions/checkout@4.%2A.%2A"),
    Package(name="pydantic", version=">= 2.5", ecosystem="pypi",
            purl="pkg:pypi/pydantic"),
    Package(name="left-pad", version="^1.3.0", ecosystem="npm"),
])
def test_ranges_and_wildcards_are_not_sent_to_osv_as_versions(package):
    """OSV matches "4.*.*" as an opaque string and returns nothing."""
    result = _query_ids([package], _BatchClient({"results": []}))
    assert result.coverage.unqueryable_components == 1
    assert result.coverage.queried_components == 0


class _RegistryClient:
    """Fake PyPI/npm registry plus OSV querybatch, recording requests."""

    def __init__(self, versions, failing=()):
        self.versions = versions
        self.failing = set(failing)
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def get(self, url, **kwargs):
        name = next((n for n in self.versions if f"/{n}/" in url
                     or f"/{n.replace('/', '%2F')}/" in url), None)
        request = httpx.Request("GET", url)
        if name is None or name in self.failing:
            raise httpx.ConnectError("registry unreachable", request=request)
        version = self.versions[name]
        if "pypi.org" in url:
            return _BatchResponse({"info": {"version": version}})
        return _BatchResponse({"version": version})

    def post(self, url, json=None, **kwargs):
        self.queries.extend(json["queries"])
        return _BatchResponse({"results": [{} for _ in json["queries"]]})


def test_versionless_registry_packages_are_checked_at_latest_release():
    """GitHub's Dependency Graph drops ">=2.5" and lists no version at all."""
    client = _RegistryClient({"pydantic": "2.11.7", "@scope/ui": "3.1.0"})
    packages = [
        Package(name="pydantic", ecosystem="pypi", purl="pkg:pypi/pydantic"),
        Package(name="@scope/ui", ecosystem="npm",
                purl="pkg:npm/%40scope/ui"),
    ]
    resolved, inferred, errors = _resolve_unversioned(packages, client)
    assert errors == []
    assert [p.version for p in resolved] == ["2.11.7", "3.1.0"]
    assert all(p.version_source.startswith("registry-latest:")
               for p in resolved)
    assert [(i["name"], i["version"]) for i in inferred] == [
        ("pydantic", "2.11.7"), ("@scope/ui", "3.1.0")]

    result = _query_ids(resolved, client)
    assert result.coverage.queried_components == 2
    assert {"package": {"purl": "pkg:pypi/pydantic"},
            "version": "2.11.7"} in client.queries


def test_failed_registry_lookup_stays_unchecked_and_visible():
    client = _RegistryClient({"pydantic": "2.11.7"}, failing={"pydantic"})
    packages = [Package(name="pydantic", ecosystem="pypi",
                        purl="pkg:pypi/pydantic")]
    resolved, inferred, errors = _resolve_unversioned(packages, client)
    assert resolved[0].version == ""
    assert inferred == []
    assert "pydantic" in errors[0]


def test_inferred_versions_never_make_sbom_coverage_complete(monkeypatch,
                                                             tmp_path):
    import patchtriage.ingest.sbom as sbom
    sbom_path = tmp_path / "github.spdx.json"
    sbom_path.write_text(json.dumps({
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [{
            "name": "pydantic", "SPDXID": "SPDXRef-pydantic",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                              "referenceType": "purl",
                              "referenceLocator": "pkg:pypi/pydantic"}],
        }],
    }), encoding="utf-8")
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(sbom.httpx, "Client",
                        lambda **kwargs: _RegistryClient({"pydantic": "2.11.7"}))
    result = load_file_with_metadata(sbom_path)
    assert result.coverage["queried_components"] == 1
    assert result.coverage["unqueryable_components"] == 0
    assert result.coverage["inferred_components"] == 1
    assert result.coverage["inferred_versions"][0]["version"] == "2.11.7"
    assert result.coverage["complete"] is False
