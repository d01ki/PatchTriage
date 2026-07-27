"""SBOM ingestion via OSV.dev.

A software bill of materials (SBOM) lists *components*, not vulnerabilities,
so PatchTriage — a decision layer, not a scanner — cannot triage one directly.
This module turns an SBOM into findings the same way a scanner would, but
online and with no local tooling: it reads a CycloneDX or SPDX file (e.g. the
SPDX export GitHub produces from the dependency graph), extracts each package,
and queries the free OSV.dev API for known vulnerabilities.

This is the path for "I cloned the repo on Linux and my SBOM comes from
GitHub" — no Trivy/Grype install required, just network access to OSV.

Everything OSV returns is cached under the enrichment cache dir, so re-runs
are cheap and offline after the first sync.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..models import Asset, Package, RawFinding, Severity
from .parsers import _prefer_cve, select_osv_fixed_version

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_CACHE_MAX_AGE_HOURS = 24 * 7


@dataclass
class OsvCoverage:
    """Completeness evidence for one SBOM-to-OSV resolution run."""

    total_components: int = 0
    queryable_components: int = 0
    queried_components: int = 0
    unqueryable_components: int = 0
    failed_components: int = 0
    vulnerability_ids: int = 0
    vulnerability_details_resolved: int = 0
    vulnerability_details_failed: int = 0
    errors: list[str] = field(default_factory=list)
    # Which components were skipped, and which ecosystems were actually
    # checked. A bare count hides the case that matters most: an SBOM whose
    # only checkable entries are CI actions, while every application
    # dependency is skipped for want of a resolved version. "0 findings"
    # then means "nothing you depend on was examined".
    unqueryable_names: list[str] = field(default_factory=list)
    queried_ecosystems: list[str] = field(default_factory=list)
    unqueryable_ecosystems: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return (self.unqueryable_components == 0
                and self.failed_components == 0
                and self.vulnerability_details_failed == 0
                and self.queried_components == self.total_components)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_type": "sbom:osv",
            "complete": self.complete,
            "total_components": self.total_components,
            "queryable_components": self.queryable_components,
            "queried_components": self.queried_components,
            "unqueryable_components": self.unqueryable_components,
            "failed_components": self.failed_components,
            "vulnerability_ids": self.vulnerability_ids,
            "vulnerability_details_resolved": self.vulnerability_details_resolved,
            "vulnerability_details_failed": self.vulnerability_details_failed,
            "errors": list(self.errors),
            "unqueryable_names": list(self.unqueryable_names),
            "queried_ecosystems": list(self.queried_ecosystems),
            "unqueryable_ecosystems": list(self.unqueryable_ecosystems),
        }


@dataclass
class OsvQueryResult:
    ids: list[list[str]]
    coverage: OsvCoverage


@dataclass
class SbomLoadResult:
    findings: list[RawFinding]
    coverage: OsvCoverage


class IncompleteOsvCoverageError(RuntimeError):
    """Raised by legacy loaders rather than returning a false clean result."""

    def __init__(self, coverage: OsvCoverage):
        self.coverage = coverage
        detail = "; ".join(coverage.errors[:3]) or "unknown OSV coverage error"
        super().__init__(f"SBOM vulnerability coverage is incomplete: {detail}")


_LAST_COVERAGE = threading.local()


def get_last_source_coverage() -> dict[str, Any] | None:
    """Return coverage from this thread's latest ``load_sbom`` call."""
    coverage = getattr(_LAST_COVERAGE, "value", None)
    return coverage.as_dict() if isinstance(coverage, OsvCoverage) else None


# --------------------------------------------------------------- SBOM parsing
def is_sbom(data: dict) -> str | None:
    """Return 'cyclonedx' | 'spdx' if data looks like an SBOM, else None."""
    if data.get("bomFormat") == "CycloneDX" or "components" in data and \
            data.get("specVersion"):
        return "cyclonedx"
    if str(data.get("spdxVersion", "")).startswith("SPDX-") or \
            ("SPDXID" in data and "packages" in data):
        return "spdx"
    return None


def _purl_from_spdx_pkg(pkg: dict) -> str:
    for ref in pkg.get("externalRefs", []) or []:
        if ref.get("referenceType") == "purl" or \
                ref.get("referenceCategory") in ("PACKAGE-MANAGER", "PACKAGE_MANAGER"):
            loc = ref.get("referenceLocator", "")
            if loc.startswith("pkg:"):
                return loc
    return ""


def _components_cyclonedx(data: dict) -> list[Package]:
    out: list[Package] = []

    def walk(comps):
        for c in comps or []:
            name = c.get("name", "")
            if name:
                out.append(Package(
                    name=name,
                    version=c.get("version", ""),
                    purl=c.get("purl", ""),
                    ecosystem=_ecosystem_from_purl(c.get("purl", "")),
                ))
            walk(c.get("components"))  # CycloneDX allows nested components

    walk(data.get("components"))
    return out


def _components_spdx(data: dict) -> list[Package]:
    out: list[Package] = []
    for p in data.get("packages", []) or []:
        name = p.get("name", "")
        if not name:
            continue
        purl = _purl_from_spdx_pkg(p)
        out.append(Package(
            name=name,
            version=p.get("versionInfo", ""),
            purl=purl,
            ecosystem=_ecosystem_from_purl(purl),
        ))
    return out


def _ecosystem_from_purl(purl: str) -> str:
    # pkg:pypi/django@3.2 -> pypi ; pkg:golang/... -> golang
    if purl.startswith("pkg:"):
        rest = purl[4:]
        return rest.split("/", 1)[0].split("@", 1)[0]
    return ""


def parse_sbom_components(data: dict) -> list[Package]:
    kind = is_sbom(data)
    if kind == "cyclonedx":
        return _components_cyclonedx(data)
    if kind == "spdx":
        return _components_spdx(data)
    raise ValueError("not a recognized CycloneDX or SPDX SBOM")


# --------------------------------------------------------------- OSV mapping
def raw_from_osv_vuln(vuln: dict, pkg: Package, asset: Asset) -> RawFinding:
    """Map one OSV vulnerability record onto a RawFinding."""
    vuln_id, aliases = _prefer_cve(vuln.get("id", ""), vuln.get("aliases") or [])

    fixed = select_osv_fixed_version(vuln, pkg)

    # OSV sometimes carries a coarse label in database_specific
    sev_label = ""
    for src in (vuln.get("database_specific"), *(
            (aff.get("database_specific") or {})
            for aff in vuln.get("affected") or [])):
        if isinstance(src, dict) and src.get("severity"):
            sev_label = str(src["severity"])
            break

    return RawFinding(
        vuln_id=vuln_id,
        aliases=aliases,
        source_scanner="osv-sbom",
        package=pkg.model_copy(update={"fixed_version": fixed}),
        asset=asset,
        severity=Severity.parse(sev_label),
        title=vuln.get("summary", ""),
        description=(vuln.get("details") or "")[:2000],
        references=[r.get("url", "") for r in (vuln.get("references") or [])][:15],
        raw=vuln,
    )


# --------------------------------------------------------------- OSV lookup
def _osv_cache_load() -> dict:
    from ..enrich.clients import _load_entry_cache
    return {
        vid: value
        for vid, value in _load_entry_cache(
            "osv_vulns.json", OSV_CACHE_MAX_AGE_HOURS).items()
        if _valid_osv_vuln(value, expected_id=vid)
    }


def _osv_cache_save(cache: dict) -> None:
    from ..enrich.clients import _merge_entry_cache
    _merge_entry_cache(
        "osv_vulns.json",
        {vid: value for vid, value in cache.items()
         if _valid_osv_vuln(value, expected_id=vid)},
    )


def _valid_osv_vuln(value: Any, expected_id: str | None = None) -> bool:
    if (not isinstance(value, dict)
            or not isinstance(value.get("id"), str)
            or not value["id"]):
        return False
    return expected_id is None or value["id"] == expected_id


def _purl_has_version(purl: str) -> bool:
    main = str(purl or "").split("?", 1)[0].split("#", 1)[0]
    return main.rfind("@") > main.find("/")


def _osv_ecosystem(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return {
        "pypi": "PyPI",
        "python": "PyPI",
        "golang": "Go",
        "go": "Go",
        "npm": "npm",
        "maven": "Maven",
        "nuget": "NuGet",
        "rubygems": "RubyGems",
        "gem": "RubyGems",
        "cargo": "crates.io",
        "crates.io": "crates.io",
    }.get(normalized, value)


def _component_query(component: Package) -> dict | None:
    if component.purl and (component.version or _purl_has_version(component.purl)):
        query: dict[str, Any] = {"package": {"purl": component.purl}}
        if component.version and not _purl_has_version(component.purl):
            query["version"] = component.version
        return query
    if component.ecosystem and component.name and component.version:
        return {
            "package": {"name": component.name,
                        "ecosystem": _osv_ecosystem(component.ecosystem)},
            "version": component.version,
        }
    return None


def _query_ids(components: list[Package], client: httpx.Client,
               progress=None) -> OsvQueryResult:
    """Resolve IDs and retain strict per-component query coverage.

    OSV must return exactly one result object per query. A short/malformed
    batch is marked failed as a whole rather than being positionally assigned
    to the wrong package or silently interpreted as no vulnerabilities.
    """
    queries = [_component_query(c) for c in components]

    ids: list[list[str]] = [[] for _ in queries]
    idx = [i for i, q in enumerate(queries) if q is not None]
    payload = [queries[i] for i in idx]
    skipped = [c for i, c in enumerate(components) if queries[i] is None]
    checked = [c for i, c in enumerate(components) if queries[i] is not None]
    coverage = OsvCoverage(
        total_components=len(components),
        queryable_components=len(payload),
        unqueryable_components=len(components) - len(payload),
        unqueryable_names=[c.name for c in skipped if c.name][:50],
        queried_ecosystems=sorted(
            {c.ecosystem for c in checked if c.ecosystem}),
        unqueryable_ecosystems=sorted(
            {c.ecosystem for c in skipped if c.ecosystem}),
    )
    if coverage.unqueryable_components:
        coverage.errors.append(
            f"{coverage.unqueryable_components} component(s) lacked a "
            "queryable package version/purl")
    for start in range(0, len(payload), 100):
        chunk = payload[start:start + 100]
        chunk_idx = idx[start:start + 100]
        try:
            r = client.post(OSV_QUERYBATCH_URL,
                            json={"queries": chunk}, timeout=60)
            r.raise_for_status()
            response = r.json()
            results = response.get("results") if isinstance(response, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                actual = len(results) if isinstance(results, list) else "invalid"
                raise ValueError(
                    f"OSV querybatch returned {actual} result(s) for "
                    f"{len(chunk)} queries")
            parsed: list[list[str]] = []
            for result in results:
                if not isinstance(result, dict):
                    raise ValueError("OSV querybatch returned a non-object result")
                vulns = result.get("vulns") or []
                if not isinstance(vulns, list):
                    raise ValueError("OSV querybatch returned invalid vulnerabilities")
                parsed.append(list(dict.fromkeys(
                    str(v["id"]) for v in vulns
                    if isinstance(v, dict) and v.get("id"))))
            for local_i, vuln_ids in enumerate(parsed):
                ids[chunk_idx[local_i]] = vuln_ids
            coverage.queried_components += len(chunk)
        except (httpx.HTTPError, json.JSONDecodeError, TypeError,
                ValueError) as exc:
            coverage.failed_components += len(chunk)
            coverage.errors.append(str(exc) or exc.__class__.__name__)
        if progress:
            progress(min(start + 100, len(payload)), len(payload))
    coverage.vulnerability_ids = sum(len(group) for group in ids)
    return OsvQueryResult(ids, coverage)


def _fetch_vuln(vid: str, client: httpx.Client, cache: dict,
                updates: dict | None = None) -> dict:
    cached = cache.get(vid)
    if _valid_osv_vuln(cached, expected_id=vid):
        return cached
    # A mismatched/corrupt cache record must never be associated with the
    # requested vulnerability. Discard it and require a validated refresh.
    cache.pop(vid, None)
    r = client.get(OSV_VULN_URL + vid, timeout=30)
    r.raise_for_status()
    entry = r.json()
    if not _valid_osv_vuln(entry, expected_id=vid):
        returned_id = entry.get("id") if isinstance(entry, dict) else None
        detail = f" (received {returned_id!r})" if returned_id else ""
        raise ValueError(
            f"OSV returned a vulnerability record that does not match {vid}"
            f"{detail}")
    cache[vid] = entry
    if updates is not None:
        updates[vid] = entry
    return entry


def load_sbom_result(path: str | Path, asset: Asset | None = None,
                     progress=None) -> SbomLoadResult:
    """Resolve an SBOM and return findings with completeness evidence."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    components = parse_sbom_components(data)
    if not components:
        raise ValueError(f"{path}: SBOM parsed but contained no components")

    default_asset = asset or Asset(identifier=Path(path).name, kind="sbom")
    cache = _osv_cache_load()
    cache_updates: dict[str, dict] = {}
    findings: list[RawFinding] = []
    with httpx.Client(headers={"user-agent": "patchtriage"}) as client:
        query_result = _query_ids(components, client, progress)
        coverage = query_result.coverage
        failed_details: dict[str, str] = {}
        for pkg, vids in zip(components, query_result.ids):
            for vid in vids:
                if vid in failed_details:
                    coverage.vulnerability_details_failed += 1
                    continue
                try:
                    vuln = _fetch_vuln(
                        vid, client, cache, updates=cache_updates)
                except (httpx.HTTPError, json.JSONDecodeError, TypeError,
                        ValueError) as exc:
                    message = str(exc) or exc.__class__.__name__
                    failed_details[vid] = message
                    coverage.vulnerability_details_failed += 1
                    coverage.errors.append(f"{vid}: {message}")
                    continue
                coverage.vulnerability_details_resolved += 1
                findings.append(raw_from_osv_vuln(vuln, pkg, default_asset))
    _osv_cache_save(cache_updates)
    return SbomLoadResult(findings, coverage)


def load_sbom(path: str | Path, asset: Asset | None = None,
              progress=None) -> list[RawFinding]:
    """Backward-compatible findings-only SBOM loader.

    ``get_last_source_coverage`` exposes completeness for legacy callers;
    new code should prefer ``load_sbom_result`` or ``load_file_with_metadata``.
    """
    result = load_sbom_result(path, asset=asset, progress=progress)
    _LAST_COVERAGE.value = result.coverage
    if not result.coverage.complete:
        raise IncompleteOsvCoverageError(result.coverage)
    return result.findings
