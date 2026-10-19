"""Authoritative vendor advisory enrichment.

The adapters normalize five public feeds without changing PatchTriage's risk
score.  Advisory presence, affected products, and fixed releases are evidence
for an operator; exploitation likelihood continues to come from KEV/EPSS.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from ..models import Finding, VendorAdvisory
from .clients import _load_cache, _save_cache

MSRC_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates/"
RHSA_URL = "https://access.redhat.com/hydra/rest/securitydata/csaf.json"
UBUNTU_OSV_URL = "https://api.osv.dev/v1/vulns/UBUNTU-"
DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"
GHSA_URL = "https://api.github.com/advisories"
# Exploit-DB's own per-CVE search (the JSON its search page uses). Queried
# live for every run and never written to disk.
EXPLOITDB_URL = "https://www.exploit-db.com/search"
EXPLOITDB_MAX_RESULTS = 10
# Concurrent per-CVE requests shared across MSRC, Ubuntu and GHSA.
PER_CVE_CONCURRENCY = 4
# Exploit-DB answers each search in about six seconds regardless of load
# (measured 2026-10-19), so it gets its own slots instead of queueing ahead
# of the other per-CVE sources.
EXPLOITDB_CONCURRENCY = 6
MSRC_GUIDE_URL = "https://msrc.microsoft.com/update-guide/vulnerability/"

ALL_SOURCES = ("msrc", "rhsa", "usn", "debian", "ghsa", "exploitdb")
# Queried for every CVE under "auto": Red Hat and Microsoft publish vendor
# analysis for many upstream CVEs (Microsoft also for Azure Linux packages),
# and Exploit-DB is the public proof-of-concept archive.
_ALWAYS_SOURCES = ("rhsa", "msrc", "exploitdb")
# Sources that are queried on every run and never persisted to the cache.
_LIVE_ONLY_SOURCES = frozenset({"exploitdb"})
_APP_ECOSYSTEMS = {
    "npm", "pypi", "maven", "nuget", "golang", "go", "rubygems", "gem",
    "cargo", "rust", "composer", "packagist", "pub", "hex", "erlang",
    "actions", "github actions", "swift",
}


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _record(**values: Any) -> dict:
    return VendorAdvisory(**values).model_dump(mode="json")


def parse_msrc(payload: dict, cve: str) -> list[dict]:
    rows = payload.get("value", []) if isinstance(payload, dict) else []
    return [
        _record(
            source="msrc",
            advisory_id=str(row.get("ID") or row.get("Alias") or cve),
            title=row.get("DocumentTitle", ""),
            # The human-readable Security Update Guide entry for this CVE;
            # the CVRF document URL is a machine feed for a whole month.
            url=f"{MSRC_GUIDE_URL}{cve}",
            published_at=row.get("InitialReleaseDate", ""),
        )
        for row in rows if isinstance(row, dict)
    ]


def parse_rhsa(payload: list | dict, cve: str) -> list[dict]:
    rows = payload if isinstance(payload, list) else payload.get("data", [])
    out = []
    for row in rows:
        if not isinstance(row, dict) or cve not in (row.get("CVEs") or []):
            continue
        advisory_id = str(row.get("RHSA") or row.get("advisory") or cve)
        packages = row.get("released_packages") or []
        out.append(_record(
            source="rhsa", advisory_id=advisory_id,
            title=f"Red Hat Security Advisory {advisory_id}",
            url=f"https://access.redhat.com/errata/{advisory_id}",
            severity=str(row.get("severity") or ""),
            published_at=str(row.get("released_on") or ""),
            products=[str(p) for p in packages],
            fixed_versions=[str(p) for p in packages],
        ))
    return out


def parse_usn(payload: dict, cve: str) -> list[dict]:
    if not isinstance(payload, dict) or not payload.get("id"):
        return []
    related = [str(v) for v in payload.get("related", [])
               if str(v).upper().startswith("USN-")]
    references = payload.get("references") or []
    advisory_urls = [
        str(ref.get("url")) for ref in references
        if isinstance(ref, dict) and ref.get("url")
        and "/security/notices/" in str(ref.get("url"))
    ]
    affected = payload.get("affected") or []
    products = _unique(
        str(item.get("package", {}).get("name", ""))
        for item in affected if isinstance(item, dict)
    )
    fixed = []
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = str(item.get("package", {}).get("name", ""))
        for version_range in item.get("ranges") or []:
            for event in version_range.get("events") or []:
                if event.get("fixed"):
                    fixed.append(f"{package} {event['fixed']}".strip())
    advisory_ids = related or [f"UBUNTU-{cve}"]
    out = []
    for index, advisory_id in enumerate(advisory_ids):
        url = next((u for u in advisory_urls
                    if advisory_id.lower() in u.lower()), "")
        if not url and advisory_id.startswith("USN-"):
            url = f"https://ubuntu.com/security/notices/{advisory_id}"
        out.append(_record(
            source="usn", advisory_id=advisory_id,
            title=str(payload.get("summary") or payload.get("details") or cve),
            url=url or (advisory_urls[index] if index < len(advisory_urls) else ""),
            published_at=str(payload.get("published") or ""),
            products=products, fixed_versions=_unique(fixed),
        ))
    return out


def parse_debian(payload: dict, cve: str) -> list[dict]:
    products, fixed, descriptions, severities = [], [], [], []
    for package, records in payload.items():
        if not isinstance(records, dict) or cve not in records:
            continue
        record = records[cve] or {}
        if record.get("description"):
            descriptions.append(str(record["description"]))
        releases = record.get("releases") or {}
        for release, state in releases.items():
            if not isinstance(state, dict):
                continue
            status = str(state.get("status") or "unknown")
            products.append(f"{package} ({release}: {status})")
            version = str(state.get("fixed_version") or "")
            if version and version != "0":
                fixed.append(f"{package} {release}: {version}")
            if state.get("urgency"):
                severities.append(str(state["urgency"]))
    if not products:
        return []
    return [_record(
        source="debian", advisory_id=cve,
        title=descriptions[0] if descriptions else f"Debian Security Tracker: {cve}",
        url=f"https://security-tracker.debian.org/tracker/{cve}",
        severity=severities[0] if severities else "",
        products=_unique(products), fixed_versions=_unique(fixed),
    )]


def parse_ghsa(payload: list | dict, cve: str) -> list[dict]:
    rows = payload if isinstance(payload, list) else []
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        vulnerabilities = row.get("vulnerabilities") or []
        products, fixed, functions = [], [], []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            package = vuln.get("package") or {}
            name = str(package.get("name") or "")
            ecosystem = str(package.get("ecosystem") or "")
            products.append(f"{ecosystem}:{name}".strip(":"))
            patched = vuln.get("first_patched_version") or ""
            patched_version = (str(patched.get("identifier") or "")
                               if isinstance(patched, dict) else str(patched))
            if patched_version:
                fixed.append(f"{name} {patched_version}".strip())
            functions.extend(str(v) for v in (vuln.get("vulnerable_functions") or []))
        out.append(_record(
            source="ghsa", advisory_id=str(row.get("ghsa_id") or cve),
            title=str(row.get("summary") or row.get("description") or cve),
            url=str(row.get("html_url") or ""),
            severity=str(row.get("severity") or ""),
            published_at=str(row.get("published_at") or ""),
            products=_unique(products), fixed_versions=_unique(fixed),
            vulnerable_functions=_unique(functions),
        ))
    return out


def parse_exploitdb(payload: dict, cve: str) -> list[dict]:
    """Normalize an Exploit-DB search response, keeping only exact CVE hits."""
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("Exploit-DB returned an unexpected search response")
    number = cve.upper().removeprefix("CVE-")
    out = []
    for row in rows[:EXPLOITDB_MAX_RESULTS]:
        if not isinstance(row, dict):
            continue
        exploit_id = str(row.get("id") or "").strip()
        codes = {
            str(code.get("code") or "").upper().removeprefix("CVE-")
            for code in (row.get("code") or [])
            if isinstance(code, dict) and code.get("code_type") == "cve"
        }
        if not exploit_id.isdigit() or number not in codes:
            continue
        description = row.get("description")
        if isinstance(description, list):
            description = description[-1] if description else ""
        kind = (row.get("type") or {}).get("display", "") \
            if isinstance(row.get("type"), dict) else ""
        platform = (row.get("platform") or {}).get("platform", "") \
            if isinstance(row.get("platform"), dict) else ""
        out.append(_record(
            source="exploitdb",
            advisory_id=f"EDB-{exploit_id}",
            title=str(description or "")[:300],
            url=f"https://www.exploit-db.com/exploits/{exploit_id}",
            severity="verified" if str(row.get("verified")) == "1"
            else "unverified",
            published_at=str(row.get("date_published") or ""),
            products=[p for p in (platform, kind) if p],
        ))
    return out


def parse_sources(value: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, str):
        requested = [v.strip().lower() for v in value.split(",") if v.strip()]
    else:
        requested = [str(v).strip().lower() for v in value if str(v).strip()]
    if requested == ["all"]:
        return ALL_SOURCES
    if "auto" in requested and requested != ["auto"]:
        raise ValueError("auto cannot be combined with explicit vendor sources")
    unknown = sorted(set(requested) - set(ALL_SOURCES) - {"auto"})
    if unknown:
        raise ValueError(
            f"unknown vendor source(s): {', '.join(unknown)}; "
            f"choose auto, all, or {','.join(ALL_SOURCES)}")
    return tuple(_unique(requested or ["auto"]))


def auto_sources(finding: Finding) -> tuple[str, ...]:
    ecosystem = finding.package.ecosystem.lower()
    purl = finding.package.purl.lower()
    kind = finding.asset.kind.lower()
    haystack = " ".join((ecosystem, purl, kind))
    sources = []
    if any(v in haystack for v in ("windows", "microsoft", "nuget", "dotnet", "powershell")):
        sources.append("msrc")
    if any(v in haystack for v in ("redhat", "rhel")):
        sources.append("rhsa")
    if "ubuntu" in haystack:
        sources.append("usn")
    if any(v in haystack for v in ("debian", "pkg:deb/debian/", "dpkg")):
        sources.append("debian")
    if ecosystem in _APP_ECOSYSTEMS or (
            purl.startswith("pkg:") and not any(
                v in purl for v in ("pkg:deb/", "pkg:rpm/", "pkg:apk/"))):
        sources.append("ghsa")
    if not any(s in sources for s in ("usn", "debian", "ghsa")):
        sources.append("ghsa")
    return tuple(_unique([*_ALWAYS_SOURCES, *sources]))


def _fetch_one(source: str, cve: str, client: httpx.Client,
               github_token: str | None) -> list[dict]:
    if source == "exploitdb":
        response = client.get(EXPLOITDB_URL, params={
            "cve": cve.upper().removeprefix("CVE-"), "draw": "1",
            "start": "0", "length": str(EXPLOITDB_MAX_RESULTS),
        }, headers={"X-Requested-With": "XMLHttpRequest",
                    "Accept": "application/json"}, timeout=30)
        response.raise_for_status()
        return parse_exploitdb(response.json(), cve)
    if source == "msrc":
        response = client.get(f"{MSRC_URL}{cve}", timeout=30)
        if response.status_code == 404:  # Microsoft has no record for it
            return []
        response.raise_for_status()
        return parse_msrc(response.json(), cve)
    if source == "usn":
        response = client.get(f"{UBUNTU_OSV_URL}{cve}", timeout=30)
        if response.status_code == 404:
            return []
        response.raise_for_status()
        return parse_usn(response.json(), cve)
    if source == "ghsa":
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "patchtriage/0.6",
        }
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        response = client.get(GHSA_URL, params={"cve_id": cve},
                              headers=headers, timeout=30)
        response.raise_for_status()
        return parse_ghsa(response.json(), cve)
    raise ValueError(f"{source} is not a per-CVE source")


def enrich_vendor_advisories(
    findings: list[Finding], sources: str | Iterable[str] = "auto",
    github_token: str | None = None, client: httpx.Client | None = None,
    max_cves: int = 50,
) -> dict:
    """Attach official vendor records in place; source failures are non-fatal."""
    requested = parse_sources(sources)
    ranked = sorted(
        {f.vuln_id for f in findings if f.vuln_id.startswith("CVE-")},
        key=lambda cve: max((
            int(f.enrichment.in_cisa_kev), f.enrichment.epss_score or 0,
            f.enrichment.nvd_cvss_score or f.cvss_score or 0,
        ) for f in findings if f.vuln_id == cve), reverse=True,
    )
    limit = max(0, max_cves)
    selected = set(ranked[:limit])
    source_cves: dict[str, set[str]] = {source: set() for source in ALL_SOURCES}
    for finding in findings:
        if finding.vuln_id not in selected:
            continue
        effective = auto_sources(finding) if requested == ("auto",) else requested
        for source in effective:
            source_cves[source].add(finding.vuln_id)

    cache = _load_cache("vendor_advisories.json", max_age_hours=24) or {}
    for source in ALL_SOURCES:
        cache.setdefault(source, {})
    for source in _LIVE_ONLY_SOURCES:
        cache[source] = {}  # never reuse a stored result for live sources
    errors: dict[tuple[str, str], str] = {}
    owns_client = client is None
    client = client or httpx.Client(
        headers={"User-Agent": "patchtriage/0.6", "Accept": "application/json"},
        follow_redirects=True,
    )
    try:
        # Red Hat accepts comma-separated CVE batches.
        missing = [c for c in source_cves["rhsa"] if c not in cache["rhsa"]]
        for start in range(0, len(missing), 50):
            batch = missing[start:start + 50]
            try:
                response = client.get(RHSA_URL, params={
                    "cve": ",".join(batch), "isCompressed": "false"}, timeout=60)
                response.raise_for_status()
                payload = response.json()
                for cve in batch:
                    cache["rhsa"][cve] = parse_rhsa(payload, cve)
            except (httpx.HTTPError, ValueError, TypeError,
                    KeyError, AttributeError) as exc:
                for cve in batch:
                    errors[("rhsa", cve)] = str(exc)

        # Debian publishes one complete tracker document; fetch it once/day.
        if source_cves["debian"]:
            debian = _load_cache("debian_security_tracker.json", max_age_hours=24)
            if debian is None:
                try:
                    response = client.get(DEBIAN_URL, timeout=120)
                    response.raise_for_status()
                    debian = response.json()
                    _save_cache("debian_security_tracker.json", debian)
                except (httpx.HTTPError, ValueError, TypeError,
                        KeyError, AttributeError) as exc:
                    for cve in source_cves["debian"]:
                        errors[("debian", cve)] = str(exc)
            if debian is not None:
                for cve in source_cves["debian"]:
                    cache["debian"][cve] = parse_debian(debian, cve)

        # Per-CVE lookups (Exploit-DB is always live; results stay in memory
        # only) run a few at a time so a large SBOM stays within request time.
        token = (github_token or os.environ.get("GITHUB_TOKEN")
                 or os.environ.get("GH_TOKEN"))
        jobs = [(source, cve) for source in ("exploitdb", "msrc", "usn", "ghsa")
                for cve in sorted(source_cves[source])
                if cve not in cache[source]]

        def lookup(job: tuple[str, str]) -> list[dict]:
            return _fetch_one(job[0], job[1], client, token)

        with ThreadPoolExecutor(max_workers=EXPLOITDB_CONCURRENCY) as slow, \
                ThreadPoolExecutor(max_workers=PER_CVE_CONCURRENCY) as pool:
            futures = {
                (slow if job[0] == "exploitdb" else pool).submit(lookup, job):
                job for job in jobs}
            for future, (source, cve) in futures.items():
                try:
                    cache[source][cve] = future.result()
                except (httpx.HTTPError, ValueError, TypeError,
                        KeyError, AttributeError) as exc:
                    errors[(source, cve)] = str(exc)
        _save_cache("vendor_advisories.json", {
            source: rows for source, rows in cache.items()
            if source not in _LIVE_ONLY_SOURCES})
    finally:
        if owns_client:
            client.close()

    advisory_count = 0
    for finding in findings:
        if finding.vuln_id not in selected:
            if (finding.vuln_id.startswith("CVE-")
                    and finding.vuln_id in set(ranked[limit:])):
                finding.enrichment.vendor_lookup_errors.append(
                    f"vendor: lookup limit {max_cves} reached")
            continue
        effective = auto_sources(finding) if requested == ("auto",) else requested
        for source in effective:
            if source not in finding.enrichment.vendor_sources_checked:
                finding.enrichment.vendor_sources_checked.append(source)
            marker = f"vendor:{source}"
            if marker not in finding.enrichment.sources:
                finding.enrichment.sources.append(marker)
            message = errors.get((source, finding.vuln_id))
            if message:
                finding.enrichment.vendor_lookup_errors.append(
                    f"{source}: {message}")
                continue
            seen = {(a.source, a.advisory_id)
                    for a in finding.enrichment.vendor_advisories}
            for row in cache[source].get(finding.vuln_id, []):
                try:
                    advisory = VendorAdvisory(**row)
                except (ValueError, TypeError) as exc:
                    finding.enrichment.vendor_lookup_errors.append(
                        f"{source}: invalid cached advisory: {exc}")
                    continue
                if (advisory.source, advisory.advisory_id) not in seen:
                    finding.enrichment.vendor_advisories.append(advisory)
                    seen.add((advisory.source, advisory.advisory_id))
                    advisory_count += 1
                if source == "exploitdb" and advisory.url and (
                        advisory.url not in finding.enrichment.exploit_references):
                    # A published Exploit-DB entry is public PoC evidence for
                    # SSVC Exploitation, alongside NVD's Exploit tags.
                    finding.enrichment.exploit_references.append(advisory.url)
            if (source == "exploitdb" and "exploitdb"
                    not in finding.enrichment.exploit_sources_checked):
                # The completed search counts as coverage even with no hit.
                finding.enrichment.exploit_sources_checked.append("exploitdb")
    return {
        "sources": [s for s in ALL_SOURCES if source_cves[s]],
        "checked_cves": len(selected), "advisories": advisory_count,
        "errors": len(errors), "truncated": max(0, len(ranked) - len(selected)),
    }
