"""Layer 2 — Dedup / correlation.

Multiple scanners report the same real-world problem with different ids,
severities and package spellings. We merge on a stable key:

    (canonical vuln id) x (ecosystem / namespace / package / installed version)
    x (asset identifier)

Canonical vuln id prefers CVE over GHSA/DSA/... using the alias graph, so a
Trivy "CVE-2023-1234" and a Grype "GHSA-xxxx (related: CVE-2023-1234)" merge.

Merge policy: keep the MAX severity / CVSS across scanners (conservative),
union references and reported_by, keep earliest detection time.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import unquote

from .models import Finding, Package, RawFinding, Severity

_SEV_ORDER = {
    Severity.UNKNOWN: -1,
    Severity.NEGLIGIBLE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_PKG_NORM = re.compile(r"[^a-z0-9]+")

_ECOSYSTEM_ALIASES = {
    "apk": "alpine",
    "cargo": "crates.io",
    "composer": "packagist",
    "cratesio": "crates.io",
    "deb": "debian",
    "gem": "rubygems",
    "go": "golang",
    # Java coordinates arrive under several scanner spellings: Trivy reports
    # "jar"/"pom"/"gradle", Grype "java-archive". They all identify the same
    # Maven groupId:artifactId, so they must share one dedup ecosystem.
    "gradle": "maven",
    "jar": "maven",
    "java": "maven",
    "javaarchive": "maven",
    "pom": "maven",
    "node": "npm",
    "nodejs": "npm",
    "nuget": "nuget",
    "pip": "pypi",
    "python": "pypi",
    "unknown": "",
}


def _norm_pkg(name: str) -> str:
    """python_dateutil / python-dateutil / Python.Dateutil -> pythondateutil"""
    return _PKG_NORM.sub("", name.lower())


def _norm_ecosystem(value: str) -> str:
    """Normalize scanner spelling without collapsing distinct distributions."""
    normalized = re.sub(r"[\s_.-]+", "", (value or "").strip().lower())
    return _ECOSYSTEM_ALIASES.get(normalized, normalized)


def _purl_parts(purl: str) -> tuple[str, str, str]:
    """Return the purl type, namespace and leaf name, or empty values.

    Qualifiers, versions and fragments are intentionally excluded: installed
    version is represented separately in the dedup identity.
    """
    value = (purl or "").strip()
    if not value.lower().startswith("pkg:"):
        return "", "", ""
    body = value[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return "", "", ""
    purl_type, path = body.split("/", 1)
    path = path.rsplit("@", 1)[0]
    parts = [unquote(part) for part in path.split("/") if part]
    if not parts:
        return "", "", ""
    return purl_type, "/".join(parts[:-1]), parts[-1]


def package_identity(package: Package) -> tuple[str, str, str, str]:
    """Return ecosystem, namespace, name and installed-version identity.

    A purl is the most precise source. For scanners that omit it, common
    namespace-bearing package spellings are interpreted so they can still
    correlate with a purl-producing scanner.
    """
    purl_type, namespace, purl_name = _purl_parts(package.purl)
    ecosystem = _norm_ecosystem(package.ecosystem or purl_type)
    name = (purl_name or package.name).strip()

    if not purl_name:
        raw_name = package.name.strip()
        if ecosystem == "npm" and raw_name.startswith("@") and "/" in raw_name:
            namespace, name = raw_name.rsplit("/", 1)
        elif ecosystem == "maven" and ":" in raw_name:
            namespace, name = raw_name.rsplit(":", 1)
        elif ecosystem in {"golang", "packagist"} and "/" in raw_name:
            namespace, name = raw_name.rsplit("/", 1)

    return (
        ecosystem,
        _norm_pkg(namespace),
        _norm_pkg(name),
        package.version.strip(),
    )


def _canonical_id(raw: RawFinding, alias_map: dict[str, str]) -> str:
    ids = [raw.vuln_id, *raw.aliases]
    for i in ids:
        if i.upper().startswith("CVE-"):
            return i.upper()
    # non-CVE: check whether any alias was already linked to a CVE elsewhere
    for i in ids:
        if i in alias_map:
            return alias_map[i]
    return raw.vuln_id


def dedup(raw_findings: list[RawFinding]) -> list[Finding]:
    # Pass 1: build alias -> CVE map across ALL findings (cross-scanner linking)
    alias_map: dict[str, str] = {}
    for r in raw_findings:
        ids = [r.vuln_id, *r.aliases]
        cves = [i.upper() for i in ids if i.upper().startswith("CVE-")]
        if cves:
            canonical = sorted(cves)[0]
            for i in ids:
                alias_map[i] = canonical

    # Pass 2: resolve missing ecosystem/namespace only when the compatible
    # value is unambiguous. An empty field must never bridge two distinct
    # packages that happen to share a name and version.
    identities = [package_identity(r.package) for r in raw_findings]
    base_groups: dict[tuple[str, str, str, str], list[int]] = defaultdict(list)
    canonical_ids: list[str] = []
    for index, (r, identity) in enumerate(zip(raw_findings, identities)):
        vid = _canonical_id(r, alias_map)
        canonical_ids.append(vid)
        ecosystem, namespace, package_name, version = identity
        base_groups[(vid, package_name, version, r.asset.identifier)].append(index)

    resolved = list(identities)
    for indexes in base_groups.values():
        ecosystems = {identities[i][0] for i in indexes if identities[i][0]}
        for index in indexes:
            ecosystem, namespace, name, version = resolved[index]
            if not ecosystem and len(ecosystems) == 1:
                ecosystem = next(iter(ecosystems))
            resolved[index] = (ecosystem, namespace, name, version)

        by_ecosystem: dict[str, list[int]] = defaultdict(list)
        for index in indexes:
            by_ecosystem[resolved[index][0]].append(index)
        for ecosystem_indexes in by_ecosystem.values():
            namespaces = {
                resolved[i][1] for i in ecosystem_indexes if resolved[i][1]
            }
            for index in ecosystem_indexes:
                ecosystem, namespace, name, version = resolved[index]
                if not namespace and len(namespaces) == 1:
                    namespace = next(iter(namespaces))
                resolved[index] = (ecosystem, namespace, name, version)

    # Pass 3: bucket by the complete component identity.
    buckets: dict[str, list[RawFinding]] = defaultdict(list)
    for r, vid, identity in zip(raw_findings, canonical_ids, resolved):
        ecosystem, namespace, package_name, version = identity
        key = "|".join((
            vid, ecosystem, namespace, package_name, version,
            r.asset.identifier,
        ))
        buckets[key].append(r)

    # Pass 4: merge each bucket
    findings: list[Finding] = []
    for key, group in buckets.items():
        group.sort(key=lambda r: _SEV_ORDER[r.severity], reverse=True)
        head = group[0]
        vid = _canonical_id(head, alias_map)

        aliases = sorted({a for r in group for a in [r.vuln_id, *r.aliases]
                          if a.upper() != vid})
        refs = sorted({ref for r in group for ref in r.references if ref})[:20]
        cvss = [r.cvss_score for r in group if r.cvss_score is not None]
        fixed_candidates = sorted({
            candidate.strip()
            for r in group
            for candidate in (
                [r.package.fixed_version]
                + list(r.package.fixed_version_candidates)
            )
            if candidate.strip()
        })
        fixed = next((r.package.fixed_version for r in group
                      if r.package.fixed_version), "")
        if not fixed and fixed_candidates:
            fixed = fixed_candidates[0]
        title = next((r.title for r in group if r.title), "")
        desc = max((r.description for r in group), key=len, default="")

        component = max(
            group,
            key=lambda r: (
                bool(_purl_parts(r.package.purl)[1]),
                bool(r.package.purl),
                bool(_norm_ecosystem(r.package.ecosystem)),
            ),
        )
        pkg = component.package.model_copy(update={
            "fixed_version": fixed,
            "fixed_version_candidates": fixed_candidates,
        })
        findings.append(Finding(
            key=key,
            vuln_id=vid,
            aliases=aliases,
            package=pkg,
            asset=head.asset,
            severity=head.severity,
            cvss_score=max(cvss) if cvss else None,
            title=title,
            description=desc,
            references=refs,
            reported_by=sorted({r.source_scanner for r in group}),
            first_seen=min(r.detected_at for r in group),
        ))

    findings.sort(key=lambda f: (_SEV_ORDER[f.severity], f.cvss_score or 0),
                  reverse=True)
    return findings
