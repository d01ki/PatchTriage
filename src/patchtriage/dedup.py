"""Layer 2 — Dedup / correlation.

Multiple scanners report the same real-world problem with different ids,
severities and package spellings. We merge on a stable key:

    (canonical vuln id) x (ecosystem / namespace / package / installed version)
    x (asset identifier)

Canonical vuln id prefers CVE over GHSA/DSA/... using the alias graph, so a
Trivy "CVE-2023-1234" and a Grype "GHSA-xxxx (related: CVE-2023-1234)" merge.
An advisory listing several CVEs (directly or through linked advisories) is
split into one finding per CVE; a record reported as a CVE keeps its id.
Other CVEs are kept as related_ids. Distribution bundles (RHSA, DSA, USN...)
never link records, because they cover many vulnerabilities.

Merge policy: keep the MAX severity / CVSS across scanners (conservative),
union references and reported_by, keep earliest detection time.
"""

from __future__ import annotations

import re
from collections import defaultdict

from .models import (Finding, Package, RawFinding, Severity,
                     normalize_ecosystem, parse_purl)

_SEV_ORDER = {
    Severity.UNKNOWN: -1,
    Severity.NEGLIGIBLE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_PKG_NORM = re.compile(r"[^a-z0-9]+")


def _norm_pkg(name: str) -> str:
    """The pre-identity-rule spelling, retained only to read old keys."""
    return _PKG_NORM.sub("", name.lower())


def _identity_part(ecosystem: str, value: str) -> str:
    """Normalize a name or namespace by its ecosystem's own equality rule.

    PyPI treats runs of ``-``, ``_`` and ``.`` as equal (PEP 503). npm names
    are distinct strings, so ``foo-bar``, ``foobar`` and ``foo_bar`` stay
    apart. Elsewhere only case is folded, because scanners disagree on it.
    """
    value = value.strip()
    # Without an ecosystem the rule is unknown; keep the spelling so it can
    # still be normalized once a peer supplies the ecosystem.
    if ecosystem == "npm" or not ecosystem:
        return value
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", value).lower()
    return value.lower()


def legacy_finding_key(key: str) -> str:
    """The key an older release produced for this finding."""
    parts = key.split("|", 5)
    if len(parts) != 6:
        return key
    parts[2], parts[3] = _norm_pkg(parts[2]), _norm_pkg(parts[3])
    return "|".join(parts)


def package_identity(package: Package) -> tuple[str, str, str, str]:
    """Return ecosystem, namespace, name and installed-version identity.

    A purl is the most precise source. For scanners that omit it, common
    namespace-bearing package spellings are interpreted so they can still
    correlate with a purl-producing scanner.
    """
    # The version is a separate identity field, not part of the name.
    purl_type, namespace, purl_name, _ = parse_purl(package.purl)
    ecosystem = normalize_ecosystem(package.ecosystem or purl_type)
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
        _identity_part(ecosystem, namespace),
        _identity_part(ecosystem, name),
        package.version.strip(),
    )


def _is_cve(value: str) -> bool:
    return value.upper().startswith("CVE-")


# Distribution advisories bundle many vulnerabilities, so sharing one says
# nothing about two records being the same vulnerability. They stay as
# aliases (provenance) but never link records together.
_BUNDLE_ADVISORY = re.compile(
    r"^(?:RHSA|RHBA|RHEA|DSA|DLA|DTSA|USN|ALAS\d*|ALSA|RLSA|ELSA|CESA|"
    r"SUSE-[A-Z]{2}|OPENSUSE-[A-Z]{2}|MGASA|FEDORA|GLSA|BIT)-",
    re.IGNORECASE)


def _links(value: str) -> bool:
    """Whether an id names one vulnerability and may link records."""
    return not _is_cve(value) and not _BUNDLE_ADVISORY.match(value)


def _per_cve(r: RawFinding, cves: list[str]
             ) -> list[tuple[RawFinding, set[str]]]:
    """One raw finding per CVE; the others are kept as related ids."""
    others = sorted({i for i in [r.vuln_id, *r.aliases] if not _is_cve(i)})
    return [(r.model_copy(update={"vuln_id": cve, "aliases": others}),
             set(cves) - {cve}) for cve in cves]


def _normalize_cves(raw_findings: list[RawFinding]
                    ) -> list[tuple[RawFinding, set[str]]]:
    """Leave every raw finding with at most one CVE.

    An advisory record (GHSA, OSV, ...) listing several CVEs covers distinct
    vulnerabilities with their own KEV, EPSS and SSVC evidence, so it gets
    one finding per CVE. A record the scanner reported *as* a CVE keeps that
    id; other CVEs it names are related, not extra findings.
    """
    out: list[tuple[RawFinding, set[str]]] = []
    for r in raw_findings:
        ids = [r.vuln_id, *r.aliases]
        cves = sorted({i.upper() for i in ids if _is_cve(i)})
        if len(cves) <= 1:
            out.append((r, set()))
            continue
        primary = (r.source_id or r.vuln_id).upper()
        if _is_cve(primary):
            out.append((r.model_copy(update={
                "vuln_id": primary,
                "aliases": [i for i in r.aliases if not _is_cve(i)],
            }), set(cves) - {primary}))
            continue
        out.extend(_per_cve(r, cves))
    return out


class _AliasGraph:
    """Connect vulnerability-level ids reported together, then their CVEs.

    Following the links transitively resolves chains such as
    GHSA -> PYSEC -> CVE, independent of input order.
    """

    def __init__(self, raws: list[RawFinding]):
        self._parent: dict[str, str] = {}
        for r in raws:
            linking = [i.upper() for i in [r.vuln_id, *r.aliases] if _links(i)]
            for i in linking:
                self._parent.setdefault(i, i)
            for a, b in zip(linking, linking[1:]):
                self._union(a, b)
        self._cves: dict[str, set[str]] = defaultdict(set)
        for r in raws:
            ids = [r.vuln_id, *r.aliases]
            cves = {i.upper() for i in ids if _is_cve(i)}
            for i in ids:
                if _links(i):
                    self._cves[self._find(i.upper())] |= cves

    def _find(self, value: str) -> str:
        while self._parent[value] != value:
            self._parent[value] = self._parent[self._parent[value]]
            value = self._parent[value]
        return value

    def _union(self, a: str, b: str) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra != rb:
            self._parent[max(ra, rb)] = min(ra, rb)

    def linked_cves(self, raw: RawFinding) -> list[str]:
        linked: set[str] = set()
        for i in [raw.vuln_id, *raw.aliases]:
            if _links(i):
                linked |= self._cves.get(self._find(i.upper()), set())
        return sorted(linked)


def _resolve_ids(raw_findings: list[RawFinding]
                 ) -> list[tuple[RawFinding, str, set[str]]]:
    """Return (raw finding, canonical id, related ids) for every record.

    A record without a CVE joins the CVE its linked advisories name. When
    they name several, it is split per CVE exactly like a multi-CVE
    advisory, so the same advisory never also stays a CVE-less duplicate.
    """
    expanded = _normalize_cves(raw_findings)
    graph = _AliasGraph([r for r, _ in expanded])
    out: list[tuple[RawFinding, str, set[str]]] = []
    for r, related in expanded:
        own = [i.upper() for i in [r.vuln_id, *r.aliases] if _is_cve(i)]
        if own:
            out.append((r, own[0], related))
            continue
        linked = graph.linked_cves(r)
        if len(linked) == 1:
            out.append((r, linked[0], related))
        elif not linked:
            out.append((r, r.vuln_id, related))
        else:
            out.extend((copy, copy.vuln_id, related | others)
                       for copy, others in _per_cve(r, linked))
    return out


def dedup(raw_findings: list[RawFinding]) -> list[Finding]:
    # Pass 1: one CVE per record, linked across ALL findings (cross-scanner,
    # transitive through vulnerability-level advisories).
    resolved_ids = _resolve_ids(raw_findings)
    raw_findings = [r for r, _, _ in resolved_ids]
    canonical_ids = [vid for _, vid, _ in resolved_ids]
    related_by_index = [related for _, _, related in resolved_ids]

    # Pass 2: resolve missing ecosystem/namespace only when the compatible
    # value is unambiguous. An empty field must never bridge two distinct
    # packages that happen to share a name and version.
    identities = [package_identity(r.package) for r in raw_findings]
    base_groups: dict[tuple[str, str, str, str], list[int]] = defaultdict(list)
    for index, (r, identity) in enumerate(zip(raw_findings, identities)):
        vid = canonical_ids[index]
        ecosystem, namespace, package_name, version = identity
        # Loose name so a finding without an ecosystem can still find its
        # peers; identities stay separate unless the name then really matches.
        base_groups[(vid, _norm_pkg(package_name), version,
                     r.asset.identifier)].append(index)

    resolved = list(identities)
    for indexes in base_groups.values():
        ecosystems = {identities[i][0] for i in indexes if identities[i][0]}
        for index in indexes:
            ecosystem, namespace, name, version = resolved[index]
            if not ecosystem and len(ecosystems) == 1:
                ecosystem = next(iter(ecosystems))
            resolved[index] = (ecosystem, namespace,
                               _identity_part(ecosystem, name), version)

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
    bucket_ids: dict[str, str] = {}
    bucket_related: dict[str, set[str]] = defaultdict(set)
    for r, vid, identity, related in zip(raw_findings, canonical_ids, resolved,
                                         related_by_index):
        ecosystem, namespace, package_name, version = identity
        key = "|".join((
            vid, ecosystem, namespace, package_name, version,
            r.asset.identifier,
        ))
        buckets[key].append(r)
        bucket_ids[key] = vid
        bucket_related[key] |= related

    # Pass 4: merge each bucket
    findings: list[Finding] = []
    for key, group in buckets.items():
        group.sort(key=lambda r: _SEV_ORDER[r.severity], reverse=True)
        head = group[0]
        vid = bucket_ids[key]

        aliases = sorted({a for r in group for a in [r.vuln_id, *r.aliases]
                          if a.upper() != vid.upper()})
        related_ids = sorted(bucket_related[key] - {vid.upper()}
                             - {a.upper() for a in aliases})
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
        title = next((r.title for r in group if r.title), "")
        desc = max((r.description for r in group), key=len, default="")

        component = max(
            group,
            key=lambda r: (
                bool(parse_purl(r.package.purl)[1]),
                bool(r.package.purl),
                bool(normalize_ecosystem(r.package.ecosystem)),
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
            related_ids=related_ids,
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
