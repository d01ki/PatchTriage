"""Layer 1 — Ingestion.

Each parser takes a scanner's native JSON output and yields RawFinding objects
in the common schema. Adding a new scanner = adding one function here and
registering it in PARSERS.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Callable, Iterator

from ..models import (Asset, Package, RawFinding, Severity,
                      normalize_ecosystem, parse_purl)
from ..plan import compare_versions


def _prefer_cve(primary: str, aliases: list[str]) -> tuple[str, list[str]]:
    """Canonicalize on a CVE id when one exists among id+aliases."""
    ids = [primary, *aliases]
    cves = [i for i in ids if i.upper().startswith("CVE-")]
    if cves:
        canonical = sorted(cves)[0].upper()
        rest = [i for i in ids if i.upper() != canonical]
        return canonical, sorted(set(rest))
    return primary, sorted(set(aliases))


def _purl_identity(value: str) -> str:
    """Version-independent, casefolded purl for OSV package matching.

    PURL types are case-insensitive. Package names are ecosystem-specific,
    but OSV feeds occasionally vary only by case, so casefold is pragmatic.
    """
    purl_type, namespace, name, _ = parse_purl(value)
    return "/".join(p for p in (purl_type, namespace, name) if p).casefold()


def _package_value(pkg: Package | dict, name: str) -> str:
    if isinstance(pkg, dict):
        return str(pkg.get(name) or "")
    return str(getattr(pkg, name, "") or "")


def _affected_matches_package(affected: dict, pkg: Package | dict,
                              allow_unqualified: bool) -> bool:
    affected_pkg = affected.get("package") or {}
    if not isinstance(affected_pkg, dict) or not affected_pkg:
        return allow_unqualified

    target_name = _package_value(pkg, "name")
    target_ecosystem = normalize_ecosystem(_package_value(pkg, "ecosystem"))
    target_purl = _purl_identity(_package_value(pkg, "purl"))
    affected_name = str(affected_pkg.get("name") or "")
    affected_ecosystem = normalize_ecosystem(
        str(affected_pkg.get("ecosystem") or ""))
    affected_purl = _purl_identity(str(affected_pkg.get("purl") or ""))

    if affected_purl and target_purl and affected_purl != target_purl:
        return False
    if affected_name and target_name and affected_name.casefold() != target_name.casefold():
        return False
    if (affected_ecosystem and target_ecosystem
            and affected_ecosystem != target_ecosystem):
        return False
    # If OSV supplies an identity field that the input lacks, do not guess
    # unless another strong field (purl or name) established the match.
    if affected_name and not target_name and not (affected_purl and target_purl):
        return False
    # Ecosystem equality is a constraint, not package identity: many packages
    # share it. A name or purl must establish the actual package match.
    return bool((affected_purl and target_purl) or
                (affected_name and target_name))


def _range_fix_candidates(osv_range: dict, installed: str,
                          explicitly_affected: bool,
                          ecosystem: str) -> list[str]:
    events = osv_range.get("events") or []
    if not isinstance(events, list):
        return []
    range_type = str(osv_range.get("type") or "").upper()
    all_fixes = [str(e.get("fixed")) for e in events
                 if isinstance(e, dict) and e.get("fixed")]
    if not installed:
        return all_fixes
    # Git commit ranges are not safely comparable as package versions. An
    # explicit affected-version list is sufficient evidence to retain a fix.
    if range_type == "GIT":
        return all_fixes if explicitly_affected else []

    candidates: list[str] = []
    introduced: str | None = "0"
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            introduced = str(event.get("introduced") or "0")
            continue
        if event.get("fixed"):
            fixed = str(event["fixed"])
            lower_ok = introduced is not None and (
                introduced in ("", "0") or
                compare_versions(installed, introduced, ecosystem) >= 0)
            upper_ok = compare_versions(installed, fixed, ecosystem) < 0
            if lower_ok and upper_ok:
                candidates.append(fixed)
            # A fixed event closes the current vulnerable interval. A later
            # introduced event starts a new, independent interval.
            introduced = None
            continue
        if event.get("last_affected") or event.get("limit"):
            introduced = None
    return candidates


def select_osv_fixed_version(vuln: dict, pkg: Package | dict) -> str:
    """Choose the applicable OSV fixed version for one package/version.

    Only matching ``affected.package`` entries are considered. Legacy records
    that omit package identity entirely remain supported, but an unqualified
    entry is ignored when the same record contains qualified package entries.
    For disjoint vulnerable intervals, the fix closing the interval containing
    the installed version is selected instead of the last fix in the record.
    """
    affected_entries = [a for a in (vuln.get("affected") or [])
                        if isinstance(a, dict)]
    has_qualified = any(isinstance(a.get("package"), dict) and a.get("package")
                        for a in affected_entries)
    installed = _package_value(pkg, "version")
    ecosystem = normalize_ecosystem(_package_value(pkg, "ecosystem"))
    candidates: list[str] = []
    for affected in affected_entries:
        if not _affected_matches_package(affected, pkg, not has_qualified):
            continue
        versions = affected.get("versions") or []
        explicitly_affected = bool(installed and isinstance(versions, list)
                                   and installed in {str(v) for v in versions})
        affected_candidates: list[str] = []
        all_entry_fixes: list[str] = []
        for osv_range in affected.get("ranges") or []:
            if isinstance(osv_range, dict):
                all_entry_fixes.extend(
                    str(event["fixed"])
                    for event in (osv_range.get("events") or [])
                    if isinstance(event, dict) and event.get("fixed")
                )
                affected_candidates.extend(_range_fix_candidates(
                    osv_range, installed, explicitly_affected, ecosystem))
        # An explicit affected-version list proves vulnerability, but not which
        # maintenance branch applies. Fall back only when the record exposes a
        # single unambiguous fix across all ranges.
        if not affected_candidates and explicitly_affected:
            unique_entry_fixes = list(dict.fromkeys(all_entry_fixes))
            if len(unique_entry_fixes) == 1:
                affected_candidates = unique_entry_fixes
        candidates.extend(affected_candidates)
    if not candidates:
        return ""
    unique = list(dict.fromkeys(candidates))
    return min(
        unique,
        key=cmp_to_key(
            lambda left, right: compare_versions(left, right, ecosystem)),
    )


def _range_affects(osv_range: dict, installed: str, ecosystem: str) -> bool:
    """Whether one OSV ECOSYSTEM/SEMVER range covers ``installed``."""
    introduced: str | None = None
    for event in osv_range.get("events") or []:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            introduced = str(event.get("introduced") or "0")
            continue
        if introduced is None:
            continue
        lower_ok = (introduced in ("", "0") or
                    compare_versions(installed, introduced, ecosystem) >= 0)
        if event.get("fixed"):
            if lower_ok and compare_versions(
                    installed, str(event["fixed"]), ecosystem) < 0:
                return True
        elif event.get("last_affected"):
            if lower_ok and compare_versions(
                    installed, str(event["last_affected"]), ecosystem) <= 0:
                return True
        elif event.get("limit"):
            if lower_ok and compare_versions(
                    installed, str(event["limit"]), ecosystem) < 0:
                return True
        introduced = None
    # An interval that is never closed affects every later version.
    return introduced is not None and (
        introduced in ("", "0")
        or compare_versions(installed, introduced, ecosystem) >= 0)


def osv_affects(vuln: dict, pkg: Package) -> bool:
    """Evaluate an OSV record's affected ranges for ``pkg`` locally.

    Needed where OSV's query API cannot compare versions itself (GitHub
    Actions). Without an installed version nothing can be ruled out.
    """
    installed = pkg.version or parse_purl(pkg.purl)[3]
    if not installed:
        return True
    ecosystem = normalize_ecosystem(pkg.ecosystem)
    entries = [a for a in (vuln.get("affected") or []) if isinstance(a, dict)]
    has_qualified = any(isinstance(a.get("package"), dict) and a.get("package")
                        for a in entries)
    bare = installed.lstrip("vV")
    for affected in entries:
        if not _affected_matches_package(affected, pkg, not has_qualified):
            continue
        if bare in {str(v).lstrip("vV") for v in affected.get("versions") or []}:
            return True
        if any(isinstance(r, dict) and str(r.get("type") or "").upper() != "GIT"
               and _range_affects(r, installed, ecosystem)
               for r in affected.get("ranges") or []):
            return True
    return False


@dataclass
class LoadResult:
    """Findings plus source-coverage metadata for completeness decisions."""

    findings: list[RawFinding]
    coverage: dict[str, Any]


# --------------------------------------------------------------------------- Trivy
def parse_trivy(data: dict, default_asset: Asset | None = None) -> Iterator[RawFinding]:
    """Trivy JSON (schema v2, `trivy image --format json`)."""
    artifact = data.get("ArtifactName", "unknown")
    artifact_type = data.get("ArtifactType", "unknown")
    asset = default_asset or Asset(
        identifier=artifact,
        kind="container_image" if artifact_type == "container_image" else artifact_type,
    )
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            vuln_id, aliases = _prefer_cve(v.get("VulnerabilityID", ""), [])
            cvss_score = None
            for src in (v.get("CVSS") or {}).values():
                for k in ("V3Score", "V40Score", "V2Score"):
                    if src.get(k) is not None:
                        cvss_score = max(cvss_score or 0.0, float(src[k]))
            yield RawFinding(
                vuln_id=vuln_id,
                aliases=aliases,
                source_scanner="trivy",
                package=Package(
                    name=v.get("PkgName", ""),
                    version=v.get("InstalledVersion", ""),
                    purl=(v.get("PkgIdentifier") or {}).get("PURL", ""),
                    ecosystem=result.get("Type", ""),
                    fixed_version=v.get("FixedVersion", ""),
                ),
                asset=asset,
                severity=Severity.parse(v.get("Severity")),
                cvss_score=cvss_score,
                title=v.get("Title", ""),
                description=(v.get("Description") or "")[:2000],
                references=(v.get("References") or [])[:15],
                raw=v,
            )


# --------------------------------------------------------------------------- Grype
def parse_grype(data: dict, default_asset: Asset | None = None) -> Iterator[RawFinding]:
    """Grype JSON (`grype -o json`)."""
    src = data.get("source") or {}
    target = src.get("target")
    if isinstance(target, dict):
        identifier = target.get("userInput") or target.get("imageID", "unknown")
    else:
        identifier = str(target or "unknown")
    asset = default_asset or Asset(identifier=identifier, kind=src.get("type", "unknown"))

    for m in data.get("matches", []) or []:
        vuln = m.get("vulnerability") or {}
        related = [r.get("id", "") for r in (m.get("relatedVulnerabilities") or [])]
        vuln_id, aliases = _prefer_cve(vuln.get("id", ""), [r for r in related if r])
        art = m.get("artifact") or {}
        cvss_score = None
        cvss_all = vuln.get("cvss") or []
        for rv in m.get("relatedVulnerabilities") or []:
            cvss_all += rv.get("cvss") or []
        for c in cvss_all:
            val = (c.get("metrics") or {}).get("baseScore")
            if val is not None:
                cvss_score = max(cvss_score or 0.0, float(val))
        fix = vuln.get("fix") or {}
        fixed_versions = fix.get("versions") or []
        yield RawFinding(
            vuln_id=vuln_id,
            aliases=aliases,
            source_scanner="grype",
            package=Package(
                name=art.get("name", ""),
                version=art.get("version", ""),
                purl=art.get("purl", ""),
                ecosystem=art.get("type", ""),
                fixed_version=fixed_versions[0] if fixed_versions else "",
            ),
            asset=asset,
            severity=Severity.parse(vuln.get("severity")),
            cvss_score=cvss_score,
            description=(vuln.get("description") or "")[:2000],
            references=[vuln.get("dataSource", "")] if vuln.get("dataSource") else [],
            raw=m,
        )


# --------------------------------------------------------------------------- OSV
def parse_osv(data: dict, default_asset: Asset | None = None) -> Iterator[RawFinding]:
    """osv-scanner JSON (`osv-scanner --format json`)."""
    for res in data.get("results", []) or []:
        source_path = (res.get("source") or {}).get("path", "unknown")
        asset = default_asset or Asset(identifier=source_path, kind="repository")
        for p in res.get("packages", []) or []:
            pkg = p.get("package") or {}
            for v in p.get("vulnerabilities", []) or []:
                vuln_id, aliases = _prefer_cve(v.get("id", ""), v.get("aliases") or [])
                sev_score = None
                for s in v.get("severity") or []:
                    if s.get("type", "").startswith("CVSS"):
                        # OSV carries vectors; keep raw score out, NVD enrich will fill it
                        pass
                fixed = select_osv_fixed_version(v, pkg)
                yield RawFinding(
                    vuln_id=vuln_id,
                    aliases=aliases,
                    source_scanner="osv",
                    package=Package(
                        name=pkg.get("name", ""),
                        version=pkg.get("version", ""),
                        ecosystem=(pkg.get("ecosystem") or "").lower(),
                        purl=pkg.get("purl", ""),
                        fixed_version=fixed,
                    ),
                    asset=asset,
                    severity=Severity.UNKNOWN,  # OSV has no simple label; NVD fills in
                    cvss_score=sev_score,
                    title=v.get("summary", ""),
                    description=(v.get("details") or "")[:2000],
                    references=[r.get("url", "") for r in (v.get("references") or [])][:15],
                    raw=v,
                )


PARSERS: dict[str, Callable[..., Iterator[RawFinding]]] = {
    "trivy": parse_trivy,
    "grype": parse_grype,
    "osv": parse_osv,
}


def sniff_format(data: dict) -> str | None:
    """Best-effort detection of which scanner produced this JSON."""
    if "Results" in data and ("ArtifactName" in data or "SchemaVersion" in data):
        return "trivy"
    if "matches" in data and "descriptor" in data:
        return "grype"
    osv_results = data.get("results")
    if isinstance(osv_results, list) and (
            not osv_results
            or all(isinstance(row, dict) and "packages" in row
                   for row in osv_results)):
        return "osv"
    return None


def load_file_with_metadata(path: str | Path, fmt: str | None = None,
                            asset: Asset | None = None,
                            progress=None) -> LoadResult:
    """Load scanner/SBOM evidence and retain explicit coverage metadata.

    Scanner JSON (Trivy/Grype/OSV) is parsed offline. SBOMs (CycloneDX / SPDX,
    e.g. the SPDX export GitHub generates) carry no vulnerabilities of their
    own, so they are resolved online via OSV.dev — no local scanner needed,
    just network access. See ingest/sbom.py.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    from .sbom import is_sbom
    sbom_kind = None if fmt in PARSERS else (fmt if fmt in ("cyclonedx", "spdx")
                                             else is_sbom(data))
    if sbom_kind:
        from .sbom import load_sbom_result
        result = load_sbom_result(path, asset=asset, progress=progress)
        return LoadResult(result.findings, result.coverage.as_dict())

    fmt = fmt or sniff_format(data)
    if fmt not in PARSERS:
        raise ValueError(
            f"Unrecognized format for {path}. Expected Trivy/Grype/OSV "
            f"scanner JSON (one of {sorted(PARSERS)}) or a CycloneDX/SPDX "
            f"SBOM. Pass fmt= to force a scanner format.")
    findings = list(PARSERS[fmt](data, asset))
    return LoadResult(findings, {
        "source_type": f"scanner:{fmt}",
        "complete": True,
        "records": len(findings),
        "errors": [],
    })


def load_file(path: str | Path, fmt: str | None = None,
              asset: Asset | None = None, progress=None) -> list[RawFinding]:
    """Backward-compatible findings-only loader.

    New callers that need to distinguish a valid empty result from incomplete
    source coverage should use :func:`load_file_with_metadata`.
    """
    # Preserve the established SBOM dispatch hook and fail closed on incomplete
    # OSV coverage. Metadata-aware callers can opt into partial results through
    # load_file_with_metadata and inspect ``coverage["complete"]``.
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    from .sbom import is_sbom
    sbom_kind = None if fmt in PARSERS else (fmt if fmt in ("cyclonedx", "spdx")
                                             else is_sbom(data))
    if sbom_kind:
        from .sbom import load_sbom
        return load_sbom(path, asset=asset, progress=progress)
    return load_file_with_metadata(
        path, fmt=fmt, asset=asset, progress=progress).findings
