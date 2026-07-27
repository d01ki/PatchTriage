"""Layer 3 — Deterministic enrichment.

Authoritative exploitation and vendor sources, all free, no API key required
(NVD/GitHub keys only raise rate limits):

  * EPSS  (FIRST.org)      probability a CVE is exploited in the next 30 days
  * CISA KEV               catalog of vulnerabilities known-exploited in the wild
  * CISA Vulnrichment      CISA's own SSVC decision points on the CVE record
  * NVD                    official CVSS score/vector + CWE
  * Vendor feeds           MSRC / RHSA / Ubuntu USN / Debian / GHSA

Design rules:
  - These values are ground truth. The LLM (Layer 5) consumes them, never
    produces them.
  - Everything is cached on disk (~/.cache/patchtriage) so re-runs are cheap
    and the tool works offline after a first sync.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..models import Finding

_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "patchtriage"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Official CVE Services record API. CISA publishes its Vulnrichment SSVC
# decision points onto the CVE record as an Authorized Data Publisher (ADP),
# so the record itself -- not a mirror of it -- is the authoritative source.
CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve"

_EXPLOIT_REFERENCE_DOMAINS = ("exploit-db.com", "packetstormsecurity.com")

# The CVE ADP short name CISA publishes Vulnrichment under. Any other
# publisher's SSVC block is ignored: "authoritative" is the whole reason
# these values outrank PatchTriage's own heuristics.
_CISA_ADP_SHORT_NAME = "cisa-adp"

# Allowed values per SSVC decision point, exactly as published in the CVE
# record. Unknown values are dropped rather than guessed at.
_VULNRICHMENT_POINTS = {
    "Exploitation": ("none", "poc", "active"),
    "Automatable": ("yes", "no"),
    "Technical Impact": ("partial", "total"),
}

# One lock is shared by all JSON caches in this module and by the OSV SBOM
# resolver. It prevents in-process web worker threads from interleaving
# read/modify/write cycles. os.replace below makes each write atomic for other
# processes/readers too (cross-process merging is intentionally out of scope).
_CACHE_LOCK = threading.RLock()
_ENTRY_CACHE_SCHEMA = "patchtriage-entry-cache-v1"


@dataclass(frozen=True)
class KevCatalogResult:
    """KEV catalog entries plus the freshness needed to interpret misses.

    A stale catalog can still substantiate a positive historical listing, but
    absence from it cannot substantiate that a CVE is currently not listed.
    ``refresh_error`` records why the last-known-good fallback was necessary.
    """

    entries: dict[str, dict]
    stale: bool = False
    refresh_error: str = ""


def cache_dir() -> Path:
    """Resolve the enrichment cache directory at call time.

    Overridable via PATCHTRIAGE_CACHE_DIR so the offline demo can use an
    isolated cache and never poison a user's real one (the demo ships a tiny
    KEV/EPSS snapshot; writing it into the shared cache would break KEV
    enrichment on real scans until the 24h TTL expired).
    """
    return Path(os.environ.get("PATCHTRIAGE_CACHE_DIR") or _DEFAULT_CACHE_DIR)


# Backwards-compatible module attribute (some callers import CACHE_DIR).
CACHE_DIR = _DEFAULT_CACHE_DIR


def _cache_path(name: str) -> Path:
    d = cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / name


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _atomic_write_json(path: Path, data: Any) -> None:
    """Atomically replace a JSON cache file after a fully flushed write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent,
                prefix=f".{path.name}.", suffix=".tmp", delete=False) as temp:
            temp_name = temp.name
            json.dump(data, temp, separators=(",", ":"))
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name:
            try:
                Path(temp_name).unlink(missing_ok=True)
            except OSError:
                pass


def _load_cache(name: str, max_age_hours: float,
                *, allow_stale: bool = False) -> dict | None:
    p = _cache_path(name)
    with _CACHE_LOCK:
        try:
            fresh = ((time.time() - p.stat().st_mtime)
                     < max_age_hours * 3600)
        except OSError:
            return None
        if fresh or allow_stale:
            data = _read_json(p)
            return data if isinstance(data, dict) else None
    return None


def _save_cache(name: str, data: dict) -> None:
    with _CACHE_LOCK:
        _atomic_write_json(_cache_path(name), data)


def _decode_entry_cache(data: Any, fallback_timestamp: float) -> dict[str, dict]:
    """Normalize legacy and timestamped per-record caches."""
    if not isinstance(data, dict):
        return {}
    if data.get("_schema") == _ENTRY_CACHE_SCHEMA:
        raw_entries = data.get("entries")
        if not isinstance(raw_entries, dict):
            return {}
        decoded: dict[str, dict] = {}
        for key, wrapped in raw_entries.items():
            if not isinstance(wrapped, dict):
                continue
            value = wrapped.get("value")
            fetched_at = wrapped.get("fetched_at")
            if isinstance(value, dict) and isinstance(fetched_at, (int, float)):
                decoded[str(key)] = {
                    "value": value,
                    "fetched_at": float(fetched_at),
                }
        return decoded
    # Version 0 caches stored only values. The file mtime is the best available
    # timestamp and lets existing demo/user caches migrate without a reset.
    return {
        str(key): {"value": value, "fetched_at": fallback_timestamp}
        for key, value in data.items() if isinstance(value, dict)
    }


def _load_entry_cache(name: str, max_age_hours: float) -> dict[str, dict]:
    path = _cache_path(name)
    with _CACHE_LOCK:
        try:
            fallback_timestamp = path.stat().st_mtime
        except OSError:
            return {}
        decoded = _decode_entry_cache(_read_json(path), fallback_timestamp)
    cutoff = time.time() - max_age_hours * 3600
    return {key: wrapped["value"] for key, wrapped in decoded.items()
            if wrapped["fetched_at"] >= cutoff}


def _merge_entry_cache(name: str, updates: dict[str, dict]) -> None:
    """Atomically merge successful records with per-entry fetch timestamps."""
    if not updates:
        return
    path = _cache_path(name)
    with _CACHE_LOCK:
        try:
            fallback_timestamp = path.stat().st_mtime
        except OSError:
            fallback_timestamp = time.time()
        entries = _decode_entry_cache(
            _read_json(path) if path.exists() else {}, fallback_timestamp)
        fetched_at = time.time()
        for key, value in updates.items():
            if isinstance(value, dict):
                entries[str(key)] = {"value": value,
                                     "fetched_at": fetched_at}
        _atomic_write_json(path, {
            "_schema": _ENTRY_CACHE_SCHEMA,
            "entries": entries,
        })


# ------------------------------------------------------------------ EPSS
def fetch_epss(cves: list[str], client: httpx.Client) -> dict[str, dict]:
    """Batch EPSS lookup. Returns {cve: {epss, percentile}}."""
    cache = _load_entry_cache("epss.json", max_age_hours=24)
    missing = [c for c in cves if c not in cache]
    for i in range(0, len(missing), 100):  # API accepts comma-separated batches
        batch = missing[i:i + 100]
        r = client.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
        r.raise_for_status()
        payload = r.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ValueError("EPSS returned an invalid response schema")
        updates: dict[str, dict] = {}
        batch_ids = {requested.upper() for requested in batch}
        try:
            for row in payload["data"]:
                if not isinstance(row, dict) or not isinstance(row.get("cve"), str):
                    raise ValueError("EPSS returned an invalid response row")
                returned_cve = row["cve"].upper()
                if returned_cve not in batch_ids:
                    raise ValueError("EPSS returned a CVE outside the requested batch")
                epss = float(row["epss"])
                percentile = float(row["percentile"])
                if (not math.isfinite(epss) or not 0 <= epss <= 1
                        or not math.isfinite(percentile)
                        or not 0 <= percentile <= 1):
                    raise ValueError("EPSS returned an out-of-range probability")
                updates[returned_cve] = {
                    "epss": epss,
                    "percentile": percentile,
                }
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("EPSS returned invalid probability data") from exc
        for c in batch:  # negative-cache CVEs EPSS doesn't know
            updates.setdefault(c, {})
        cache.update(updates)
        # Only a successfully validated response may create negative entries.
        _merge_entry_cache("epss.json", updates)
    return cache


# ------------------------------------------------------------------ CISA KEV
def fetch_kev(client: httpx.Client) -> KevCatalogResult:
    """Return the KEV catalog with explicit cache-freshness metadata."""
    cache = _load_cache("kev.json", max_age_hours=24)
    if _valid_kev_cache(cache):
        return KevCatalogResult(entries=cache)
    last_known_good = _load_cache(
        "kev.json", max_age_hours=24, allow_stale=True)
    if not _valid_kev_cache(last_known_good):
        last_known_good = None
    try:
        r = client.get(KEV_URL, timeout=60, follow_redirects=True)
        r.raise_for_status()
        payload = r.json()
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            raise ValueError("CISA KEV returned an invalid or empty catalog")
        fetched: dict[str, dict] = {}
        for entry in vulnerabilities:
            if not isinstance(entry, dict):
                raise ValueError("CISA KEV returned an invalid catalog row")
            cve = entry.get("cveID")
            if not isinstance(cve, str) or not cve.upper().startswith("CVE-"):
                raise ValueError("CISA KEV catalog row is missing cveID")
            fetched[cve.upper()] = entry
        if not _valid_kev_cache(fetched):
            raise ValueError("CISA KEV catalog failed schema validation")
    except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError,
            ValueError) as exc:
        if last_known_good is not None:
            return KevCatalogResult(
                entries=last_known_good,
                stale=True,
                refresh_error=f"{type(exc).__name__}: {exc}",
            )
        raise
    _save_cache("kev.json", fetched)
    return KevCatalogResult(entries=fetched)


def _valid_kev_cache(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    return all(
        isinstance(cve, str) and cve.upper().startswith("CVE-")
        and isinstance(entry, dict)
        and isinstance(entry.get("cveID"), str)
        and str(entry["cveID"]).upper() == cve.upper()
        for cve, entry in value.items())


# ------------------------------------------------------------------ NVD
def fetch_nvd(cve: str, client: httpx.Client, api_key: str | None = None) -> dict:
    """Single-CVE NVD lookup (per-CVE cache; NVD rate limits are strict)."""
    cache = _load_entry_cache("nvd.json", max_age_hours=24 * 7)
    if cve in cache and cache[cve]:
        return cache[cve]
    headers = {"apiKey": api_key} if api_key else {}
    r = client.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=30)
    if r.status_code == 403:  # rate limited — back off once
        time.sleep(6)
        r = client.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=30)
    r.raise_for_status()
    payload = r.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("NVD returned an invalid response schema")
    vulns = payload["vulnerabilities"]
    if not vulns:
        # Do not cache a valid empty record: publication can lag a new CVE.
        return {}
    if not isinstance(vulns[0], dict) or not isinstance(vulns[0].get("cve"), dict):
        raise ValueError("NVD returned an invalid vulnerability record")
    cve_obj = vulns[0]["cve"]
    returned_id = str(cve_obj.get("id") or "")
    if returned_id and returned_id.upper() != cve.upper():
        raise ValueError("NVD returned a record for a different CVE")

    entry: dict = {}
    metrics = cve_obj.get("metrics", {})
    if not isinstance(metrics, dict):
        raise ValueError("NVD returned invalid CVSS metrics")
    for ver in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_rows = metrics.get(ver)
        if metric_rows:
            try:
                d = metric_rows[0]["cvssData"]
                entry.update({
                    "score": d.get("baseScore"),
                    "vector": d.get("vectorString", ""),
                    "version": d.get("version", ""),
                })
            except (KeyError, TypeError, IndexError) as exc:
                raise ValueError("NVD returned invalid CVSS metric data") from exc
            break
    entry["cwes"] = [
        desc["value"]
        for w in cve_obj.get("weaknesses", []) or []
        if isinstance(w, dict)
        for desc in w.get("description", []) or []
        if isinstance(desc, dict) and str(desc.get("value", "")).startswith("CWE-")
    ]
    reference_records = []
    for ref in cve_obj.get("references", []) or []:
        if not isinstance(ref, dict) or not isinstance(ref.get("url"), str):
            continue
        tags = ref.get("tags") or []
        reference_records.append({
            "url": ref["url"],
            "tags": [str(tag) for tag in tags] if isinstance(tags, list) else [],
        })
    entry["reference_records"] = reference_records
    entry["references"] = [record["url"] for record in reference_records]
    _merge_entry_cache("nvd.json", {cve: entry})
    if not api_key:
        time.sleep(0.7)  # stay under NVD's unauthenticated rate limit
    return entry


# ------------------------------------------------------- CISA Vulnrichment
def parse_vulnrichment_ssvc(record: Any) -> dict:
    """Extract CISA's SSVC decision points from a CVE record.

    Returns ``{}`` when the record carries no CISA-ADP SSVC block, which is
    the common case: roughly half of all CVEs are not yet enriched. Callers
    must treat that as "not assessed by CISA", never as a benign verdict.
    """
    if not isinstance(record, dict):
        return {}
    containers = record.get("containers")
    if not isinstance(containers, dict):
        return {}
    for container in containers.get("adp") or []:
        if not isinstance(container, dict):
            continue
        provider = container.get("providerMetadata")
        short_name = (provider or {}).get("shortName") if isinstance(
            provider, dict) else None
        if not isinstance(short_name, str):
            continue
        if short_name.strip().casefold() != _CISA_ADP_SHORT_NAME:
            continue
        for metric in container.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            other = metric.get("other")
            if not isinstance(other, dict) or other.get("type") != "ssvc":
                continue
            content = other.get("content")
            if not isinstance(content, dict):
                continue
            parsed: dict[str, str] = {}
            for option in content.get("options") or []:
                if not isinstance(option, dict):
                    continue
                for name, allowed in _VULNRICHMENT_POINTS.items():
                    value = option.get(name)
                    if isinstance(value, str) and value.strip().casefold() in allowed:
                        parsed[name] = value.strip().casefold()
            if not parsed:
                continue
            for key, source in (("role", "role"), ("version", "version"),
                                ("timestamp", "timestamp")):
                value = content.get(source)
                if isinstance(value, str):
                    parsed[key] = value
            return parsed
    return {}


def fetch_vulnrichment(cve: str, client: httpx.Client) -> dict:
    """Fetch one CVE record's CISA SSVC decision points, with a disk cache.

    The cached entry always records that a lookup *happened*: an enriched CVE
    caches its decision points, and an un-enriched one caches an explicit
    ``{"assessed": False}``. Without that marker a cache hit would be
    indistinguishable from "never looked", which is exactly the ambiguity the
    SSVC evidence model is meant to remove.
    """
    cache = _load_entry_cache("vulnrichment.json", max_age_hours=24 * 7)
    cached = cache.get(cve)
    if isinstance(cached, dict) and cached:
        return cached
    response = client.get(
        f"{CVE_RECORD_URL}/{cve}",
        headers={"Accept": "application/json"},
        timeout=30,
        follow_redirects=False,
    )
    if response.status_code == 404:
        entry = {"assessed": False, "reason": "no published CVE record"}
        _merge_entry_cache("vulnrichment.json", {cve: entry})
        return entry
    response.raise_for_status()
    parsed = parse_vulnrichment_ssvc(response.json())
    entry = {"assessed": True, **parsed} if parsed else {
        "assessed": False, "reason": "CVE record carries no CISA SSVC assessment"}
    _merge_entry_cache("vulnrichment.json", {cve: entry})
    return entry


def _apply_vulnrichment(enrichment: Any, entry: dict) -> None:
    """Copy validated SSVC decision points onto a finding's enrichment."""
    enrichment.ssvc_exploitation = entry.get("Exploitation")
    enrichment.ssvc_automatable = entry.get("Automatable")
    enrichment.ssvc_technical_impact = entry.get("Technical Impact")
    enrichment.ssvc_role = entry.get("role", "") or ""
    enrichment.ssvc_version = entry.get("version", "") or ""
    enrichment.ssvc_timestamp = entry.get("timestamp", "") or ""


def _exploit_reference_urls(nvd_entry: dict) -> list[str]:
    """Prefer NVD's structured Exploit tag, then narrow trusted host hints."""
    records = nvd_entry.get("reference_records") or []
    tagged: list[str] = []
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict) or not record.get("url"):
                continue
            tags = record.get("tags") or []
            if any(str(tag).strip().casefold() == "exploit" for tag in tags):
                tagged.append(str(record["url"]))
    if tagged:
        return list(dict.fromkeys(tagged))[:5]
    urls = [str(record.get("url")) for record in records
            if isinstance(record, dict) and record.get("url")]
    if not urls:
        urls = [str(url) for url in (nvd_entry.get("references") or []) if url]
    # A generic "poc" substring falsely matched benign words and paths.
    return list(dict.fromkeys(
        url for url in urls if _is_known_exploit_reference(url)
    ))[:5]


def _is_known_exploit_reference(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold().rstrip(".")
    if any(host == domain or host.endswith("." + domain)
           for domain in _EXPLOIT_REFERENCE_DOMAINS):
        return True
    return (host == "github.com"
            and parsed.path.casefold().startswith("/rapid7/"))


# ------------------------------------------------------------------ Orchestrator
def enrich(findings: list[Finding], nvd_api_key: str | None = None,
           use_nvd: bool = True, progress=None,
           vendor_sources: str | list[str] | None = None,
           github_token: str | None = None,
           use_vulnrichment: bool = True) -> list[Finding]:
    """Attach EPSS / KEV / NVD and optional vendor records in place."""
    cves = sorted({f.vuln_id for f in findings if f.vuln_id.startswith("CVE-")})
    now = datetime.now(timezone.utc)
    with httpx.Client() as client:
        epss: dict[str, dict] = {}
        kev_result = KevCatalogResult(entries={})
        epss_error = ""
        kev_error = ""
        try:
            epss = fetch_epss(cves, client)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            epss_error = f"{type(exc).__name__}: {exc}"
        try:
            fetched_kev = fetch_kev(client)
            # Keep compatibility with callers that monkeypatch the historical
            # dict return type while making real fetch freshness explicit.
            kev_result = (
                fetched_kev if isinstance(fetched_kev, KevCatalogResult)
                else KevCatalogResult(entries=fetched_kev)
            )
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            kev_error = f"{type(exc).__name__}: {exc}"
        for i, f in enumerate(findings):
            e = f.enrichment
            e.enriched_at = now
            if not f.vuln_id.startswith("CVE-"):
                e.retrieval_status.update({
                    "epss": "not_applicable", "kev": "not_applicable",
                    "nvd": "not_applicable", "vulnrichment": "not_applicable",
                })
                continue
            if epss_error:
                e.retrieval_status["epss"] = "failed"
                e.retrieval_errors.append(f"EPSS: {epss_error}")
            else:
                row = epss.get(f.vuln_id) or {}
                e.epss_score = row.get("epss")
                e.epss_percentile = row.get("percentile")
                e.retrieval_status["epss"] = (
                    "found" if row else "not_found")
                e.sources.append("epss")
            if kev_error:
                e.retrieval_status["kev"] = "failed"
                e.retrieval_errors.append(f"CISA KEV: {kev_error}")
            else:
                k = kev_result.entries.get(f.vuln_id)
                if k:
                    e.in_cisa_kev = True
                    e.kev_ransomware = (
                        k.get("knownRansomwareCampaignUse", "").lower()
                        == "known")
                    e.kev_due_date = k.get("dueDate")
                if kev_result.stale:
                    e.retrieval_status["kev"] = (
                        "listed_stale" if k else "unknown_stale")
                    warning = (
                        "CISA KEV: live refresh failed; a stale catalog was "
                        "used for positive matches only"
                    )
                    if kev_result.refresh_error:
                        warning += f" ({kev_result.refresh_error})"
                    e.retrieval_errors.append(warning)
                    e.sources.append("kev:stale")
                else:
                    e.retrieval_status["kev"] = (
                        "listed" if k else "not_listed")
                    e.sources.append("kev")
            if use_nvd:
                try:
                    n = fetch_nvd(f.vuln_id, client, nvd_api_key)
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                    e.retrieval_status["nvd"] = "failed"
                    e.retrieval_errors.append(
                        f"NVD: {type(exc).__name__}: {exc}")
                else:
                    e.nvd_cvss_score = n.get("score")
                    e.nvd_cvss_vector = n.get("vector", "")
                    e.nvd_cvss_version = n.get("version", "")
                    e.cwe_ids = n.get("cwes", [])
                    e.exploit_references = _exploit_reference_urls(n)
                    e.retrieval_status["nvd"] = (
                        "found" if n else "not_found")
                    if n and "nvd" not in e.exploit_sources_checked:
                        e.exploit_sources_checked.append("nvd")
                    e.sources.append("nvd")
            else:
                e.retrieval_status["nvd"] = "disabled"
            if use_vulnrichment:
                try:
                    entry = fetch_vulnrichment(f.vuln_id, client)
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                    e.retrieval_status["vulnrichment"] = "failed"
                    e.retrieval_errors.append(
                        f"CISA Vulnrichment: {type(exc).__name__}: {exc}")
                else:
                    assessed = bool(entry.get("assessed")) and any(
                        key in entry for key in _VULNRICHMENT_POINTS)
                    if assessed:
                        _apply_vulnrichment(e, entry)
                        e.retrieval_status["vulnrichment"] = "found"
                        # CISA's published Exploitation verdict is a completed
                        # exploit-evidence search by an authoritative source.
                        if "cisa-vulnrichment" not in e.exploit_sources_checked:
                            e.exploit_sources_checked.append("cisa-vulnrichment")
                    else:
                        e.retrieval_status["vulnrichment"] = "not_found"
                    e.sources.append("vulnrichment")
            else:
                e.retrieval_status["vulnrichment"] = "disabled"
            if progress:
                progress(i + 1, len(findings))
        if vendor_sources:
            # Deferred import keeps vendor adapters out of the fully offline
            # bundled-snapshot path.
            from .vendors import enrich_vendor_advisories
            enrich_vendor_advisories(
                findings, sources=vendor_sources, github_token=github_token,
                client=client)
    return findings


def enrich_from_snapshot(findings: list[Finding], epss: dict, kev: dict,
                         nvd: dict | None = None,
                         vulnrichment: dict | None = None) -> list[Finding]:
    """Attach bundled deterministic data without network or shared cache.

    Used by the browser's one-click Demo. Keeping this path explicit
    avoids mutating PATCHTRIAGE_CACHE_DIR (process-global state) and prevents a
    tiny demo catalog from contaminating real enrichment runs.
    """
    nvd = nvd or {}
    vulnrichment = vulnrichment or {}
    now = datetime.now(timezone.utc)
    for f in findings:
        e = f.enrichment
        e.enriched_at = now
        if not f.vuln_id.startswith("CVE-"):
            e.retrieval_status.update({
                "epss": "not_applicable", "kev": "not_applicable",
                "nvd": "not_applicable", "vulnrichment": "not_applicable",
            })
            continue
        row = epss.get(f.vuln_id) or {}
        e.epss_score = row.get("epss")
        e.epss_percentile = row.get("percentile")
        e.retrieval_status["epss"] = "found" if row else "not_found"
        e.sources.append("epss:snapshot")
        kev_row = kev.get(f.vuln_id)
        if kev_row:
            e.in_cisa_kev = True
            e.kev_ransomware = (
                kev_row.get("knownRansomwareCampaignUse", "").lower() == "known")
            e.kev_due_date = kev_row.get("dueDate")
        e.retrieval_status["kev"] = "listed" if kev_row else "not_listed"
        e.sources.append("kev:snapshot")
        nvd_row = nvd.get(f.vuln_id) or {}
        e.nvd_cvss_score = nvd_row.get("score")
        e.nvd_cvss_vector = nvd_row.get("vector", "")
        e.nvd_cvss_version = nvd_row.get("version", "")
        e.cwe_ids = nvd_row.get("cwes", [])
        e.exploit_references = _exploit_reference_urls(nvd_row)
        e.retrieval_status["nvd"] = "found" if nvd_row else "not_found"
        if nvd_row and "nvd:snapshot" not in e.exploit_sources_checked:
            e.exploit_sources_checked.append("nvd:snapshot")
        e.sources.append("nvd:snapshot")
        vulnrichment_row = vulnrichment.get(f.vuln_id) or {}
        assessed = bool(vulnrichment_row.get("assessed")) and any(
            key in vulnrichment_row for key in _VULNRICHMENT_POINTS)
        if assessed:
            _apply_vulnrichment(e, vulnrichment_row)
            e.retrieval_status["vulnrichment"] = "found"
            if "cisa-vulnrichment:snapshot" not in e.exploit_sources_checked:
                e.exploit_sources_checked.append("cisa-vulnrichment:snapshot")
        else:
            e.retrieval_status["vulnrichment"] = "not_found"
        e.sources.append("vulnrichment:snapshot")
    return findings
