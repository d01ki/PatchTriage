"""CISA Vulnrichment: parsing, caching honesty, and SSVC decision effects.

The value of these decision points is that CISA publishes them
authoritatively. The tests below therefore pin two things: only CISA's own
ADP block is trusted, and a missing assessment stays visibly missing instead
of decaying into a benign-looking default.
"""

from __future__ import annotations

import httpx
import pytest

from patchtriage.enrich import clients
from patchtriage.models import Asset, Finding, Package
from patchtriage.ssvc import Confidence, TechnicalImpact, assess


def _cve_record(options, *, provider="CISA-ADP", role="CISA Coordinator",
                version="2.0.3", timestamp="2024-04-17T04:00:13.543064Z"):
    return {
        "containers": {
            "adp": [
                {
                    "providerMetadata": {"shortName": provider},
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "id": "CVE-2024-3400",
                                    "role": role,
                                    "options": options,
                                    "version": version,
                                    "timestamp": timestamp,
                                },
                            }
                        }
                    ],
                }
            ]
        }
    }


_FULL_OPTIONS = [
    {"Exploitation": "active"},
    {"Automatable": "yes"},
    {"Technical Impact": "total"},
]


# ------------------------------------------------------------------ parsing

def test_parses_cisa_adp_ssvc_decision_points():
    parsed = clients.parse_vulnrichment_ssvc(_cve_record(_FULL_OPTIONS))
    assert parsed["Exploitation"] == "active"
    assert parsed["Automatable"] == "yes"
    assert parsed["Technical Impact"] == "total"
    assert parsed["role"] == "CISA Coordinator"
    assert parsed["version"] == "2.0.3"


def test_ignores_ssvc_published_by_a_non_cisa_provider():
    record = _cve_record(_FULL_OPTIONS, provider="acme-adp")
    assert clients.parse_vulnrichment_ssvc(record) == {}


def test_ignores_values_outside_the_published_vocabulary():
    record = _cve_record([
        {"Exploitation": "extremely-bad"},
        {"Automatable": "maybe"},
        {"Technical Impact": "total"},
    ])
    parsed = clients.parse_vulnrichment_ssvc(record)
    assert "Exploitation" not in parsed
    assert "Automatable" not in parsed
    assert parsed["Technical Impact"] == "total"


@pytest.mark.parametrize("record", [
    {}, {"containers": None}, {"containers": {"adp": [None]}},
    {"containers": {"adp": [{"providerMetadata": {"shortName": "CISA-ADP"}}]}},
    "not-a-record", None,
])
def test_malformed_records_parse_to_empty(record):
    assert clients.parse_vulnrichment_ssvc(record) == {}


# ------------------------------------------------------------------ fetching

def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_caches_a_positive_assessment(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, json=_cve_record(_FULL_OPTIONS))

    with _client(handler) as client:
        first = clients.fetch_vulnrichment("CVE-2024-3400", client)
        second = clients.fetch_vulnrichment("CVE-2024-3400", client)
    assert first["assessed"] is True
    assert first["Exploitation"] == "active"
    assert second == first
    assert calls["n"] == 1, "second lookup must be served from cache"


def test_unenriched_cve_is_cached_as_checked_but_unassessed(
        tmp_path, monkeypatch):
    """A CVE CISA has not enriched must not look like a clean verdict."""
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, json={"containers": {"adp": []}})

    with _client(handler) as client:
        entry = clients.fetch_vulnrichment("CVE-2020-8203", client)
        clients.fetch_vulnrichment("CVE-2020-8203", client)
    assert entry["assessed"] is False
    assert entry["reason"]
    assert calls["n"] == 1


def test_missing_cve_record_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    with _client(lambda request: httpx.Response(404)) as client:
        entry = clients.fetch_vulnrichment("CVE-9999-99999", client)
    assert entry["assessed"] is False


def test_server_error_raises_rather_than_faking_an_assessment(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    with _client(lambda request: httpx.Response(500)) as client:
        with pytest.raises(httpx.HTTPError):
            clients.fetch_vulnrichment("CVE-2024-3400", client)


# ----------------------------------------------------- effect on SSVC points

def _finding(**enrichment):
    finding = Finding(
        key="k", vuln_id="CVE-2024-3400", package=Package(name="pkg"),
        asset=Asset(identifier="asset", system_exposure="open",
                    mission_impact="mef_failure", safety_impact="marginal"),
    )
    for field, value in enrichment.items():
        setattr(finding.enrichment, field, value)
    return finding


def test_published_automatable_replaces_the_conservative_default():
    """The headline accuracy win: no more unconfirmed assumed-Yes."""
    unknown = assess(_finding()).automatable
    assert unknown.value == "yes"
    assert unknown.needs_confirmation is True
    assert unknown.confidence is Confidence.LOW

    published = assess(_finding(ssvc_automatable="no")).automatable
    assert published.value == "no"
    assert published.needs_confirmation is False
    assert published.confidence is Confidence.HIGH
    assert published.source == "CISA Vulnrichment"


def test_published_exploitation_is_used_when_kev_is_silent():
    point = assess(_finding(ssvc_exploitation="poc")).exploitation
    assert point.value == "public_poc"
    assert point.confidence is Confidence.HIGH
    assert point.source == "CISA Vulnrichment"


def test_kev_still_outranks_a_published_none():
    point = assess(
        _finding(in_cisa_kev=True, ssvc_exploitation="none")).exploitation
    assert point.value == "active"
    assert point.source == "CISA KEV"


def test_local_exploit_references_conflicting_with_none_are_surfaced():
    """An authoritative 'none' must not silently bury contradicting evidence."""
    point = assess(_finding(
        ssvc_exploitation="none",
        exploit_references=["https://www.exploit-db.com/exploits/1"],
    )).exploitation
    assert point.value == "public_poc"
    assert point.needs_confirmation is True
    assert any("disagree" in line for line in point.evidence)


def test_analyst_input_still_outranks_vulnrichment():
    finding = _finding(ssvc_exploitation="none")
    finding.ssvc_inputs = {"exploitation": "active"}
    point = assess(finding).exploitation
    assert point.value == "active"
    assert point.inferred is False


def test_technical_impact_is_recorded_but_never_changes_the_decision():
    """The Deployer tree takes Human Impact; Technical Impact rides along."""
    baseline = assess(_finding(ssvc_exploitation="active",
                               ssvc_automatable="yes"))
    with_impact = assess(_finding(ssvc_exploitation="active",
                                  ssvc_automatable="yes",
                                  ssvc_technical_impact="total"))
    assert with_impact.technical_impact.value == TechnicalImpact.TOTAL.value
    assert with_impact.technical_impact.confidence is Confidence.HIGH
    assert baseline.technical_impact.value == TechnicalImpact.UNKNOWN.value
    assert with_impact.decision == baseline.decision
    assert with_impact.suggested_deadline_days == \
        baseline.suggested_deadline_days
    # An unknown supplemental point must not drag the assessment's confidence
    # down, because it is not an input to the decision.
    assert baseline.confidence is not Confidence.LOW or \
        baseline.automatable.confidence is Confidence.LOW


def test_unassessed_cve_leaves_technical_impact_explicitly_unknown():
    point = assess(_finding()).technical_impact
    assert point.value == "unknown"
    assert point.source == "not assessed"


# ------------------------------------------------------- offline demo path

def test_bundled_demo_snapshot_covers_every_demo_cve():
    """The offline demo must exercise this feature without network access."""
    import json
    from importlib import resources

    data = resources.files("patchtriage") / "data"
    snapshot = json.loads(
        (data / "demo_vulnrichment.json").read_text(encoding="utf-8"))
    for name in ("epss", "kev", "nvd"):
        other = json.loads(
            (data / f"demo_{name}.json").read_text(encoding="utf-8"))
        missing = set(other) - set(snapshot)
        assert not missing, f"demo_{name}.json CVEs missing a snapshot: {missing}"
    # The snapshot deliberately includes an un-enriched CVE so the demo also
    # shows the honest "CISA has not assessed this" path.
    assert any(not entry.get("assessed") for entry in snapshot.values())
    assert any(entry.get("Automatable") == "no" for entry in snapshot.values())


def test_snapshot_enrichment_applies_decision_points_without_network():
    finding = _finding()
    clients.enrich_from_snapshot(
        [finding], epss={}, kev={},
        vulnrichment={"CVE-2024-3400": {
            "assessed": True, "Exploitation": "poc",
            "Automatable": "no", "Technical Impact": "partial",
        }},
    )
    assert finding.enrichment.ssvc_automatable == "no"
    assert finding.enrichment.retrieval_status["vulnrichment"] == "found"
    assessment = assess(finding)
    assert assessment.automatable.value == "no"
    assert assessment.technical_impact.value == "partial"


def test_snapshot_without_an_entry_reports_not_found():
    finding = _finding()
    clients.enrich_from_snapshot([finding], epss={}, kev={}, vulnrichment={})
    assert finding.enrichment.retrieval_status["vulnrichment"] == "not_found"
    assert finding.enrichment.ssvc_automatable is None
