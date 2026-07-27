"""Decision-quality reporting: authority vs assumption, told honestly.

The point of this summary is to make an invisible improvement visible, so
the risk it must not carry is overstating itself. These tests pin what may
be counted as "authoritative" and that a de-escalation is only claimed when a
published assessment really is less urgent than the conservative default.
"""

from __future__ import annotations

from patchtriage.models import Asset, Finding, Package
from patchtriage.presentation import decision_quality
from patchtriage.report.html import render_html
from patchtriage.ssvc import assess, triage_from_assessment


def _finding(key="k", **enrichment):
    finding = Finding(
        key=key, vuln_id="CVE-2024-3400", package=Package(name="pkg"),
        asset=Asset(identifier="asset", system_exposure="open",
                    mission_impact="mef_failure", safety_impact="marginal"),
    )
    for field, value in enrichment.items():
        setattr(finding.enrichment, field, value)
    finding.triage = triage_from_assessment(assess(finding))
    return finding


def test_counts_only_the_two_vulnerability_specific_points():
    quality = decision_quality([_finding()])
    assert quality["findings"] == 1
    assert quality["points_total"] == 2


def test_published_assessment_counts_as_authoritative():
    quality = decision_quality([
        _finding(ssvc_exploitation="poc", ssvc_automatable="no"),
    ])
    assert quality["authoritative"] == 2
    assert quality["assumed"] == 0
    assert quality["authoritative_pct"] == 100.0
    assert quality["sources"]["CISA Vulnrichment"] == 2


def test_conservative_default_is_reported_as_assumed_not_authoritative():
    quality = decision_quality([_finding()])
    assert quality["authoritative"] == 0
    assert quality["assumed"] == 2
    assert quality["needs_confirmation"] == 1
    assert "SSVC conservative default" in quality["sources"]


def test_de_escalation_is_claimed_only_for_a_published_no():
    """A published Yes agrees with the default, so nothing was corrected."""
    assert decision_quality([
        _finding(ssvc_automatable="no")])["de_escalated"] == 1
    assert decision_quality([
        _finding(ssvc_automatable="yes")])["de_escalated"] == 0
    assert decision_quality([_finding()])["de_escalated"] == 0


def test_kev_is_authoritative_for_exploitation():
    quality = decision_quality([_finding(in_cisa_kev=True)])
    assert quality["sources"]["CISA KEV"] == 1
    assert quality["authoritative"] >= 1


def test_untriaged_findings_are_excluded_rather_than_counted_as_assumed():
    untriaged = Finding(
        key="u", vuln_id="CVE-2024-0001", package=Package(name="pkg"),
        asset=Asset(identifier="asset"),
    )
    quality = decision_quality([_finding(), untriaged])
    assert quality["findings"] == 1
    assert quality["points_total"] == 2


def test_empty_run_reports_zeroes_without_dividing_by_zero():
    quality = decision_quality([])
    assert quality["points_total"] == 0
    assert quality["authoritative_pct"] == 0.0


def test_report_renders_the_decision_quality_section():
    findings = [
        _finding(key="a", ssvc_exploitation="active", ssvc_automatable="no"),
        _finding(key="b"),
    ]
    html = render_html(findings, [])
    assert "Decision quality" in html
    assert "de-escalated" in html
    assert "CISA Vulnrichment" in html


def test_report_omits_the_section_when_nothing_was_assessed():
    assert "Decision quality" not in render_html([], [])
