"""Regression tests for component identity, version planning and AI audit."""

import pytest

from patchtriage.dedup import dedup
from patchtriage.models import (
    Asset,
    Enrichment,
    Package,
    RawFinding,
    Severity,
)
from patchtriage.plan import build_plan, compare_versions
from patchtriage.triage.audit import audit_finding
from patchtriage.triage.engine import RulesBackend


def _raw(
    vuln_id: str,
    *,
    name: str = "widget",
    version: str = "1.0",
    ecosystem: str = "npm",
    purl: str = "",
    fixed: str = "2.0",
    scanner: str = "scanner",
    asset: str = "asset-1",
) -> RawFinding:
    return RawFinding(
        vuln_id=vuln_id,
        source_scanner=scanner,
        package=Package(
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=purl,
            fixed_version=fixed,
        ),
        asset=Asset(identifier=asset),
        severity=Severity.HIGH,
    )


def _triage(findings):
    rules = RulesBackend()
    for finding in findings:
        finding.asset.system_exposure = "open"
        finding.asset.automatable = "yes"
        finding.asset.mission_impact = "mef_failure"
        finding.asset.safety_impact = "critical"
        finding.enrichment = Enrichment(
            exploit_sources_checked=["nvd"], nvd_cvss_score=7.5,
        )
        finding.triage = rules.triage(finding)
    return findings


def test_dedup_keeps_ecosystem_and_installed_version_in_identity():
    raws = [
        _raw("CVE-2026-0001", ecosystem="debian", version="1.0"),
        _raw("CVE-2026-0001", ecosystem="deb", version="1.0",
             scanner="other"),
        _raw("CVE-2026-0001", ecosystem="debian", version="1.1"),
        _raw("CVE-2026-0001", ecosystem="npm", version="1.0"),
    ]
    findings = dedup(raws)
    assert len(findings) == 3
    merged = next(
        finding for finding in findings
        if finding.package.ecosystem == "debian" and finding.package.version == "1.0"
    )
    assert merged.reported_by == ["other", "scanner"]


def test_dedup_uses_purl_namespace_and_does_not_let_empty_bridge_ambiguity():
    raws = [
        _raw("CVE-2026-0002", ecosystem="maven",
             purl="pkg:maven/org.alpha/widget@1.0", scanner="alpha"),
        _raw("CVE-2026-0002", ecosystem="maven",
             purl="pkg:maven/org.beta/widget@1.0", scanner="beta"),
        _raw("CVE-2026-0002", ecosystem="java", scanner="unknown"),
    ]
    findings = dedup(raws)
    assert len(findings) == 3


def test_dedup_fills_one_unambiguous_missing_namespace():
    findings = dedup([
        _raw("CVE-2026-0003", ecosystem="maven",
             purl="pkg:maven/org.alpha/widget@1.0", scanner="purl"),
        _raw("CVE-2026-0003", ecosystem="java", scanner="no-purl"),
    ])
    assert len(findings) == 1
    assert findings[0].reported_by == ["no-purl", "purl"]


def test_plan_selects_numeric_highest_fix_and_retains_all_candidates():
    findings = _triage(dedup([
        _raw("CVE-2026-0010", fixed="9.9"),
        _raw("CVE-2026-0011", fixed="10.0"),
    ]))
    actions = build_plan(findings)
    assert len(actions) == 1
    assert actions[0].target_version == "10.0"
    assert actions[0].target_version_candidates == ["9.9", "10.0"]

    correlated = _triage(dedup([
        _raw("CVE-2026-0012", fixed="9.9", scanner="first"),
        _raw("CVE-2026-0012", fixed="10.0", scanner="second"),
    ]))
    assert correlated[0].package.fixed_version_candidates == ["10.0", "9.9"]
    action = build_plan(correlated)[0]
    assert action.target_version == "10.0"
    assert action.target_version_candidates == ["9.9", "10.0"]


def test_plan_understands_debian_tilde_and_keeps_installed_versions_separate():
    same_install = _triage(dedup([
        _raw("CVE-2026-0020", ecosystem="debian", fixed="2.0~rc1"),
        _raw("CVE-2026-0021", ecosystem="deb", fixed="2.0"),
    ]))
    action = build_plan(same_install)[0]
    assert action.target_version == "2.0"
    assert action.target_version_candidates == ["2.0~rc1", "2.0"]

    separate_installs = _triage(dedup([
        _raw("CVE-2026-0022", ecosystem="npm", version="1.0"),
        _raw("CVE-2026-0023", ecosystem="npm", version="1.1"),
    ]))
    actions = build_plan(separate_installs)
    assert len(actions) == 2
    assert {action.installed_version for action in actions} == {"1.0", "1.1"}

    separate_ecosystems = _triage(dedup([
        _raw("CVE-2026-0024", ecosystem="npm", version="1.0"),
        _raw("CVE-2026-0025", ecosystem="pypi", version="1.0"),
    ]))
    actions = build_plan(separate_ecosystems)
    assert len(actions) == 2
    assert {action.ecosystem for action in actions} == {"npm", "pypi"}


def test_pypi_versions_use_pep440_instead_of_semver_precedence():
    assert compare_versions("1.0-1", "1.0", "pypi") > 0
    assert compare_versions("1.0rc1", "1.0", "pypi") < 0
    assert compare_versions("1!1.0", "9.0", "pypi") > 0

    findings = _triage(dedup([
        _raw("CVE-2026-0030", ecosystem="pypi", fixed="1.0"),
        _raw("CVE-2026-0031", ecosystem="pypi", fixed="1.0-1"),
    ]))
    assert build_plan(findings)[0].target_version == "1.0-1"


def test_maven_versions_respect_service_pack_and_release_qualifiers():
    assert compare_versions("1.0-sp", "1.0", "maven") > 0
    assert compare_versions("1.0-rc1", "1.0", "maven") < 0
    assert compare_versions("1.0-final", "1.0", "maven") == 0
    assert compare_versions("1.0.1", "1.0", "maven") > 0


def _audited_finding(*, kev: bool = True, fixed: str = "2.0"):
    finding = dedup([_raw("CVE-2026-0099", fixed=fixed)])[0]
    finding.asset.system_exposure = "open"
    finding.asset.automatable = "yes"
    finding.asset.mission_impact = "mef_failure"
    finding.asset.safety_impact = "critical"
    finding.enrichment = Enrichment(
        in_cisa_kev=kev,
        epss_score=0.856,
        epss_percentile=0.991,
        nvd_cvss_score=7.5,
        exploit_sources_checked=["nvd"],
    )
    finding.triage = RulesBackend().triage(finding)
    return finding


def test_audit_checks_nested_ai_numbers_percentages_and_downgrades():
    finding = _audited_finding()
    finding.triage["ai_recommendation"] = {
        "action": "monitor",
        "rationale": "No known exploitation; EPSS is 42.4%.",
        "remediation_steps": ["Upgrade after 6.6 days."],
        "uncertainties": [],
    }
    result = audit_finding(finding, RulesBackend())
    assert any(flag.startswith("ai_action_downgrade") for flag in result["flags"])
    assert any(flag.startswith("fabricated_percentage:ai_rationale")
               for flag in result["flags"])
    assert any(flag.startswith("fabricated_number:ai_remediation_steps")
               for flag in result["flags"])
    assert "ai_kev_exploitation_downgrade_claim" in result["flags"]


def test_audit_rejects_patch_instruction_when_no_fix_exists():
    finding = _audited_finding(kev=False, fixed="")
    finding.triage["ai_recommendation"] = {
        "action": finding.triage["action"],
        "remediation_steps": ["Upgrade the package immediately."],
        "uncertainties": [],
    }
    result = audit_finding(finding, RulesBackend())
    assert "ai_patch_instruction_without_fix" in result["flags"]


def test_audit_ignores_step_numbers_and_protocol_versions_in_prose():
    finding = _audited_finding()
    finding.triage["ai_recommendation"] = {
        "action": finding.triage["action"],
        "remediation_steps": ["Step 1: require TLS 1.3 at the edge."],
        "uncertainties": [],
    }
    result = audit_finding(finding, RulesBackend())
    assert not any(flag.startswith("fabricated_number")
                   for flag in result["flags"])


def test_audit_checks_the_top_level_ai_rationale_used_by_the_engine():
    finding = _audited_finding()
    finding.triage["rationale"] = "No active exploitation has been observed."
    finding.triage["ai_recommendation"] = {
        "action": finding.triage["action"],
        "remediation_steps": [],
        "uncertainties": [],
    }
    result = audit_finding(finding, RulesBackend())
    assert "ai_kev_exploitation_downgrade_claim" in result["flags"]


def test_audit_accepts_supported_ai_claims_and_matching_action():
    finding = _audited_finding()
    finding.triage["ai_recommendation"] = {
        "action": finding.triage["action"],
        "rationale": "EPSS is 85.6% and CVSS is 7.5.",
        "remediation_steps": ["Apply the available fixed package."],
        "uncertainties": [],
    }
    result = audit_finding(finding, RulesBackend())
    assert result["verified"] is True
    assert result["flags"] == []


def _plan(*raws):
    return build_plan(_triage(dedup(list(raws))))


def test_downgrade_is_never_an_executable_upgrade():
    action = _plan(_raw("CVE-2026-0040", version="3.0.0", fixed="2.0.0"))[0]
    assert action.kind == "investigate"
    assert action.target_version == ""
    assert "newer than the installed" in action.manual_review_reason
    assert action.target_version_candidates == ["2.0.0"]


def test_fix_equal_to_installed_is_not_an_upgrade():
    action = _plan(_raw("CVE-2026-0041", version="2.0.0", fixed="2.0.0"))[0]
    assert action.kind == "investigate"


def test_spelling_variants_of_one_fix_are_a_single_stable_target():
    forward = _plan(_raw("CVE-2026-0042", version="1.0.0", fixed="v2.0.0"),
                    _raw("CVE-2026-0043", version="1.0.0", fixed="2.0.0"))[0]
    backward = _plan(_raw("CVE-2026-0043", version="1.0.0", fixed="2.0.0"),
                     _raw("CVE-2026-0042", version="1.0.0", fixed="v2.0.0"))[0]
    assert forward.kind == "upgrade"
    assert forward.target_version == backward.target_version
    assert forward.target_version_candidates == (
        backward.target_version_candidates)


@pytest.mark.parametrize("ecosystem", ["npm", "pypi"])
def test_uncomparable_versions_need_manual_review(ecosystem):
    action = _plan(_raw("CVE-2026-0044", ecosystem=ecosystem,
                        version="1.0.0", fixed="latest-build"))[0]
    assert action.kind == "investigate"
    assert "cannot be compared" in action.manual_review_reason


def test_unknown_installed_version_needs_manual_review():
    action = _plan(_raw("CVE-2026-0045", version="", fixed="2.0.0"))[0]
    assert action.kind == "investigate"
    assert "installed version is unknown" in action.manual_review_reason


def test_candidate_only_finding_is_not_recommended():
    raw = _raw("CVE-2026-0046", version="1.0.0", fixed="")
    raw.package = raw.package.model_copy(
        update={"fixed_version_candidates": ["1.1.0", "2.0.0"]})
    action = _plan(raw)[0]
    assert action.kind == "investigate"
    assert action.target_version_candidates == ["1.1.0", "2.0.0"]
    assert "candidate" in action.manual_review_reason


def test_target_covers_disjoint_fix_lines():
    action = _plan(_raw("CVE-2026-0047", version="1.0.0", fixed="1.2.5"),
                   _raw("CVE-2026-0048", version="1.0.0", fixed="2.0.1"))[0]
    assert action.kind == "upgrade"
    assert action.target_version == "2.0.1"


@pytest.mark.parametrize(
    ("ecosystem", "installed", "fixed"),
    [("apk", "1.36.1-r9", "1.36.1-r10"), ("alpine", "1.2.3-r99", "1.2.3-r100"),
     ("ubuntu", "1.2.3-1ubuntu9", "1.2.3-1ubuntu10"),
     ("rpm", "1.0.2k-19.el7", "0:1.0.2k-21.el7")])
def test_distribution_revisions_are_real_upgrades(ecosystem, installed, fixed):
    action = _plan(_raw("CVE-2026-0050", ecosystem=ecosystem,
                        version=installed, fixed=fixed))[0]
    assert action.kind == "upgrade"
    assert action.target_version == fixed
