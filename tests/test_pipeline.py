import json
from pathlib import Path

import pytest

from patchtriage.dedup import dedup
from patchtriage.ingest.parsers import load_file, sniff_format
from patchtriage.models import Asset, Enrichment, VendorAdvisory
from patchtriage.triage.engine import RulesBackend

FIX = Path(__file__).parent / "fixtures"


def _load_all():
    return (load_file(FIX / "trivy_sample.json"),
            load_file(FIX / "grype_sample.json"))


def test_sniff_format():
    assert sniff_format(json.loads((FIX / "trivy_sample.json").read_text())) == "trivy"
    assert sniff_format(json.loads((FIX / "grype_sample.json").read_text())) == "grype"
    assert sniff_format({"results": []}) == "osv"


def test_trivy_parse():
    trivy, _ = _load_all()
    assert len(trivy) == 4
    xz = next(f for f in trivy if f.vuln_id == "CVE-2024-3094")
    assert xz.severity.value == "critical"
    assert xz.cvss_score == 10.0
    assert xz.package.fixed_version.startswith("5.6.1")


def test_grype_ghsa_canonicalized_to_cve():
    _, grype = _load_all()
    lodash = next(f for f in grype if f.package.name == "lodash")
    assert lodash.vuln_id == "CVE-2021-23337"       # CVE preferred over GHSA
    assert "GHSA-35jh-r3h4-6jhm" in lodash.aliases


def test_dedup_merges_cross_scanner():
    trivy, grype = _load_all()
    findings = dedup(trivy + grype)
    # 7 raw -> 4 unique (lodash, libc6 and spring-beans overlap across scanners)
    assert len(findings) == 4
    lodash = next(f for f in findings if f.package.name == "lodash")
    assert sorted(lodash.reported_by) == ["grype", "trivy"]
    libc = next(f for f in findings if "libc" in f.package.name)
    assert sorted(libc.reported_by) == ["grype", "trivy"]
    assert libc.cvss_score == 7.8                    # max kept
    # Trivy calls the ecosystem "jar", Grype "java-archive": same Maven package
    spring = next(f for f in findings if "spring-beans" in f.package.name)
    assert sorted(spring.reported_by) == ["grype", "trivy"]


def test_rules_backend_uses_kev_as_active_ssvc_evidence():
    trivy, _ = _load_all()
    findings = dedup(trivy)
    f = findings[0]
    f.asset = Asset(
        identifier="x", system_exposure="open", automatable="yes",
        mission_impact="mef_failure", safety_impact="critical",
    )
    f.enrichment = Enrichment(in_cisa_kev=True, epss_score=0.9)
    result = RulesBackend().triage(f)
    assert result["priority"] == "P1"
    assert result["action"] == "patch_immediately"
    assert result["ssvc"]["exploitation"]["value"] == "active"


def test_rules_backend_low_signal_is_low_priority():
    trivy, _ = _load_all()
    findings = dedup(trivy)
    f = findings[-1]
    f.enrichment = Enrichment(epss_score=0.001, nvd_cvss_score=4.0)
    result = RulesBackend().triage(f)
    assert result["priority"] in ("P3", "P4")


def test_rules_backend_keeps_runtime_as_supplemental_evidence():
    trivy, _ = _load_all()
    f = dedup(trivy)[0]
    f.asset.system_exposure = "controlled"
    f.asset.automatable = "no"
    f.asset.mission_impact = "degraded"
    f.asset.safety_impact = "negligible"
    f.asset.runtime_observed = True
    f.enrichment = Enrichment(epss_score=0.6, nvd_cvss_score=8.0)
    result = RulesBackend().triage(f)
    assert result["priority"] == "P4"
    assert result["ssvc"]["supplemental"]["runtime_observed"] is True


# ---------------------------------------------------------------- new layers
from patchtriage.context import apply_context, load_inventory
from patchtriage.evalcmp import evaluate
from patchtriage.plan import build_plan
from patchtriage.presentation import (
    evaluation_outcome,
    priority_basis,
    priority_definition,
    priority_evidence,
)
from patchtriage.report.html import render_html


def _triaged_findings():
    trivy, grype = _load_all()
    findings = dedup(trivy + grype)
    for f in findings:
        f.asset.internet_exposed = True
        f.asset.criticality = "critical"
        f.asset.system_exposure = "open"
        f.asset.automatable = "yes"
        f.asset.mission_impact = "mef_failure"
        f.asset.safety_impact = "critical"
    libc = next(f for f in findings if "libc" in f.package.name)
    libc.enrichment = Enrichment(in_cisa_kev=True, kev_ransomware=True,
                                 epss_score=0.856, nvd_cvss_score=7.8)
    xz = next(f for f in findings if f.package.name == "xz-utils")
    xz.enrichment = Enrichment(epss_score=0.372, nvd_cvss_score=10.0)
    lodash = next(f for f in findings if f.package.name == "lodash")
    lodash.enrichment = Enrichment(epss_score=0.018, nvd_cvss_score=7.2)
    from patchtriage.triage.engine import RulesBackend, run_triage
    return run_triage(findings, RulesBackend())


def test_context_apply(tmp_path):
    inv = tmp_path / "assets.yaml"
    inv.write_text(
        "assets:\n  - match: 'web-frontend*'\n    criticality: critical\n"
        "    internet_exposed: true\n    reachable: true\n"
        "    runtime_observed: true\n    context_sources: [otel, falco]\n"
        "    system_exposure: open\n    automatable: yes\n"
        "    mission_impact: mef_failure\n    safety_impact: marginal\n"
        "    owner: platform-team\n    notes: customer checkout\n")
    trivy, _ = _load_all()
    findings = dedup(trivy)
    n = apply_context(findings, load_inventory(inv))
    assert n == len(findings)
    assert all(f.asset.criticality == "critical" for f in findings)
    assert all(f.asset.internet_exposed for f in findings)
    assert all(f.asset.reachable for f in findings)
    assert all(f.asset.runtime_observed for f in findings)
    assert all(f.asset.context_sources == ["otel", "falco"] for f in findings)
    assert all(f.asset.system_exposure == "open" for f in findings)
    assert all(f.asset.automatable == "yes" for f in findings)
    assert all(f.asset.mission_impact == "mef_failure" for f in findings)
    assert all(f.asset.safety_impact == "marginal" for f in findings)
    assert all(f.asset.owner == "platform-team" for f in findings)


def test_plan_ranks_kev_action_first():
    findings = _triaged_findings()
    actions = build_plan(findings)
    assert actions[0].package == "libc6"          # KEV beats CVSS 10.0
    assert actions[0].kev_count == 1
    assert actions[0].kind == "upgrade"
    assert "2.36-9+deb12u3" in actions[0].summary


def test_eval_patchtriage_beats_cvss_at_k1():
    findings = _triaged_findings()
    rows = evaluate(findings, budgets=[1])
    assert rows[0].kev_baseline == 0              # CVSS order misses the KEV
    assert rows[0].kev_epss == 1                  # strongest simple baseline
    assert rows[0].kev_patchtriage == 1           # we catch it
    assert rows[0].epss_epss == 0.856
    assert rows[0].epss_patchtriage > rows[0].epss_baseline


def test_eval_empty_inventory_has_no_comparison_rows():
    assert evaluate([]) == []


def test_priority_is_explained_in_plain_language_and_evidence():
    findings = _triaged_findings()
    libc = next(f for f in findings if "libc" in f.package.name)
    assert priority_definition("P1")["label"] == "Immediate"
    assert priority_basis(libc).startswith("The SSVC Deployer path")
    checks = {check["label"]: check for check in priority_evidence(libc)}
    assert checks["Exploitation"]["status"] == "confirmed"
    assert "Active" in checks["Exploitation"]["value"]
    assert checks["Fix readiness"]["status"] == "confirmed"


def test_evaluation_is_presented_as_user_outcomes():
    findings = _triaged_findings()
    row = evaluate(findings, budgets=[1])[0]
    outcome = evaluation_outcome(row, len(findings))
    assert outcome["review_reduction_pct"] == 75.0
    assert outcome["kev_coverage_pct"] == 100.0
    assert outcome["kev_gain_points"] == 100.0
    assert outcome["additional_kev_vs_cvss"] == 1


def test_html_report_renders():
    findings = _triaged_findings()
    actions = build_plan(findings)
    html = render_html(findings, actions, evaluate(findings))
    assert "<!doctype html>" in html
    assert "CVE-2023-4911" in html
    assert "Remediation plan" in html
    assert "Why Immediate" in html
    assert ">Immediate<" in html
    assert "Why P1" not in html
    assert all(code not in html for code in ("P1", "P2", "P3", "P4"))
    assert 'class="evidence"' in html
    assert "Exploitation" in html
    assert "smaller first-pass queue" in html
    assert "environment context decides" in html
    assert "cdn" not in html.lower()              # must stay self-contained


def test_html_report_renders_vendor_evidence():
    findings = _triaged_findings()
    findings[0].enrichment.vendor_sources_checked = ["debian"]
    findings[0].enrichment.vendor_advisories = [VendorAdvisory(
        source="debian", advisory_id=findings[0].vuln_id,
        title="Debian tracker record",
        url=f"https://security-tracker.debian.org/tracker/{findings[0].vuln_id}",
        products=["libc6 (bookworm: resolved)"],
        fixed_versions=["libc6 bookworm: 2.36-9+deb12u3"],
    )]
    html = render_html(findings, build_plan(findings), evaluate(findings))
    assert "Official vendor advisories" in html
    assert "DEBIAN" in html
    assert "2.36-9+deb12u3" in html


def test_html_report_explains_empty_input_without_a_false_comparison():
    html = render_html([], [], evaluate([]))
    assert "No vulnerability records were reported" in html
    assert "No SSVC assessment was required" in html
    assert "Outcome at a top-" not in html


def test_html_report_surfaces_incomplete_coverage_instead_of_clean_result():
    html = render_html(
        [], [], evaluate([]),
        coverage={
            "status": "incomplete", "complete": False,
            "total_components": 2, "failed_components": 2,
            "errors": ["OSV query failed"],
        },
        coverage_warnings=["Provider scope could not be verified."],
    )
    assert "evidence coverage is limited" in html
    assert "Status: incomplete" in html
    assert "OSV query failed" in html
    assert "Provider scope could not be verified" in html
    assert "No vulnerabilities found" not in html


# ---------------------------------------------------------------- audit layer
from patchtriage.triage.audit import audit_all, audit_finding
from patchtriage.triage.engine import RulesBackend as _RB


def test_audit_verifies_clean_decisions():
    findings = _triaged_findings()
    summary = audit_all(findings)
    assert summary["verified"] == summary["total"] == len(findings)
    assert all(f.triage["audit"]["verified"] for f in findings)


def test_audit_catches_fabricated_number():
    findings = _triaged_findings()
    f = findings[0]
    f.triage["rationale"] = "EPSS of 0.99 demands urgency."   # real epss differs
    result = audit_finding(f, _RB())
    assert not result["verified"]
    assert any(fl.startswith("fabricated_number") for fl in result["flags"])


def test_audit_catches_ssvc_priority_mismatch():
    findings = _triaged_findings()
    libc = next(f for f in findings if "libc" in f.package.name)
    libc.triage["priority"] = "P4"
    libc.triage["rationale"] = "seems fine"
    result = audit_finding(libc, _RB())
    assert any(fl.startswith("ssvc_priority_mismatch") for fl in result["flags"])


def test_audit_catches_patch_without_fix():
    findings = _triaged_findings()
    f = findings[0]
    f.package.fixed_version = ""
    f.triage["action"] = "patch_immediately"
    f.triage["rationale"] = "patch it"
    result = audit_finding(f, _RB())
    assert "patch_without_fix" in result["flags"]


def test_audit_catches_ssvc_action_and_deadline_mismatch():
    findings = _triaged_findings()
    f = findings[0]
    f.triage["action"] = "monitor"
    f.triage["suggested_deadline_days"] = 999
    result = audit_finding(f, _RB())
    assert any(flag.startswith("ssvc_action_mismatch") for flag in result["flags"])
    assert any(flag.startswith("ssvc_deadline_mismatch") for flag in result["flags"])


# ---------------------------------------------------------------- sbom input
def test_empty_sbom_reports_no_components(tmp_path):
    # A populated SBOM is resolved online via OSV.dev (see test_sbom.py); an
    # empty one has nothing to resolve, and the error should say exactly that.
    spdx = tmp_path / "sbom.json"
    spdx.write_text('{"spdxVersion": "SPDX-2.3", "packages": []}',
                    encoding="utf-8")
    with pytest.raises(ValueError, match="no components"):
        load_file(spdx)
