"""CISA BOD 26-04 response policy, evaluated separately from SSVC Deployer.

Expected outcomes come from tests/fixtures/bod2604_decision_table.json, which
was transcribed from the CERT/CC CSV and pins that file's SHA-256. Nothing
here derives expectations from the engine under test.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from patchtriage import bod2604
from patchtriage.context import apply_context
from patchtriage.models import Asset, Enrichment, Finding, Package
from patchtriage.ssvc import assess, triage_from_assessment

FIXTURE = Path(__file__).parent / "fixtures" / "bod2604_decision_table.json"


def _expectations() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _finding(*, kev_status="not_listed", in_kev=False, vulnrichment="found",
             automatable=None, technical=None, applicability="unknown",
             publicly_exposed="unknown", internet_exposed=None,
             system_exposure="unknown", mission="unknown",
             fixed="1.2.4", vector="", date_added=None) -> Finding:
    finding = Finding(
        key="CVE-2024-0001|pkg|asset",
        vuln_id="CVE-2024-0001",
        package=Package(name="pkg", version="1.2.3", fixed_version=fixed),
        asset=Asset(
            identifier="asset", internet_exposed=internet_exposed,
            system_exposure=system_exposure, mission_impact=mission,
            publicly_exposed=publicly_exposed,
            bod2604_applicability=applicability,
        ),
        enrichment=Enrichment(
            in_cisa_kev=in_kev,
            kev_date_added=date_added,
            ssvc_automatable=automatable,
            ssvc_technical_impact=technical,
            nvd_cvss_vector=vector,
            retrieval_status={"kev": kev_status,
                              "vulnrichment": vulnrichment},
        ),
    )
    finding.triage = triage_from_assessment(assess(finding))
    return finding


# ---------------------------------------------------------------- conformance
def test_pinned_expectations_match_their_recorded_source_fingerprint():
    data = _expectations()
    text = data["source"]["csv"]
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == \
        data["source"]["sha256"]
    parsed = [list(row.values()) for row in csv.DictReader(text.splitlines())]
    assert [
        [str(r["row"]), r["in_kev"], r["publicly_exposed"], r["automatable"],
         r["technical_impact"], r["outcome_name"]] for r in data["rows"]
    ] == parsed
    assert data["model"] == bod2604.POLICY_ID
    assert data["outcome_group"] == bod2604.OUTCOME_GROUP


def test_all_16_published_rows_match_the_policy_table():
    rows = _expectations()["rows"]
    assert len(rows) == 16
    combos = {(r["in_kev"], r["publicly_exposed"], r["automatable"],
               r["technical_impact"]) for r in rows}
    assert len(combos) == 16  # every input combination exactly once
    for row in rows:
        assert bod2604.bod_outcome(
            row["in_kev"], row["publicly_exposed"], row["automatable"],
            row["technical_impact"]) == row["outcome"], row


def test_only_3df_adds_forensic_triage_and_fsu_has_no_numeric_deadline():
    for key, outcome in bod2604.OUTCOMES.items():
        assert ("forensic_triage" in outcome["obligations"]) is (key == "3DF")
    assert bod2604.OUTCOMES["FSU"]["days"] is None
    assert {k: v["days"] for k, v in bod2604.OUTCOMES.items()
            if k != "FSU"} == {"60D": 60, "14D": 14, "3D": 3, "3DF": 3}


# ---------------------------------------------------------------- inputs
def test_resolved_inputs_produce_published_outcome_and_keep_ssvc():
    finding = _finding(kev_status="listed", in_kev=True, automatable="yes",
                       technical="total", publicly_exposed="yes",
                       applicability="required", date_added="2024-01-02")
    before = json.dumps(finding.triage["ssvc"], sort_keys=True)
    priority = finding.triage["priority"]
    bod2604.apply_policy([finding])
    policy = finding.triage["bod2604"]
    assert policy["status"] == "resolved"
    assert policy["outcome"] == "3DF"
    assert "forensic_triage" in policy["obligations"]
    assert policy["kev_date_added"] == "2024-01-02"
    # No absolute due date is fabricated: the agency identification date that
    # can start the clock earlier is not known to PatchTriage.
    assert "due_date" not in policy
    assert "earlier of" in policy["deadline_anchor"]
    assert json.dumps(finding.triage["ssvc"], sort_keys=True) == before
    assert finding.triage["priority"] == priority


def test_failed_kev_lookup_never_becomes_not_in_kev():
    finding = _finding(kev_status="failed", automatable="yes",
                       technical="total", publicly_exposed="yes")
    policy = bod2604.evaluate(finding)
    assert policy["inputs"]["in_kev"]["value"] == "unknown"
    assert policy["status"] == "unresolved"
    assert policy["outcome"] is None
    # (N|Y, Y, Y, T) -> 3D or 3DF: provisional is the most urgent candidate.
    assert policy["candidate_outcomes"] == ["3DF", "3D"]
    assert policy["provisional_outcome"] == "3DF"
    assert "in_kev" in policy["unresolved_inputs"]


@pytest.mark.parametrize("status", ["unknown_stale", "", "not_applicable"])
def test_incomplete_kev_states_stay_unresolved(status):
    policy = bod2604.evaluate(_finding(kev_status=status))
    assert policy["inputs"]["in_kev"]["resolved"] is False


def test_cisa_defaults_apply_only_when_both_missing_and_not_in_kev():
    policy = bod2604.evaluate(_finding(vulnrichment="not_found",
                                       publicly_exposed="no"))
    assert policy["inputs"]["automatable"]["value"] == "no"
    assert policy["inputs"]["technical_impact"]["value"] == "total"
    assert policy["inputs"]["automatable"]["defaulted"] is True
    assert policy["outcome"] == "FSU"  # (N, N, N, T)


def test_kev_cve_without_vulnrichment_is_not_defaulted():
    policy = bod2604.evaluate(_finding(kev_status="listed", in_kev=True,
                                       vulnrichment="not_found",
                                       publicly_exposed="yes"))
    assert policy["inputs"]["automatable"]["value"] == "unknown"
    assert policy["inputs"]["technical_impact"]["value"] == "unknown"
    assert set(policy["candidate_outcomes"]) == {"14D", "3D", "3DF"}
    assert policy["status"] == "unresolved"


def test_failed_vulnrichment_lookup_is_not_treated_as_unpublished():
    policy = bod2604.evaluate(_finding(vulnrichment="failed",
                                       publicly_exposed="no"))
    assert policy["inputs"]["automatable"]["resolved"] is False
    assert policy["inputs"]["technical_impact"]["resolved"] is False


def test_one_published_value_does_not_trigger_the_pair_default():
    policy = bod2604.evaluate(_finding(automatable="yes",
                                       publicly_exposed="no"))
    assert policy["inputs"]["automatable"]["value"] == "yes"
    assert policy["inputs"]["technical_impact"]["value"] == "unknown"
    # (N, N, Y, P|T) -> 60D either way: resolved despite the unknown.
    assert policy["status"] == "resolved" and policy["outcome"] == "60D"


def test_publicly_exposed_is_not_ssvc_system_exposure():
    open_but_unanswered = bod2604.evaluate(_finding(system_exposure="open"))
    assert open_but_unanswered["inputs"]["publicly_exposed"]["value"] == \
        "unknown"
    small_but_exposed = bod2604.evaluate(
        _finding(system_exposure="small", publicly_exposed="yes"))
    assert small_but_exposed["inputs"]["publicly_exposed"]["value"] == "yes"


def test_internet_exposure_evidence_sets_yes_but_its_absence_not_no():
    assert bod2604.evaluate(_finding(internet_exposed=True))[
        "inputs"]["publicly_exposed"]["value"] == "yes"
    assert bod2604.evaluate(_finding(internet_exposed=False))[
        "inputs"]["publicly_exposed"]["value"] == "unknown"
    assert bod2604.evaluate(_finding(publicly_exposed="no",
                                     internet_exposed=True))[
        "inputs"]["publicly_exposed"]["value"] == "no"


def test_technical_impact_is_not_derived_from_human_impact():
    severe = bod2604.evaluate(_finding(mission="mission_failure",
                                       vulnrichment="failed"))
    assert severe["inputs"]["technical_impact"]["value"] == "unknown"


def test_cvss_v4_automatable_is_used_as_published_metadata():
    policy = bod2604.evaluate(_finding(
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/AU:Y",
        technical="partial", publicly_exposed="no"))
    assert policy["inputs"]["automatable"]["value"] == "yes"
    assert policy["inputs"]["automatable"]["source"] == "CVSS v4 Automatable"


# ---------------------------------------------------------------- precedence
def _ssvc(days, label="Scheduled"):
    return {"suggested_deadline_days": days, "decision_label": label}


def _policy(outcome, *, applicability="voluntary", status="resolved",
            unresolved=()):
    result = {
        "applicability": applicability,
        "applied": applicability in bod2604.APPLIED,
        "status": status,
        "outcome": outcome if status == "resolved" else None,
        "provisional_outcome": None if status == "resolved" else outcome,
        "unresolved_inputs": list(unresolved),
    }
    return result


@pytest.mark.parametrize("applicability", ["unknown", "not_applicable"])
def test_unapplied_policy_never_changes_the_ssvc_deadline(applicability):
    effective = bod2604.resolve_effective(
        _ssvc(30), _policy("3DF", applicability=applicability))
    assert effective["rule"] == "ssvc_only"
    assert effective["deadline_days"] == 30
    assert "forensic_triage" not in effective["obligations"]


def test_bod_maximum_applies_when_not_later_than_workflow_target():
    effective = bod2604.resolve_effective(_ssvc(30), _policy("14D"))
    assert (effective["rule"], effective["deadline_days"]) == \
        ("bod_maximum", 14)


def test_stricter_workflow_target_still_keeps_forensic_triage():
    effective = bod2604.resolve_effective(_ssvc(1, "Immediate"),
                                          _policy("3DF"))
    assert effective["rule"] == "workflow_target_stricter"
    assert effective["deadline_days"] == 1
    assert "forensic_triage" in effective["obligations"]


def test_fix_on_system_upgrade_is_neither_defer_nor_an_invented_deadline():
    effective = bod2604.resolve_effective(_ssvc(90, "Defer"),
                                          _policy("FSU"))
    assert effective["rule"] == "bod_fix_on_upgrade"
    assert effective["deadline_days"] == 90  # the SSVC workflow target
    assert effective["deadline_source"] == "SSVC workflow target"
    assert "remediate_at_next_major_upgrade" in effective["obligations"]


def test_unresolved_applied_policy_is_provisional_and_needs_confirmation():
    effective = bod2604.resolve_effective(
        _ssvc(30), _policy("3DF", status="unresolved",
                           unresolved=["in_kev"]))
    assert effective["rule"] == "bod_unresolved_provisional"
    assert effective["requires_confirmation"] is True
    assert effective["deadline_days"] == 3
    assert "Provisional" in effective["explanation"]


def test_required_and_voluntary_applicability_are_distinguished():
    required = bod2604.evaluate(_finding(applicability="required"))
    voluntary = bod2604.evaluate(_finding(applicability="voluntary"))
    assert required["applied"] and voluntary["applied"]
    assert "binding" in required["applicability_note"]
    assert "not a legal obligation" in voluntary["applicability_note"]


# ---------------------------------------------------------------- inventory
def test_inventory_accepts_policy_fields_and_yaml_booleans():
    finding = _finding()
    apply_context([finding], [{"match": "asset", "publicly_exposed": True,
                               "bod2604_applicability": "voluntary"}])
    assert finding.asset.publicly_exposed == "yes"
    assert finding.asset.bod2604_applicability == "voluntary"
    with pytest.raises(ValueError):
        apply_context([finding], [{"match": "asset",
                                   "bod2604_applicability": "maybe"}])


def test_action_keeps_every_obligation_and_names_the_governing_rule():
    from patchtriage.plan import build_plan

    urgent = _finding(kev_status="listed", in_kev=True, automatable="yes",
                      technical="total", publicly_exposed="yes",
                      applicability="voluntary")
    other = _finding(automatable="no", technical="partial",
                     publicly_exposed="yes", applicability="voluntary")
    other.key, other.vuln_id = "CVE-2024-0002|pkg|asset", "CVE-2024-0002"
    bod2604.apply_policy([urgent, other])
    [action] = build_plan([urgent, other])
    assert action.bod2604["outcome"] == "3DF"
    assert action.bod2604["forensic_triage"] is True
    assert "forensic_triage" in action.obligations
    assert action.effective_deadline_days == 3
    assert action.effective_rule in {"bod_maximum",
                                     "workflow_target_stricter"}
    # The SSVC workflow target is still reported unchanged next to it.
    assert action.deadline_days == min(
        f.triage["ssvc"]["suggested_deadline_days"] for f in (urgent, other))
