"""Offline, reviewer-runnable conformance and reproducibility verification."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from contextlib import ExitStack
from datetime import datetime, timezone
from importlib import resources
from typing import Any

from .context import apply_context, load_inventory
from .dedup import dedup
from .enrich.clients import enrich_from_snapshot
from .ingest.parsers import load_file
from .models import Asset, Enrichment, Finding, Package
from .ssvc import (
    Automatable,
    Exploitation,
    HumanImpact,
    MissionImpact,
    SafetyImpact,
    SystemExposure,
    assess,
    deployer_decision,
    derive_human_impact,
)
from .triage.audit import audit_all, audit_finding
from .triage.engine import RulesBackend, run_triage
from .webapp.runner import asset_from_target


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _resource_bytes(relative: str) -> bytes:
    item = resources.files("patchtriage")
    for part in relative.split("/"):
        item = item / part
    return item.read_bytes()


def _validation_spec() -> dict:
    return json.loads(_resource_bytes("data/ssvc_validation.json"))


def _check(name: str, cases: int, failures: list[dict],
           observations: Any = None) -> dict:
    result = {
        "name": name,
        "passed": not failures,
        "cases": cases,
        "passed_cases": max(0, cases - len(failures)),
        "failures": failures,
    }
    if observations is not None:
        result["observations"] = observations
    return result


def _official_deployer_check(spec: dict) -> tuple[dict, list[dict]]:
    failures: list[dict] = []
    observations: list[dict] = []
    codes = spec["deployer"]["outcome_codes"]
    human_order = spec["deployer"]["human_impact_order"]
    for row in spec["deployer"]["rows"]:
        for index, human in enumerate(human_order):
            expected = codes[row["expected"][index]]
            actual = deployer_decision(
                Exploitation(row["exploitation"]),
                SystemExposure(row["system_exposure"]),
                Automatable(row["automatable"]),
                HumanImpact(human),
            ).value
            case = {
                "exploitation": row["exploitation"],
                "system_exposure": row["system_exposure"],
                "automatable": row["automatable"],
                "human_impact": human,
                "expected": expected,
                "actual": actual,
            }
            observations.append(case)
            if actual != expected:
                failures.append(case)
    return _check(
        "official_ssvc_deployer_table",
        len(observations), failures,
        {"source": spec["sources"]["deployer"]},
    ), observations


def _official_human_impact_check(spec: dict) -> tuple[dict, list[dict]]:
    failures: list[dict] = []
    observations: list[dict] = []
    mission_order = spec["human_impact"]["mission_order"]
    for row in spec["human_impact"]["rows"]:
        for index, mission in enumerate(mission_order):
            expected = row["expected"][index]
            actual = derive_human_impact(
                MissionImpact(mission), SafetyImpact(row["safety_impact"]),
            ).value
            case = {
                "mission_impact": mission,
                "safety_impact": row["safety_impact"],
                "expected": expected,
                "actual": actual,
            }
            observations.append(case)
            if actual != expected:
                failures.append(case)
    return _check(
        "official_ssvc_human_impact_table",
        len(observations), failures,
        {"source": spec["sources"]["human_impact"]},
    ), observations


def _target_sensitivity_check(spec: dict) -> tuple[dict, list[dict], list[Finding]]:
    failures: list[dict] = []
    observations: list[dict] = []
    findings: list[Finding] = []
    expected_fields = (
        "system_exposure", "mission_impact", "safety_impact",
    )
    data = resources.files("patchtriage") / "data"
    snapshots = {
        name: json.loads((data / f"demo_{name}.json").read_text(encoding="utf-8"))
        for name in ("epss", "kev", "nvd")
    }
    with resources.as_file(data / "fixtures" / "trivy_sample.json") as fixture_path:
        for scenario in spec["target_sensitivity"]:
            target = {
                "name": scenario["name"],
                "source_format": "trivy",
                "context_sources": ["reviewer-fixture"],
                **scenario["context"],
            }
            asset = asset_from_target(target)
            parsed = dedup(load_file(fixture_path, asset=asset))
            enrich_from_snapshot(parsed, **snapshots)
            finding = next(
                item for item in parsed if item.vuln_id == "CVE-2023-4911"
            )
            run_triage([finding], RulesBackend())
            ssvc = (finding.triage or {})["ssvc"]
            mapped = {field: getattr(finding.asset, field) for field in expected_fields}
            case = {
                "name": scenario["name"],
                "same_vulnerability": finding.vuln_id,
                "same_package": finding.package.name,
                "same_threat_evidence": "frozen CISA KEV / Active",
                "pipeline": "Trivy -> target mapping -> snapshot enrichment -> SSVC",
                "target_context_entered": scenario["context"],
                "target_context_consumed": mapped,
                "vulnerability_automatable": {
                    "value": ssvc["automatable"]["value"],
                    "source": ssvc["automatable"]["source"],
                },
                "expected_decision": scenario["expected_decision"],
                "actual_decision": ssvc["decision"],
                "decision_path": ssvc["decision_path"],
            }
            observations.append(case)
            findings.append(finding)
            if (mapped != scenario["context"]
                    or ssvc["decision"] != scenario["expected_decision"]):
                failures.append(case)
    expected_outcomes = {
        scenario["expected_decision"] for scenario in spec["target_sensitivity"]
    }
    actual_outcomes = {case["actual_decision"] for case in observations}
    if actual_outcomes != expected_outcomes:
        failures.append({
            "reason": "target context did not produce the expected outcome spread",
            "expected": sorted(expected_outcomes),
            "actual": sorted(actual_outcomes),
        })
    return _check(
        "target_context_mapping_sensitivity",
        len(observations), failures, observations,
    ), observations, findings


def _unknown_context_check(spec: dict) -> tuple[dict, dict]:
    finding = Finding(
        key="unknown-context",
        vuln_id="CVE-2099-0002",
        package=Package(name="unknown-context-component", version="1.0.0"),
        asset=Asset(identifier="unknown-target"),
        enrichment=Enrichment(sources=["frozen-validation-snapshot"]),
    )
    assessment = assess(finding)
    actual = {
        "system_exposure": assessment.system_exposure.value,
        "automatable": assessment.automatable.value,
        "mission_impact": assessment.mission_impact.value,
        "safety_impact": assessment.safety_impact.value,
        "decision": assessment.decision.value,
    }
    expected = spec["unknown_context"]["expected"]
    expected_confirmation = sorted(spec["unknown_context"]["needs_confirmation"])
    actual_confirmation = sorted(assessment.needs_confirmation)
    failures = []
    if actual != expected or actual_confirmation != expected_confirmation:
        failures.append({
            "expected": expected,
            "actual": actual,
            "expected_confirmation": expected_confirmation,
            "actual_confirmation": actual_confirmation,
        })
    observation = {
        "expected": expected,
        "actual": actual,
        "needs_confirmation": actual_confirmation,
    }
    return _check("unknown_context_is_explicit", 1, failures, observation), observation


def _assessment_projection(finding: Finding) -> dict:
    assessment = assess(finding)
    return {
        "model": assessment.model,
        "decision": assessment.decision.value,
        "decision_path": assessment.decision_path,
        "deadline_days": assessment.suggested_deadline_days,
        "recommended_action": assessment.recommended_action,
        "confidence": assessment.confidence.value,
        "needs_confirmation": assessment.needs_confirmation,
        "points": {
            key: getattr(assessment, key).model_dump(mode="json")
            for key in (
                "exploitation", "system_exposure", "automatable",
                "mission_impact", "safety_impact", "human_impact",
            )
        },
    }


def _repeatability_check(findings: list[Finding], repeats: int) -> tuple[dict, dict]:
    observations: dict[str, dict] = {}
    failures: list[dict] = []
    for finding in findings:
        hashes = [
            _sha256(_canonical(_assessment_projection(finding)))
            for _ in range(repeats)
        ]
        unique = sorted(set(hashes))
        observations[finding.asset.identifier] = {
            "runs": repeats,
            "unique_decision_hashes": unique,
        }
        if len(unique) != 1:
            failures.append({
                "target": finding.asset.identifier,
                "unique_decision_hashes": unique,
            })
    return _check(
        "repeatability",
        len(findings) * repeats,
        failures,
        observations,
    ), observations


def _demo_run() -> tuple[dict[str, str], dict]:
    data = resources.files("patchtriage") / "data"
    with ExitStack() as stack:
        fixture_paths = [
            stack.enter_context(resources.as_file(data / "fixtures" / name))
            for name in ("trivy_sample.json", "grype_sample.json")
        ]
        assets_path = stack.enter_context(resources.as_file(data / "demo_assets.yaml"))
        raw = [item for path in fixture_paths for item in load_file(path)]
        findings = dedup(raw)
        apply_context(findings, load_inventory(assets_path))
    snapshots = {
        name: json.loads((data / f"demo_{name}.json").read_text(encoding="utf-8"))
        for name in ("epss", "kev", "nvd")
    }
    enrich_from_snapshot(findings, **snapshots)
    run_triage(findings, RulesBackend())
    audit = audit_all(findings)
    outcomes = {
        finding.vuln_id: (finding.triage or {}).get("ssvc", {}).get("decision")
        for finding in sorted(findings, key=lambda value: value.vuln_id)
    }
    projection = {
        finding.vuln_id: {
            "package": finding.package.name,
            "asset_context": {
                "system_exposure": finding.asset.system_exposure,
                "mission_impact": finding.asset.mission_impact,
                "safety_impact": finding.asset.safety_impact,
            },
            "ssvc": _assessment_projection(finding),
        }
        for finding in sorted(findings, key=lambda value: value.vuln_id)
    }
    return outcomes, {
        "projection_hash": _sha256(_canonical(projection)),
        "audit_verified": audit["verified"],
        "audit_total": audit["total"],
        "audit_flagged": audit["flagged"],
    }


def _demo_check(spec: dict) -> tuple[dict, dict]:
    outcomes_one, run_one = _demo_run()
    outcomes_two, run_two = _demo_run()
    failures: list[dict] = []
    expected = spec["demo_expected"]
    if outcomes_one != expected:
        failures.append({"reason": "unexpected outcomes", "expected": expected,
                         "actual": outcomes_one})
    if outcomes_one != outcomes_two or run_one["projection_hash"] != run_two["projection_hash"]:
        failures.append({"reason": "two frozen end-to-end runs differed",
                         "first": run_one["projection_hash"],
                         "second": run_two["projection_hash"]})
    if run_one["audit_verified"] != run_one["audit_total"] or run_one["audit_flagged"]:
        failures.append({"reason": "end-to-end audit failed", "audit": run_one})
    observation = {
        "expected_outcomes": expected,
        "actual_outcomes": outcomes_one,
        "first_projection_hash": run_one["projection_hash"],
        "second_projection_hash": run_two["projection_hash"],
        "audit": {
            "verified": run_one["audit_verified"],
            "total": run_one["audit_total"],
        },
    }
    return _check("frozen_end_to_end_pipeline", 3, failures, observation), observation


def _tamper_check(finding: Finding) -> tuple[dict, dict]:
    tampered = finding.model_copy(deep=True)
    tampered.triage = RulesBackend().triage(tampered)
    tampered.triage["priority"] = "P4"
    tampered.triage["action"] = "monitor"
    tampered.triage["suggested_deadline_days"] = 999
    tampered.triage["ssvc"]["decision_path"] = "tampered"
    audit = audit_finding(tampered, RulesBackend())
    expected_prefixes = (
        "ssvc_priority_mismatch", "ssvc_action_mismatch",
        "ssvc_deadline_mismatch", "ssvc_path_mismatch",
    )
    detected = {
        prefix: any(flag.startswith(prefix) for flag in audit["flags"])
        for prefix in expected_prefixes
    }
    failures = [] if all(detected.values()) and not audit["verified"] else [{
        "expected_detections": list(expected_prefixes),
        "actual_flags": audit["flags"],
    }]
    observation = {"detected": detected, "audit_flags": audit["flags"]}
    return _check("decision_tamper_detection", 4, failures, observation), observation


def _manifest() -> dict[str, str]:
    paths = (
        "data/ssvc_validation.json",
        "data/demo_assets.yaml",
        "data/demo_epss.json",
        "data/demo_kev.json",
        "data/demo_nvd.json",
        "data/fixtures/trivy_sample.json",
        "data/fixtures/grype_sample.json",
        "validation.py",
        "ssvc.py",
        "models.py",
        "context.py",
        "dedup.py",
        "enrich/clients.py",
        "ingest/parsers.py",
        "triage/engine.py",
        "triage/audit.py",
        "webapp/runner.py",
    )
    return {path: _sha256(_resource_bytes(path)) for path in paths}


def run_validation(repeats: int = 25) -> dict:
    """Run all offline verification layers and return a JSON-safe report."""
    if repeats < 2:
        raise ValueError("repeats must be at least 2")
    spec = _validation_spec()
    checks: list[dict] = []
    fingerprint_material: dict[str, Any] = {}

    check, official_deployer = _official_deployer_check(spec)
    checks.append(check)
    fingerprint_material[check["name"]] = official_deployer

    check, official_human = _official_human_impact_check(spec)
    checks.append(check)
    fingerprint_material[check["name"]] = official_human

    check, target_results, target_findings = _target_sensitivity_check(spec)
    checks.append(check)
    fingerprint_material[check["name"]] = target_results

    check, unknown_result = _unknown_context_check(spec)
    checks.append(check)
    fingerprint_material[check["name"]] = unknown_result

    check, repeat_results = _repeatability_check(target_findings, repeats)
    checks.append(check)
    fingerprint_material[check["name"]] = {
        target: result["unique_decision_hashes"]
        for target, result in repeat_results.items()
    }

    check, demo_result = _demo_check(spec)
    checks.append(check)
    fingerprint_material[check["name"]] = demo_result

    check, tamper_result = _tamper_check(target_findings[0])
    checks.append(check)
    fingerprint_material[check["name"]] = tamper_result

    manifest = _manifest()
    report = {
        "schema": spec["schema"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "pass" if all(check["passed"] for check in checks) else "fail",
        "offline": True,
        "repeats": repeats,
        "environment": {
            "python": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "official_sources": spec["sources"],
        "input_manifest_sha256": manifest,
        "input_fingerprint": _sha256(_canonical(manifest)),
        "decision_fingerprint": _sha256(_canonical(fingerprint_material)),
        "checks": checks,
        "claim_scope": (
            "Conformance to the bundled official SSVC expectations, faithful GUI "
            "target-context mapping, deterministic repeatability for frozen inputs, "
            "frozen end-to-end behavior, and detection of altered decisions."
        ),
        "claim_limit": (
            "This does not by itself prove real-world remediation effectiveness; "
            "that requires an independently labeled prospective evaluation."
        ),
    }
    return report


def validation_report_text(report: dict) -> str:
    """The JSON evidence file written by ``patchtriage verify``."""
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"
