"""CLI and GUI must assess evidence through the same core (issue #20)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from patchtriage import assess as assessmod
from patchtriage import cli
from patchtriage import targets as tstore
from patchtriage.ingest.parsers import LoadResult
from patchtriage.models import Asset, Package, RawFinding, Severity
from patchtriage.webapp.runner import run_target

FIX = Path(__file__).parent / "fixtures"


def _offline(monkeypatch):
    calls = []
    monkeypatch.setattr(
        assessmod, "enrich", lambda findings, **kwargs: calls.append(kwargs))
    return calls


def test_cli_and_gui_reach_identical_decisions(monkeypatch, tmp_path):
    calls = _offline(monkeypatch)
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    context = {
        "system_exposure": "controlled",
        "mission_impact": "mef_failure",
        "safety_impact": "critical",
        "bod2604_applicability": "voluntary",
        "publicly_exposed": "yes",
    }

    report = tmp_path / "cli.json"
    result = CliRunner().invoke(cli.app, [
        "run", str(FIX / "trivy_sample.json"), "-o", str(report),
        "--asset-id", "web",
        "--ssvc-exposure", context["system_exposure"],
        "--ssvc-mission-impact", context["mission_impact"],
        "--ssvc-safety-impact", context["safety_impact"],
        "--bod2604", context["bod2604_applicability"],
        "--publicly-exposed", context["publicly_exposed"],
    ])
    assert result.exit_code == 0, result.output
    cli_report = json.loads(report.read_text(encoding="utf-8"))

    target = tstore.add_target("web", **context)
    tstore.save_source(
        target["id"], (FIX / "trivy_sample.json").read_text(encoding="utf-8"),
        "trivy", filename="trivy_sample.json", source_kind="upload",
        provenance={"provider": "upload",
                    "coverage_status": "provider_reported"})
    summary = run_target(tstore.get_target(target["id"]))
    assert len(calls) == 2  # both entry points enriched through the core

    cli_decisions = {
        f["key"]: (f["triage"]["ssvc"]["decision"],
                   f["triage"]["bod2604"]["outcome"],
                   f["triage"]["effective"]["rule"])
        for f in cli_report["findings"]
    }
    assert summary["total"] == len(cli_decisions)
    outcomes = {"immediate": 0, "out_of_cycle": 0, "scheduled": 0, "defer": 0}
    for decision, _, _ in cli_decisions.values():
        outcomes[decision] += 1
    assert summary["outcomes"] == outcomes
    assert [a["action_id"] for a in summary["action_queue"]] == [
        a["action_id"] for a in cli_report["actions"]]
    assert summary["response_policy"] == cli_report["response_policy"]
    assert summary["source"]["coverage_status"] == \
        cli_report["coverage"]["status"]


def test_cli_reports_partial_sbom_coverage_instead_of_aborting(
        monkeypatch, tmp_path):
    _offline(monkeypatch)
    coverage = {
        "source_type": "sbom:osv", "complete": False,
        "total_components": 3, "queryable_components": 1,
        "queried_components": 1, "unqueryable_components": 2,
        "unqueryable_names": ["fastapi", "httpx"],
        "queried_ecosystems": ["PyPI"],
    }
    monkeypatch.setattr(
        assessmod, "load_file_with_metadata",
        lambda path, fmt=None, asset=None, progress=None:
            LoadResult([], dict(coverage)))
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    report = tmp_path / "report.json"

    result = CliRunner().invoke(
        cli.app, ["run", str(sbom), "-o", str(report)])

    assert result.exit_code == 0, result.output
    assert "could not be checked" in result.output
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["coverage"]["complete"] is False
    assert data["coverage"]["unqueryable_names"] == ["fastapi", "httpx"]


def test_file_coverage_merge_never_hides_an_incomplete_file():
    merged = assessmod.merge_file_coverage([
        {"source_type": "scanner:trivy", "complete": True, "records": 4,
         "errors": []},
        {"source_type": "sbom:osv", "complete": False,
         "total_components": 3, "queried_components": 1,
         "unqueryable_components": 2, "unqueryable_names": ["a", "b"],
         "errors": ["timeout"]},
    ])
    assert merged["complete"] is False
    assert merged["total_components"] == 3
    assert merged["unqueryable_names"] == ["a", "b"]
    assert merged["errors"] == ["timeout"]
    assert merged["source_type"] == "scanner:trivy+sbom:osv"
    single = {"source_type": "scanner:grype", "complete": True}
    assert assessmod.merge_file_coverage([single]) == single


def test_cli_progress_output_survives_a_real_sbom_load(monkeypatch, tmp_path):
    """The SBOM loader reports (done, total); the CLI prints messages."""
    import patchtriage.ingest.sbom as sbom

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{}, {}]}

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, *args, **kwargs):
            return Response()

    _offline(monkeypatch)
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(sbom.httpx, "Client", Client)
    report = tmp_path / "report.json"

    result = CliRunner().invoke(
        cli.app, ["run", str(FIX / "sbom_spdx.json"), "-o", str(report)])

    assert result.exit_code == 0, result.output
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["coverage"]["queried_components"] == 2


def _assess_raw(monkeypatch, tmp_path, raw, overrides):
    _offline(monkeypatch)
    monkeypatch.setattr(
        assessmod, "load_file_with_metadata",
        lambda path, fmt=None, asset=None, progress=None: LoadResult(raw, {
            "source_type": "scanner:osv", "complete": True}))
    scan = tmp_path / "scan.json"
    scan.write_text("{}", encoding="utf-8")
    return assessmod.assess([scan], ssvc_overrides=overrides).findings


def _raw(name, ecosystem):
    return RawFinding(
        vuln_id="CVE-2024-1111", source_scanner="test",
        package=Package(name=name, version="1.0.0", ecosystem=ecosystem),
        asset=Asset(identifier="repo"), severity=Severity.HIGH)


OVERRIDE = {"automatable": "yes"}


def test_override_under_legacy_key_migrates_when_unique(monkeypatch, tmp_path):
    findings = _assess_raw(
        monkeypatch, tmp_path, [_raw("python-dateutil", "pypi")],
        {"CVE-2024-1111|pypi||pythondateutil|1.0.0|repo": OVERRIDE})
    assert findings[0].key == "CVE-2024-1111|pypi||python-dateutil|1.0.0|repo"
    assert findings[0].ssvc_inputs == OVERRIDE


def test_ambiguous_legacy_override_is_not_applied(monkeypatch, tmp_path):
    findings = _assess_raw(
        monkeypatch, tmp_path, [_raw("foo-bar", "npm"), _raw("foobar", "npm")],
        {"CVE-2024-1111|npm||foobar|1.0.0|repo": OVERRIDE})
    by_name = {f.package.name: f.ssvc_inputs for f in findings}
    # "foobar" still matches its own unchanged key exactly; "foo-bar" must not
    # inherit an override that could have belonged to either package.
    assert by_name["foobar"] == OVERRIDE
    assert not by_name["foo-bar"]
