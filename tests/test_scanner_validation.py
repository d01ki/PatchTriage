"""Scanner JSON structure is validated the same way for auto and forced formats."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchtriage.assess import combine_coverage
from patchtriage.ingest.parsers import (
    ScannerFormatError,
    load_file,
    load_file_with_metadata,
)

FIX = Path(__file__).parent / "fixtures"
TRIVY_VULN = {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl",
              "InstalledVersion": "1.0"}
GRYPE_MATCH = {"vulnerability": {"id": "CVE-2024-0002"},
               "artifact": {"name": "lodash", "version": "4.0.0"}}
OSV_PACKAGE = {"package": {"name": "requests", "version": "2.0",
                           "ecosystem": "PyPI"},
               "vulnerabilities": [{"id": "CVE-2024-0003"}]}


def _write(tmp_path, data):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _trivy(*vulns):
    return {"SchemaVersion": 2, "ArtifactName": "img",
            "Results": [{"Target": "t", "Vulnerabilities": list(vulns)}]}


def _grype(*matches):
    return {"descriptor": {"name": "grype"}, "matches": list(matches)}


def _osv(*packages):
    return {"results": [{"source": {"path": "a"}, "packages": list(packages)}]}


VALID = [("trivy", _trivy(TRIVY_VULN)), ("grype", _grype(GRYPE_MATCH)),
         ("osv", _osv(OSV_PACKAGE))]
EMPTY = [("trivy", {"SchemaVersion": 2, "ArtifactName": "img"}),
         ("trivy", {"SchemaVersion": 2, "ArtifactName": "i", "Results": []}),
         ("trivy", _trivy()),
         ("grype", _grype()),
         ("osv", {"results": []}),
         ("osv", _osv({"package": {"name": "a"}, "vulnerabilities": []}))]
INVALID = [("trivy", {}), ("trivy", {"SchemaVersion": 2, "Results": "x"}),
           ("trivy", []), ("grype", {}), ("grype", {"matches": {}}),
           ("osv", {}), ("osv", {"results": {}}), ("osv", {"results": ["x"]}),
           ("osv", _osv({"package": 1, "vulnerabilities": []})),
           ("grype", _grype({"vulnerability": 1, "artifact": {}})),
           ("trivy", _trivy({"VulnerabilityID": ""}))]


@pytest.mark.parametrize("forced", [False, True])
@pytest.mark.parametrize(("fmt", "data"), VALID)
def test_valid_documents_are_complete(tmp_path, fmt, data, forced):
    result = load_file_with_metadata(
        _write(tmp_path, data), fmt=fmt if forced else None)
    assert result.coverage["source_type"] == f"scanner:{fmt}"
    assert result.coverage["complete"] is True
    assert len(result.findings) == 1


@pytest.mark.parametrize(("fmt", "data"), EMPTY)
def test_legitimately_empty_results_are_complete(tmp_path, fmt, data):
    result = load_file_with_metadata(_write(tmp_path, data), fmt=fmt)
    assert result.findings == []
    assert result.coverage["complete"] is True


@pytest.mark.parametrize(("fmt", "data"), INVALID)
def test_invalid_documents_are_rejected(tmp_path, fmt, data):
    with pytest.raises(ScannerFormatError):
        load_file_with_metadata(_write(tmp_path, data), fmt=fmt)


@pytest.mark.parametrize("data", [[], "x", 7, {}, {"Results": "x",
                                                   "SchemaVersion": 2}])
def test_auto_detection_rejects_unrecognized_structures(tmp_path, data):
    with pytest.raises(ValueError):
        load_file_with_metadata(_write(tmp_path, data))


@pytest.mark.parametrize("forced", [False, True])
@pytest.mark.parametrize(
    ("fmt", "data"),
    [("trivy", _trivy(TRIVY_VULN, "bad", {"VulnerabilityID": "CVE-1"})),
     ("trivy", _trivy(TRIVY_VULN, {**TRIVY_VULN, "CVSS": "not-an-object"})),
     ("grype", _grype(GRYPE_MATCH, "bad")),
     ("osv", _osv(OSV_PACKAGE, "bad"))])
def test_broken_rows_keep_valid_ones_and_mark_incomplete(
        tmp_path, fmt, data, forced):
    result = load_file_with_metadata(
        _write(tmp_path, data), fmt=fmt if forced else None)
    assert len(result.findings) == 1
    assert result.coverage["complete"] is False
    assert result.coverage["malformed_rows"] >= 1
    assert "malformed" in result.coverage["errors"][0] or (
        "lacks" in result.coverage["errors"][0])


def test_row_error_list_is_bounded_and_does_not_echo_content(tmp_path):
    bad = ["SECRET-CONTENT"] * 50
    result = load_file_with_metadata(
        _write(tmp_path, _grype(GRYPE_MATCH, *bad)), fmt="grype")
    assert len(result.coverage["errors"]) == 21
    assert result.coverage["malformed_rows"] == 50
    assert "SECRET-CONTENT" not in json.dumps(result.coverage)


def test_findings_only_loader_fails_closed_on_partial_scanner(tmp_path):
    with pytest.raises(ScannerFormatError):
        load_file(_write(tmp_path, _grype(GRYPE_MATCH, "bad")), fmt="grype")


@pytest.mark.parametrize("name", ["trivy_sample.json", "grype_sample.json"])
def test_bundled_scanner_fixtures_stay_complete(name):
    result = load_file_with_metadata(FIX / name)
    assert result.coverage["complete"] is True
    assert result.findings


def test_partial_scanner_cannot_be_reported_as_complete(tmp_path):
    loaded = load_file_with_metadata(
        _write(tmp_path, _grype(GRYPE_MATCH, "bad")), fmt="grype")
    combined = combine_coverage({}, loaded.coverage, "")
    assert combined["status"] == "incomplete"
    assert combined["complete"] is False
