"""Deterministic regression tests for the enhanced browser API.

These tests deliberately use a real localhost ``ThreadingHTTPServer`` while
mocking the only repository network boundary.  They cover browser/session
contracts that unit tests of the target store alone cannot exercise.
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from patchtriage.repository import (
    RepositoryProvenance,
    RepositoryReference,
    RepositorySbom,
)
from patchtriage.webapp import server as webserver


FIXTURES = Path(__file__).parent / "fixtures"


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(CookieJar()))


def _api(opener, method: str, url: str, body: dict | None = None,
         headers: dict[str, str] | None = None) -> tuple[int, object]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    request = urllib.request.Request(
        url, data=data, method=method, headers=request_headers)
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            payload: object = json.loads(raw)
        except json.JSONDecodeError:
            payload = raw.decode("utf-8", errors="replace")
        return exc.code, payload


def _report_status(opener, base: str, target_id: str) -> int:
    try:
        with opener.open(f"{base}/report/{target_id}", timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code


def _poll_job(opener, base: str, job_id: str) -> dict:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        status, job = _api(opener, "GET", f"{base}/api/jobs/{job_id}")
        assert status == 200
        assert isinstance(job, dict)
        if job["state"] in {"succeeded", "failed"}:
            return job
        time.sleep(0.01)
    pytest.fail("assessment job did not finish within ten seconds")


@pytest.fixture()
def enhanced_server(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "cfg"))
    for key in (
        "PATCHTRIAGE_AI_PROVIDER",
        "PATCHTRIAGE_AI_API_KEY",
        "PATCHTRIAGE_AI_BASE_URL",
        "PATCHTRIAGE_AI_MODEL",
        "PATCHTRIAGE_AI_SCREEN_MODEL",
        "PATCHTRIAGE_AI_DEEP_MODEL",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("PATCHTRIAGE_COOKIE_SECURE", raising=False)
    with webserver._JOB_LOCK:
        webserver._JOBS.clear()
    with webserver._RUN_LOCKS_GUARD:
        webserver._RUN_LOCKS.clear()

    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webserver.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)
    with webserver._JOB_LOCK:
        webserver._JOBS.clear()


def _create_demo(opener, base: str) -> dict:
    status, target = _api(opener, "POST", base + "/api/demo", {})
    assert status == 201
    assert isinstance(target, dict)
    return target


def _run_demo(opener, base: str, target_id: str) -> dict:
    status, summary = _api(
        opener, "POST", f"{base}/api/targets/{target_id}/run",
        {"backend": "rules"},
    )
    assert status == 200
    assert isinstance(summary, dict)
    return summary


def test_summary_is_rehydrated_by_refresh_api(enhanced_server):
    opener = _opener()
    target = _create_demo(opener, enhanced_server)
    completed = _run_demo(opener, enhanced_server, target["id"])

    # A page refresh retains the anonymous session cookie and reconstructs
    # RESULTS from this endpoint rather than from an in-memory JavaScript Map.
    status, summaries = _api(opener, "GET", enhanced_server + "/api/summaries")
    assert status == 200
    assert isinstance(summaries, list) and len(summaries) == 1
    restored = summaries[0]
    assert restored["target_id"] == target["id"]
    assert restored["total"] == completed["total"]
    assert restored["source_sha256"] == target["source_sha256"]
    assert isinstance(restored["input_revision"], int)
    assert restored["assessed_at"] > 0
    assert _report_status(opener, enhanced_server, target["id"]) == 200


def test_all_input_changes_invalidate_summary_and_report(enhanced_server):
    opener = _opener()
    target = _create_demo(opener, enhanced_server)
    target_id = target["id"]
    _run_demo(opener, enhanced_server, target_id)

    status, _ = _api(
        opener, "POST", f"{enhanced_server}/api/targets/{target_id}/context",
        {"system_exposure": "controlled", "context_sources": ["CMDB"]},
    )
    assert status == 200
    assert _api(opener, "GET", enhanced_server + "/api/summaries") == (200, [])
    assert _report_status(opener, enhanced_server, target_id) == 404

    _run_demo(opener, enhanced_server, target_id)
    replacement = (FIXTURES / "trivy_sample.json").read_text(encoding="utf-8")
    status, _ = _api(
        opener, "POST", f"{enhanced_server}/api/targets/{target_id}/source",
        {"content": replacement, "filename": "replacement-trivy.json"},
    )
    assert status == 200
    assert _api(opener, "GET", enhanced_server + "/api/summaries") == (200, [])
    assert _report_status(opener, enhanced_server, target_id) == 404

    summary = _run_demo(opener, enhanced_server, target_id)
    finding_key = summary["ssvc_inputs"][0]["finding_key"]
    status, saved = _api(
        opener, "POST",
        f"{enhanced_server}/api/targets/{target_id}/ssvc-inputs",
        {"inputs": [{"finding_key": finding_key, "automatable": "no"}]},
    )
    assert status == 200 and saved == {"ok": True, "overrides": 1}
    assert _api(opener, "GET", enhanced_server + "/api/summaries") == (200, [])
    assert _report_status(opener, enhanced_server, target_id) == 404


def test_async_demo_job_can_be_polled_and_persists_result(enhanced_server):
    opener = _opener()
    target = _create_demo(opener, enhanced_server)
    status, job = _api(
        opener, "POST", f"{enhanced_server}/api/targets/{target['id']}/runs",
        {"backend": "rules"},
    )
    assert status == 202
    assert isinstance(job, dict)
    assert job["state"] in {"queued", "running", "succeeded"}
    assert "workspace" not in job

    finished = _poll_job(opener, enhanced_server, job["job_id"])
    assert finished["state"] == "succeeded", finished.get("error")
    assert finished["summary"]["target_id"] == target["id"]
    assert finished["summary"]["total"] == 3
    with webserver._JOB_LOCK:
        assert "summary" not in webserver._JOBS[job["job_id"]]
    status, summaries = _api(opener, "GET", enhanced_server + "/api/summaries")
    assert status == 200
    assert [summary["target_id"] for summary in summaries] == [target["id"]]


def test_jobs_are_isolated_by_anonymous_session(enhanced_server):
    owner = _opener()
    stranger = _opener()
    target = _create_demo(owner, enhanced_server)
    status, job = _api(
        owner, "POST", f"{enhanced_server}/api/targets/{target['id']}/runs",
        {"backend": "rules"},
    )
    assert status == 202

    status, response = _api(
        stranger, "GET", f"{enhanced_server}/api/jobs/{job['job_id']}")
    assert status == 404
    assert response == {"error": "no such job"}
    assert _poll_job(owner, enhanced_server, job["job_id"])["state"] == "succeeded"


def test_uploaded_source_exposes_filename_hash_and_size(enhanced_server):
    opener = _opener()
    status, target = _api(
        opener, "POST", enhanced_server + "/api/targets",
        {"name": "metadata"},
    )
    assert status == 201
    content = (FIXTURES / "trivy_sample.json").read_text(encoding="utf-8")
    expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    expected_size = len(content.encode("utf-8"))
    status, attached = _api(
        opener, "POST", f"{enhanced_server}/api/targets/{target['id']}/source",
        {"content": content, "filename": "scanner-output.json"},
    )
    assert status == 200
    assert attached == {
        "ok": True,
        "format": "trivy",
        "filename": "scanner-output.json",
        "sha256": expected_hash,
        "size": expected_size,
    }

    status, targets = _api(opener, "GET", enhanced_server + "/api/targets")
    assert status == 200
    stored = targets[0]
    assert stored["source_file"] is True
    assert stored["source_name"] == "scanner-output.json"
    assert stored["source_sha256"] == expected_hash
    assert stored["source_size"] == expected_size
    assert stored["source_kind"] == "upload"
    assert stored["source_provenance"]["filename"] == "scanner-output.json"
    assert stored["source_provenance"]["coverage_status"] == "provider_reported"
    assert stored["source_provenance"]["coverage"]["status"] == "provider_reported"


def test_source_size_and_workspace_quota_are_enforced(
        enhanced_server, monkeypatch):
    opener = _opener()
    content = (FIXTURES / "trivy_sample.json").read_text(encoding="utf-8")
    size = len(content.encode("utf-8"))
    status, first = _api(
        opener, "POST", enhanced_server + "/api/targets", {"name": "first"})
    assert status == 201

    monkeypatch.setattr(webserver, "MAX_SOURCE_BYTES", size - 1)
    status, response = _api(
        opener, "POST", f"{enhanced_server}/api/targets/{first['id']}/source",
        {"content": content, "filename": "too-large.json"},
    )
    assert status == 413
    assert "byte limit" in response["error"]

    monkeypatch.setattr(webserver, "MAX_SOURCE_BYTES", size + 1)
    monkeypatch.setattr(webserver, "MAX_SESSION_SOURCE_BYTES", size)
    status, _ = _api(
        opener, "POST", f"{enhanced_server}/api/targets/{first['id']}/source",
        {"content": content, "filename": "first.json"},
    )
    assert status == 200
    status, second = _api(
        opener, "POST", enhanced_server + "/api/targets", {"name": "second"})
    assert status == 201
    status, response = _api(
        opener, "POST", f"{enhanced_server}/api/targets/{second['id']}/source",
        {"content": content, "filename": "second.json"},
    )
    assert status == 413
    assert response == {"error": "anonymous workspace evidence quota exceeded"}


def test_target_quota_is_enforced(enhanced_server, monkeypatch):
    monkeypatch.setattr(webserver, "MAX_TARGETS_PER_SESSION", 1)
    opener = _opener()
    assert _api(
        opener, "POST", enhanced_server + "/api/targets", {"name": "one"})[0] == 201
    status, response = _api(
        opener, "POST", enhanced_server + "/api/targets", {"name": "two"})
    assert status == 429
    assert response == {"error": "target limit reached (1)"}


def test_cookie_secure_flag_uses_forwarded_proto_not_host(enhanced_server):
    def cookie_for(headers: dict[str, str]) -> str:
        request = urllib.request.Request(enhanced_server + "/", headers=headers)
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.headers["Set-Cookie"]

    assert "; Secure" not in cookie_for({"Host": "localhost:8765"})
    assert "; Secure" not in cookie_for({"Host": "192.168.1.50:8765"})
    assert "; Secure" in cookie_for({
        "Host": "patch-triage.example", "X-Forwarded-Proto": "https",
    })


def test_repository_endpoint_saves_source_and_provenance(
        enhanced_server, monkeypatch):
    opener = _opener()
    status, target = _api(
        opener, "POST", enhanced_server + "/api/targets",
        {"name": "repository"},
    )
    assert status == 201
    content = (FIXTURES / "sbom_spdx.json").read_text(encoding="utf-8")
    provenance = RepositoryProvenance(
        provider="github_dependency_graph",
        repository="acme/widgets",
        ref="default_branch",
        resolved_url="https://github.com/acme/widgets",
        api_url="https://api.github.test/repos/acme/widgets/dependency-graph/sbom",
        format="spdx",
        component_count=2,
        coverage_status="provider_reported",
        warnings=("Dependency Graph coverage boundary.",),
        retrieved_at="2026-07-18T00:00:00+00:00",
    )
    captured = {}

    def fake_fetch(reference, **kwargs):
        captured["reference"] = reference
        captured.update(kwargs)
        return RepositorySbom(content=content, provenance=provenance)

    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(webserver, "fetch_repository_sbom", fake_fetch)
    status, imported = _api(
        opener, "POST",
        f"{enhanced_server}/api/targets/{target['id']}/repository",
        {"repository_url": "https://github.com/acme/widgets/tree/release/v1"},
    )
    assert status == 200
    reference = captured.pop("reference")
    assert isinstance(reference, RepositoryReference)
    assert reference.normalized_url == "https://github.com/acme/widgets"
    assert reference.ref == "release/v1"
    assert captured == {
        "github_token": "test-token", "max_bytes": webserver.MAX_SOURCE_BYTES,
    }
    expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert imported["format"] == "spdx"
    assert imported["filename"] == "acme_widgets.spdx.json"
    assert imported["sha256"] == expected_hash
    assert imported["size"] == len(content.encode("utf-8"))
    assert imported["provenance"] == provenance.to_dict()

    status, targets = _api(opener, "GET", enhanced_server + "/api/targets")
    assert status == 200
    stored = targets[0]
    assert stored["source_file"] is True
    assert stored["source_kind"] == "repository"
    assert stored["source_format"] == "spdx"
    assert stored["source_name"] == "acme_widgets.spdx.json"
    assert stored["source_sha256"] == expected_hash
    assert stored["source_provenance"] == provenance.to_dict()


def test_public_deployment_never_passes_service_token_to_repository_import(
        monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_DEPLOYMENT_MODE", "public")
    monkeypatch.setenv("GITHUB_TOKEN", "service-account-secret")
    assert webserver._github_import_token() is None

    monkeypatch.setenv("PATCHTRIAGE_DEPLOYMENT_MODE", "local")
    assert webserver._github_import_token() == "service-account-secret"


def test_public_deployment_disables_legacy_synchronous_run(
        enhanced_server, monkeypatch):
    opener = _opener()
    target = _create_demo(opener, enhanced_server)
    monkeypatch.setenv("PATCHTRIAGE_DEPLOYMENT_MODE", "public")
    status, response = _api(
        opener, "POST",
        f"{enhanced_server}/api/targets/{target['id']}/run",
        {"backend": "rules"},
    )
    assert status == 410
    assert "use /runs" in response["error"]


def test_job_pruning_never_removes_active_workers(monkeypatch):
    old = time.time() - webserver.SESSION_TTL_SECONDS - 60
    monkeypatch.setattr(webserver, "MAX_RETAINED_JOBS", 10)
    with webserver._JOB_LOCK:
        webserver._JOBS.clear()
        webserver._JOBS.update({
            "a" * 24: {
                "job_id": "a" * 24, "workspace": "w",
                "target_id": "1" * 12, "backend": "rules",
                "state": "running", "created_at": old,
            },
            "b" * 24: {
                "job_id": "b" * 24, "workspace": "w",
                "target_id": "2" * 12, "backend": "rules",
                "state": "succeeded", "created_at": old,
                "finished_at": old,
            },
        })
        webserver._prune_jobs_locked()
        assert "a" * 24 in webserver._JOBS
        assert "b" * 24 not in webserver._JOBS
        webserver._JOBS.clear()


def test_ui_exposes_repository_context_privacy_and_async_contract(
        enhanced_server):
    with urllib.request.urlopen(enhanced_server + "/", timeout=15) as response:
        page = response.read().decode("utf-8")
    assert 'id="repodialog"' in page
    assert "Import a repository" in page
    assert "repository code and package managers are never executed" in page
    assert "Advanced context evidence" in page
    assert 'id="privacy-note"' in page
    assert "Do not upload confidential scanner output" in page
    assert page.index('id="privacy-note"') < page.index('id="targetform"')
    assert 'api("GET","/api/summaries")' in page
    assert "/api/targets/${id}/runs" in page
    assert "/api/jobs/${jobId}" in page
