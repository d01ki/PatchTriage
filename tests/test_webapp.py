"""End-to-end GUI API test against a live localhost server (no browser).

Exercises the full flow: add target -> attach SBOM -> run -> fetch report.
The SBOM run hits OSV.dev, so this test needs network; skip it offline.
"""

import json
import socket
import threading
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from patchtriage.webapp.runner import _combine_coverage
from patchtriage.webapp.server import Handler

FIX = Path(__file__).parent / "fixtures"
_OPENERS = {}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    _OPENERS.pop(base, None)
    yield base
    _OPENERS.pop(base, None)
    httpd.shutdown()
    httpd.server_close()


def _new_opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(CookieJar()))


def _request(opener, method, url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=request_headers)
    try:
        with opener.open(req, timeout=60) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _req(method, url, body=None, headers=None):
    parsed = urlsplit(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    opener = _OPENERS.setdefault(base, _new_opener())
    return _request(opener, method, url, body, headers)


def test_config_lists_rules_backend(server):
    status, cfg = _req("GET", server + "/api/config")
    assert status == 200
    assert cfg["backends"] == ["rules"]
    assert cfg["has_key"] is False
    assert "offline-demo" in cfg["capabilities"]
    assert "ssvc-deployer" in cfg["capabilities"]
    assert "kev-baseline" in cfg["capabilities"]
    assert "vendor-advisories" in cfg["capabilities"]
    assert cfg["data_isolation"] == "anonymous-session"
    assert cfg["retention_hours"] == 6
    assert cfg["connectors"] == {
        "msrc": "public", "rhsa": "public", "usn": "public",
        "debian": "public", "ghsa": "public-rate-limit",
    }


def test_provider_coverage_boundary_cannot_be_overwritten_by_parser_success():
    coverage = _combine_coverage(
        {"status": "no_package_inventory", "complete": False},
        {"source_type": "scanner:osv", "complete": True, "records": 0},
        "no_package_inventory",
    )
    assert coverage["status"] == "no_package_inventory"
    assert coverage["complete"] is False


def test_add_and_delete_target(server):
    status, t = _req("POST", server + "/api/targets",
                     {"name": "checkout", "url": "https://example.com",
                      "criticality": "critical", "internet_exposed": True,
                      "system_exposure": "open",
                      "mission_impact": "mef_failure",
                      "safety_impact": "marginal",
                      "reachable": True, "runtime_observed": True,
                      "context_sources": ["otel"]})
    assert status == 201
    assert t["name"] == "checkout" and t["url"] == "https://example.com"
    assert t["reachable"] is True and t["runtime_observed"] is True
    assert t["system_exposure"] == "open"
    assert t["automatable"] == "unknown"
    assert t["mission_impact"] == "mef_failure"
    assert t["safety_impact"] == "marginal"
    assert t["context_sources"] == ["otel"]
    _, targets = _req("GET", server + "/api/targets")
    assert len(targets) == 1
    status, _ = _req("DELETE", server + f"/api/targets/{t['id']}")
    assert status == 204
    _, targets = _req("GET", server + "/api/targets")
    assert targets == []


def test_anonymous_browser_sessions_are_isolated(server):
    first = _new_opener()
    second = _new_opener()
    status, target = _request(
        first, "POST", server + "/api/targets", {"name": "private-target"})
    assert status == 201
    _, first_targets = _request(first, "GET", server + "/api/targets")
    _, second_targets = _request(second, "GET", server + "/api/targets")
    assert [item["id"] for item in first_targets] == [target["id"]]
    assert second_targets == []


def test_rejects_unsafe_target_url(server):
    status, response = _req(
        "POST", server + "/api/targets",
        {"name": "unsafe", "url": "javascript:alert(1)"},
    )
    assert status == 400
    assert "http:// or https://" in response["error"]

    status, response = _req(
        "POST", server + "/api/targets",
        {"name": "secret", "url": "https://user:token@example.com/runbook"},
    )
    assert status == 400
    assert "embedded credentials" in response["error"]


def test_rejects_cross_origin_mutation(server):
    status, response = _req(
        "POST", server + "/api/targets", {"name": "cross-site"},
        headers={"Origin": "https://attacker.example"},
    )
    assert status == 403
    assert "cross-origin" in response["error"]


def test_security_headers_are_present(server):
    with urllib.request.urlopen(server + "/") as response:
        page = response.read().decode("utf-8")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert "HttpOnly" in response.headers["Set-Cookie"]
        assert "SameSite=Strict" in response.headers["Set-Cookie"]
    assert "Run the offline demo" in page
    assert "Patch what matters" in page
    assert "Severity informs. Your environment decides." in page
    assert "Immediate decisions" in page
    assert "Upload evidence" in page
    assert "Import repository" in page
    assert "CycloneDX/SPDX JSON" in page
    assert "Categorical outcome — no aggregate SSVC score" in page
    assert "Automatable are evaluated" in page
    assert 'id="f-automatable"' not in page
    assert "Advanced context evidence" in page
    assert "Context evidence sources" in page
    assert "Review vulnerability-specific SSVC inputs" in page
    assert "Black Hat" not in page
    assert "Arsenal" not in page
    assert "LOCAL DECISION ENGINE" not in page
    assert "v0.6.0" not in page
    assert all(code not in page for code in ("P1", "P2", "P3", "P4"))


def test_updates_and_validates_ssvc_context(server):
    _, target = _req("POST", server + "/api/targets", {"name": "context"})
    status, updated = _req(
        "POST", server + f"/api/targets/{target['id']}/context",
        {"system_exposure": "controlled",
         "mission_impact": "mef_support_crippled",
         "safety_impact": "critical", "context_sources": ["CMDB"]},
    )
    assert status == 200
    assert updated["system_exposure"] == "controlled"
    assert updated["automatable"] == "unknown"
    assert updated["mission_impact"] == "mef_support_crippled"
    assert updated["safety_impact"] == "critical"
    assert updated["context_sources"] == ["CMDB"]

    status, response = _req(
        "POST", server + f"/api/targets/{target['id']}/context",
        {"system_exposure": "internet-ish"},
    )
    assert status == 400
    assert "system_exposure" in response["error"]


def test_reject_non_scan_non_sbom(server):
    _, t = _req("POST", server + "/api/targets", {"name": "x"})
    status, resp = _req("POST", server + f"/api/targets/{t['id']}/source",
                        {"content": '{"hello": "world"}', "filename": "x.json"})
    assert status == 400
    assert "unrecognized" in resp["error"]


def test_source_requires_existing_target(server):
    status, response = _req(
        "POST", server + "/api/targets/000000000000/source",
        {"content": '{"hello": "world"}', "filename": "x.json"},
    )
    assert status == 404
    assert response["error"] == "no such target"


def test_source_detects_sbom_format(server):
    _, t = _req("POST", server + "/api/targets", {"name": "x"})
    content = (FIX / "sbom_spdx.json").read_text(encoding="utf-8")
    status, resp = _req("POST", server + f"/api/targets/{t['id']}/source",
                        {"content": content, "filename": "sbom_spdx.json"})
    assert status == 200
    assert resp["format"] == "spdx"


def test_empty_scan_is_reported_as_no_vulnerabilities(server):
    _, target = _req("POST", server + "/api/targets", {"name": "empty-scan"})
    content = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "empty:latest",
        "ArtifactType": "container_image",
        "Results": [],
    })
    status, _ = _req(
        "POST", server + f"/api/targets/{target['id']}/source",
        {"content": content, "filename": "empty-trivy.json"},
    )
    assert status == 200
    status, summary = _req(
        "POST", server + f"/api/targets/{target['id']}/run",
        {"backend": "rules"},
    )
    assert status == 200
    assert summary["total"] == 0
    assert summary["actions"] == 0
    assert summary["result_state"] == "coverage_incomplete"
    assert "provider-reported" in summary["result_message"]
    assert summary["source"]["coverage_status"] == "provider_reported"
    assert summary["top_ssvc_decision"] == ""
    assert summary["comparison"] is None


def test_offline_demo_runs_end_to_end(server):
    status, target = _req("POST", server + "/api/demo", {})
    assert status == 201
    assert target["demo"] is True
    status, summary = _req(
        "POST", server + f"/api/targets/{target['id']}/run",
        {"backend": "rules"},
    )
    assert status == 200
    assert summary["total"] == 3
    assert summary["kev"] == 1
    assert summary["vendor_advisories"] == 0
    assert summary["vendor_sources"] == []
    assert summary["comparison"]["kev"] == {
        "cvss": 0, "epss": 1, "kev": 1, "ssvc": 1,
        "patchtriage": 1,
    }
    assert summary["comparison"]["outcome"] == {
        "reviewed": 1,
        "review_reduction_pct": 66.7,
        "kev_coverage_pct": 100.0,
        "kev_gain_points": 100.0,
        "additional_kev_vs_cvss": 1,
        "kev_lift_vs_cvss": None,
        "urgent_coverage_pct": 100.0,
    }
    assert summary["comparison"]["urgent"] == {
        "total": 1, "cvss": 0, "epss": 1, "kev": 1, "ssvc": 1,
    }
    # CVE-2023-4911 is KEV-listed, but CISA publishes Automatable = No for it
    # (local privilege escalation is not automatable at scale). The demo
    # therefore lands on Out-of-Cycle rather than the Immediate produced by
    # the old conservative "assume Yes" default: an authoritative input
    # correcting an over-prioritization is the point of the Vulnrichment feed.
    assert summary["outcomes"] == {
        "immediate": 0, "out_of_cycle": 1, "scheduled": 2, "defer": 0,
    }
    assert summary["top_ssvc_decision"] == "Out-of-Cycle"
    assert summary["ssvc_confirmation_fields"] == ["automatable"]
    assert summary["top_deadline_days"] == 14
    assert summary["explanation"]["outcome_label"] == "Out-of-Cycle"
    assert summary["explanation"]["basis"].startswith(
        "The SSVC Deployer path"
    )
    assert summary["evaluated_context"] == {
        "system_exposure": "open",
        "mission_impact": "mef_failure", "safety_impact": "critical",
        "context_sources": ["OpenTelemetry", "Falco"],
    }
    assert summary["explanation"]["ssvc"]["decision"] == "out_of_cycle"
    assert (summary["explanation"]["ssvc"]["automatable"]["source"]
            == "CISA Vulnrichment")
    assert summary["explanation"]["checks"][0]["status"] == "confirmed"
    assert summary["explanation"]["ssvc"]["supplemental"]["runtime_observed"] is True
    assert len(summary["ssvc_inputs"]) == 3
    assert all("exploitation" in item and "automatable" in item
               for item in summary["ssvc_inputs"])
    assert summary["duration_ms"] >= 0
    status, same_target = _req("POST", server + "/api/demo", {})
    assert status == 200
    assert same_target["id"] == target["id"]
    _, targets = _req("GET", server + "/api/targets")
    assert len(targets) == 1


def test_analyst_can_confirm_per_vulnerability_ssvc_inputs(server):
    _, target = _req("POST", server + "/api/demo", {})
    _, first = _req(
        "POST", server + f"/api/targets/{target['id']}/run",
        {"backend": "rules"},
    )
    finding = next(
        item for item in first["ssvc_inputs"]
        if item["exploitation"]["value"] != "active"
    )
    status, saved = _req(
        "POST", server + f"/api/targets/{target['id']}/ssvc-inputs",
        {"inputs": [{
            "finding_key": finding["finding_key"],
            "exploitation": "none",
            "automatable": "no",
        }]},
    )
    assert status == 200
    assert saved["overrides"] == 1
    _, rerun = _req(
        "POST", server + f"/api/targets/{target['id']}/run",
        {"backend": "rules"},
    )
    updated = next(
        item for item in rerun["ssvc_inputs"]
        if item["finding_key"] == finding["finding_key"]
    )
    assert updated["exploitation"]["value"] == "none"
    assert updated["automatable"]["value"] == "no"
    assert updated["exploitation"]["source"] == "analyst-confirmed SSVC input"
    assert updated["automatable"]["source"] == "analyst-confirmed SSVC input"


@pytest.mark.network
def test_full_run_over_sbom(server):
    """add -> attach SPDX -> run (OSV) -> report. Needs network."""
    _, t = _req("POST", server + "/api/targets",
                {"name": "demo", "url": "https://example.com",
                 "criticality": "high", "internet_exposed": True})
    content = (FIX / "sbom_spdx.json").read_text(encoding="utf-8")
    st, _ = _req("POST", server + f"/api/targets/{t['id']}/source",
                 {"content": content, "filename": "sbom_spdx.json"})
    assert st == 200
    try:
        st, summary = _req("POST", server + f"/api/targets/{t['id']}/run",
                           {"backend": "rules"})
    except urllib.error.URLError:
        pytest.skip("no network for OSV.dev")
    if st != 200:
        pytest.skip(f"OSV unreachable: {summary}")
    if summary["result_state"] == "coverage_incomplete":
        pytest.skip(
            "OSV lookup incomplete: "
            + " | ".join(
                ((summary.get("source") or {}).get("provenance") or {})
                .get("coverage", {}).get("errors", [])))
    assert summary["total"] > 0
    assert summary["report_url"] == f"/report/{t['id']}"
    # report is now fetchable
    # Reports belong to the same anonymous browser session as the API calls.
    # Reuse its cookie-aware opener instead of starting a new session.
    with _OPENERS[server].open(server + f"/report/{t['id']}") as r:
        html = r.read().decode()
    assert "<!doctype html>" in html
    assert "1E3A31" not in html  # no green in the redesigned palette
