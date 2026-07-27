"""Backend-level tests: cascade escalation routing and graceful fallback.

These use injected fake backends — no API key, no network.
"""

from pathlib import Path
from datetime import datetime, timezone

from patchtriage.dedup import dedup
from patchtriage.ingest.parsers import load_file
from patchtriage.models import Enrichment
from patchtriage.triage.engine import (
    AIBackend,
    CascadeBackend,
    RulesBackend,
    TRIAGE_SYSTEM_PROMPT,
    TRIAGE_TOOL,
    run_triage,
)
from patchtriage.triage.providers import OpenAICompatibleProvider

FIX = Path(__file__).parent / "fixtures"


class FakeBackend:
    def __init__(self, result: dict, fail: bool = False):
        self.result = result
        self.fail = fail
        self.calls = 0

    def triage(self, f):
        self.calls += 1
        if self.fail:
            raise RuntimeError("simulated API failure")
        return dict(self.result)


class FakeProvider:
    name = "test-provider"

    def __init__(self, result: dict):
        self.result = result
        self.calls = []

    def complete(self, **kwargs):
        self.calls.append(kwargs)
        return dict(self.result)


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeHTTPClient:
    def __init__(self, response: dict):
        self.response = response
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse(self.response)


def _findings():
    raw = load_file(FIX / "trivy_sample.json") + load_file(FIX / "grype_sample.json")
    return dedup(raw)


def _kev_finding():
    f = next(x for x in _findings() if "libc" in x.package.name)
    f.asset.internet_exposed = True
    f.asset.criticality = "critical"
    f.asset.system_exposure = "open"
    f.asset.automatable = "yes"
    f.asset.mission_impact = "mef_failure"
    f.asset.safety_impact = "critical"
    f.enrichment = Enrichment(in_cisa_kev=True, kev_ransomware=True,
                              epss_score=0.856, nvd_cvss_score=7.8)
    return f


def _quiet_finding():
    f = next(x for x in _findings() if x.package.name == "lodash")
    f.asset.internet_exposed = False
    f.asset.criticality = "low"
    f.asset.system_exposure = "small"
    f.asset.automatable = "no"
    f.asset.mission_impact = "degraded"
    f.asset.safety_impact = "negligible"
    f.enrichment = Enrichment(
        epss_score=0.018, nvd_cvss_score=7.2,
        enriched_at=datetime.now(timezone.utc),
    )
    return f


def test_cascade_escalates_kev_to_deep_model():
    finding = _kev_finding()
    baseline = RulesBackend().triage(finding)
    screen = FakeBackend(baseline)
    deep_result = {**baseline, "rationale": "actively exploited"}
    deep = FakeBackend(deep_result)
    cascade = CascadeBackend(screen=screen, deep=deep)
    out = cascade.triage(finding)
    assert deep.calls == 1
    assert out["escalated"] is True
    assert "ssvc_immediate" in out["escalation_reasons"]
    assert out["rationale"] == "actively exploited"


def test_cascade_keeps_clean_low_signal_finding_on_screen_tier():
    # Matches the deterministic SSVC result and passes
    # every audit check -> no reason to spend frontier tokens.
    finding = _quiet_finding()
    baseline = RulesBackend().triage(finding)
    screen = FakeBackend(baseline)
    deep = FakeBackend({**baseline, "rationale": "should not be called"})
    cascade = CascadeBackend(screen=screen, deep=deep)
    out = cascade.triage(finding)
    assert deep.calls == 0
    assert out["escalated"] is False


def test_cascade_escalates_on_audit_flag():
    finding = _quiet_finding()
    baseline = RulesBackend().triage(finding)
    screen = FakeBackend({**baseline, "rationale": "EPSS of 0.99 is unlikely"})
    deep = FakeBackend({**baseline, "rationale": "corrected"})
    cascade = CascadeBackend(screen=screen, deep=deep)
    out = cascade.triage(finding)
    assert deep.calls == 1
    assert any(r.startswith("audit_flags:") for r in out["escalation_reasons"])


def test_run_triage_falls_back_to_rules_on_api_error():
    findings = _findings()
    failing = FakeBackend({}, fail=True)
    run_triage(findings, failing, jobs=1)
    assert all(f.triage["backend"] == "rules_fallback" for f in findings)
    assert all("simulated API failure" in f.triage["error"] for f in findings)
    # fallback decisions are still real rules decisions
    assert all(f.triage["priority"] in ("P1", "P2", "P3", "P4") for f in findings)


def test_run_triage_parallel_preserves_order():
    findings = _findings()
    ok = FakeBackend({"priority": "P2", "action": "patch_scheduled",
                      "rationale": "x", "suggested_deadline_days": 14})
    run_triage(findings, ok, jobs=4)
    assert ok.calls == len(findings)
    assert all(f.triage["priority"] == "P2" for f in findings)


def test_rules_backend_errors_are_not_masked():
    # RulesBackend has no fallback path — a bug should surface loudly.
    findings = _findings()
    rules = RulesBackend()
    run_triage(findings, rules)
    assert all(f.triage["backend"] == "ssvc" for f in findings)


def test_provider_neutral_backend_keeps_ssvc_authoritative():
    finding = _quiet_finding()
    baseline = RulesBackend().triage(finding)
    provider = FakeProvider({
        "action": baseline["action"],
        "rationale": "Explain the supplied SSVC path.",
        "remediation_steps": ["Review the vendor advisory."],
        "uncertainties": [],
    })
    result = AIBackend(model="example-model", provider=provider).triage(finding)

    assert result["priority"] == baseline["priority"]
    assert result["action"] == baseline["action"]
    assert result["suggested_deadline_days"] == baseline[
        "suggested_deadline_days"
    ]
    assert result["backend"] == "test-provider:example-model"
    assert result["ai_recommendation"]["remediation_steps"] == [
        "Review the vendor advisory."
    ]
    assert provider.calls[0]["system_prompt"] == TRIAGE_SYSTEM_PROMPT
    assert '"ssvc_assessment"' in provider.calls[0]["payload"]


def test_openai_compatible_provider_uses_structured_tool_call():
    arguments = {
        "action": "monitor",
        "rationale": "The supplied SSVC path is Defer.",
        "remediation_steps": ["Continue monitoring."],
        "uncertainties": [],
    }
    http = FakeHTTPClient({
        "choices": [{
            "message": {
                "tool_calls": [{
                    "function": {
                        "name": "triage",
                        "arguments": __import__("json").dumps(arguments),
                    },
                }],
            },
        }],
    })
    provider = OpenAICompatibleProvider(
        base_url="http://localhost:11434/v1",
        client=http,
    )
    result = provider.complete(
        model="local-model",
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        payload="{}",
        tool=TRIAGE_TOOL,
    )

    assert result == arguments
    url, request = http.calls[0]
    assert url == "http://localhost:11434/v1/chat/completions"
    assert request["json"]["tool_choice"]["function"]["name"] == "triage"
    assert request["json"]["tools"][0]["function"]["strict"] is True
    assert "Authorization" not in request["headers"]


def test_invalid_provider_output_falls_back_to_rules():
    finding = _quiet_finding()
    provider = FakeProvider({
        "action": "invent_a_priority",
        "rationale": "invalid",
        "remediation_steps": [],
        "uncertainties": [],
    })
    run_triage(
        [finding],
        AIBackend(model="example-model", provider=provider),
    )
    assert finding.triage["backend"] == "rules_fallback"
    assert "invalid action" in finding.triage["error"]
