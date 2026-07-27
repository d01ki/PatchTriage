"""Layer 5 — AI triage.

The deterministic CERT/CC SSVC Deployer tree owns action timing. The LLM
receives that final assessment and may add explanation, remediation steps,
and uncertainty notes; it cannot rescore or override the decision.

Backends are pluggable. Three public modes are shipped:
  * "rules"   — deterministic SSVC (no API key)
  * "ai"      — provider-neutral structured explanation through Anthropic or
                an OpenAI-compatible endpoint ("claude" remains an alias).
  * "cascade" — two-tier provider-neutral pipeline: a fast screening model
                handles every finding; urgent or low-confidence decisions and
                failed explanation audits are escalated to a deeper model.

Robustness: run_triage() parallelizes API calls and degrades gracefully —
a finding whose API call fails is triaged by the deterministic SSVC baseline
and tagged, so a network blip never aborts a 2,000-finding run.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional, Protocol

from ..models import Finding
from ..ssvc import assess, triage_from_assessment
from .providers import (
    AIProvider,
    ANTHROPIC_DEFAULT_MODEL,
    ANTHROPIC_DEFAULT_SCREEN_MODEL,
    AnthropicProvider,
    make_provider,
    resolve_model,
    resolve_provider_name,
)

# Backwards-compatible imports for callers that customized the old backend.
DEFAULT_MODEL = ANTHROPIC_DEFAULT_MODEL
DEFAULT_SCREEN_MODEL = ANTHROPIC_DEFAULT_SCREEN_MODEL

TRIAGE_SYSTEM_PROMPT = """\
You are a vulnerability-management analyst performing patch triage.
You will receive ONE finding plus a deterministic SSVC Deployer assessment.
The SSVC decision and P1-P4 mapping are final. Your role is to explain that
decision and propose concrete remediation steps, not to rescore the finding.

Rules:
- NEVER invent or adjust numeric scores. Reason only from the given signals.
- NEVER change the supplied SSVC decision, priority, or service-level target.
- Distinguish observed exploitation (KEV/PoC) from predictive EPSS evidence.
- No available fix means mitigation or investigation, not patching.
- Call out low-confidence SSVC inputs that need human confirmation.
- Be concise and concrete. Output via the `triage` tool only.
"""

TRIAGE_TOOL = {
    "name": "triage",
    "description": "Record the triage decision for one finding.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "enum": ["patch_immediately", "patch_out_of_cycle",
                                "patch_scheduled", "mitigate", "monitor",
                                "investigate"]},
            "rationale": {"type": "string",
                          "maxLength": 2000,
                          "description": "2-3 sentences citing SSVC inputs"},
            "remediation_steps": {
                "type": "array",
                "items": {"type": "string", "maxLength": 2000},
                "maxItems": 5,
            },
            "uncertainties": {
                "type": "array",
                "items": {"type": "string", "maxLength": 2000},
                "maxItems": 5,
            },
        },
        "required": ["action", "rationale", "remediation_steps",
                     "uncertainties"],
        "additionalProperties": False,
    },
}


class TriageBackend(Protocol):
    def triage(self, finding: Finding) -> dict: ...


# ------------------------------------------------------------------ baseline
class SSVCBackend:
    """Deterministic CERT/CC SSVC Deployer decision backend."""

    def triage(self, f: Finding) -> dict:
        return triage_from_assessment(assess(f), backend="ssvc")


class RulesBackend(SSVCBackend):
    """Backward-compatible name for the deterministic SSVC backend."""


def _finding_payload(f: Finding) -> str:
    payload = f.model_dump(mode="json", exclude={"triage", "description"})
    payload["description"] = f.description[:600]
    payload["ssvc_assessment"] = assess(f).model_dump(mode="json")
    return json.dumps(payload)


def _merge_ai_recommendation(f: Finding, recommendation: dict,
                             backend: str) -> dict:
    """Keep the SSVC decision authoritative and attach AI assistance."""
    result = triage_from_assessment(assess(f), backend=backend)
    if recommendation.get("rationale"):
        result["rationale"] = str(recommendation["rationale"])
    result["ai_recommendation"] = {
        "action": recommendation.get("action"),
        "remediation_steps": recommendation.get("remediation_steps", []),
        "uncertainties": recommendation.get("uncertainties", []),
    }
    return result


def _validate_recommendation(recommendation: dict) -> dict:
    """Enforce the tool schema locally across providers."""
    if not isinstance(recommendation, dict):
        raise RuntimeError("AI provider returned a non-object recommendation")
    expected_fields = {
        "action", "rationale", "remediation_steps", "uncertainties",
    }
    if set(recommendation) != expected_fields:
        raise RuntimeError(
            "AI provider returned missing or unexpected recommendation fields"
        )
    allowed_actions = set(TRIAGE_TOOL["input_schema"]["properties"]["action"][
        "enum"
    ])
    action = recommendation.get("action")
    if action not in allowed_actions:
        raise RuntimeError(f"AI provider returned invalid action: {action!r}")
    rationale = recommendation.get("rationale")
    if (not isinstance(rationale, str) or not rationale.strip()
            or len(rationale) > 2000):
        raise RuntimeError("AI provider returned an invalid rationale")
    validated = {
        "action": action,
        "rationale": rationale.strip(),
    }
    for field in ("remediation_steps", "uncertainties"):
        values = recommendation.get(field)
        if (not isinstance(values, list) or len(values) > 5
                or any(not isinstance(value, str) or len(value) > 2000
                       for value in values)):
            raise RuntimeError(
                f"AI provider returned invalid {field}; expected up to 5 strings"
            )
        validated[field] = [value.strip() for value in values if value.strip()]
    return validated


class AIBackend:
    """Provider-neutral structured AI explanation backend."""

    def __init__(self, model: str | None = None,
                 provider: str | AIProvider | None = None,
                 base_url: str | None = None):
        if provider is not None and not isinstance(provider, str):
            self.provider = provider
            provider_name = provider.name
        else:
            provider_name = resolve_provider_name(provider)
            self.provider = make_provider(
                provider or provider_name, base_url=base_url
            )
        self.model = resolve_model(provider_name, model, tier="deep")

    def triage(self, f: Finding) -> dict:
        recommendation = self.provider.complete(
            model=self.model,
            system_prompt=TRIAGE_SYSTEM_PROMPT,
            payload=_finding_payload(f),
            tool=TRIAGE_TOOL,
        )
        recommendation = _validate_recommendation(recommendation)
        return _merge_ai_recommendation(
            f, recommendation, f"{self.provider.name}:{self.model}"
        )


class ClaudeBackend(AIBackend):
    """Deprecated compatibility alias for the Anthropic provider."""

    def __init__(self, model: str = DEFAULT_MODEL):
        super().__init__(model=model, provider="anthropic")


# ------------------------------------------------------------------ cascade
class CascadeBackend:
    """Two-tier triage: screen everything cheap, escalate what matters.

    Tier 1 (screen): every finding is triaged by a fast screening model.
    Tier 2 (deep):   a finding is re-triaged by the frontier model when it is
      * SSVC-urgent — Immediate or Out-of-Cycle needs richer guidance,
      * context-uncertain — a conservative SSVC input needs confirmation, or
      * audit-flagged — the screening explanation failed the machine audit.

    The escalation decision and its reasons are recorded in the triage output
    so every routing choice is itself auditable.
    """

    def __init__(self,
                 screen_model: str | None = None,
                 deep_model: str | None = None,
                 provider: str | AIProvider | None = None,
                 base_url: str | None = None,
                 screen: Optional[TriageBackend] = None,
                 deep: Optional[TriageBackend] = None):
        if screen is None or deep is None:
            if provider is not None and not isinstance(provider, str):
                provider_client = provider
                provider_name = provider.name
            else:
                provider_name = resolve_provider_name(provider)
                provider_client = make_provider(
                    provider or provider_name, base_url=base_url
                )
            if screen is None:
                screen = AIBackend(
                    resolve_model(provider_name, screen_model, tier="screen"),
                    provider=provider_client,
                )
            if deep is None:
                deep = AIBackend(
                    resolve_model(provider_name, deep_model, tier="deep"),
                    provider=provider_client,
                )
        self.screen = screen
        self.deep = deep
        self._rules = RulesBackend()

    def _escalation_reasons(self, f: Finding, tentative: dict) -> list[str]:
        from .audit import audit_finding  # deferred: audit imports engine

        reasons: list[str] = []
        assessment = assess(f)
        if assessment.priority in ("P1", "P2"):
            reasons.append(f"ssvc_{assessment.decision.value}")
        if assessment.needs_confirmation:
            reasons.append(
                "ssvc_confirmation:" + ",".join(assessment.needs_confirmation))

        prev = f.triage
        f.triage = tentative
        try:
            audit = audit_finding(f, self._rules)
        finally:
            f.triage = prev
        if not audit["verified"]:
            reasons.append("audit_flags:" + ",".join(audit["flags"]))
        return reasons

    def triage(self, f: Finding) -> dict:
        result = self.screen.triage(f)
        reasons = self._escalation_reasons(f, result)
        if reasons:
            result = self.deep.triage(f)
            result["escalated"] = True
            result["escalation_reasons"] = reasons
        else:
            result["escalated"] = False
        return result


def get_backend(name: str = "rules", model: str | None = None,
                escalation_model: str | None = None,
                provider: str | None = None,
                base_url: str | None = None) -> TriageBackend:
    if name == "rules":
        return RulesBackend()
    if name == "claude":
        return ClaudeBackend(model or DEFAULT_MODEL)
    if name == "ai":
        return AIBackend(model, provider=provider, base_url=base_url)
    if name == "cascade":
        return CascadeBackend(
            screen_model=model,
            deep_model=escalation_model,
            provider=provider,
            base_url=base_url,
        )
    raise ValueError(f"Unknown triage backend: {name}")


# ------------------------------------------------------------------ runner
def run_triage(findings: list[Finding], backend: TriageBackend,
               progress: Optional[Callable[[int, int], None]] = None,
               jobs: int = 1) -> list[Finding]:
    """Triage every finding in place.

    API-backed runs parallelize across `jobs` workers. A finding whose API
    call fails falls back to the deterministic SSVC baseline and is tagged
    (backend="rules_fallback") — one flaky request never aborts the run.
    """
    rules = RulesBackend()
    is_rules = isinstance(backend, RulesBackend)

    def _one(f: Finding) -> dict:
        try:
            return backend.triage(f)
        except Exception as exc:
            if is_rules:  # a bug in the baseline should never be masked
                raise
            out = rules.triage(f)
            out["backend"] = "rules_fallback"
            out["error"] = f"{type(exc).__name__}: {exc}"[:300]
            return out

    if jobs <= 1 or is_rules:
        for i, f in enumerate(findings):
            f.triage = _one(f)
            if progress:
                progress(i + 1, len(findings))
    else:
        done = 0
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            for f, result in zip(findings, pool.map(_one, findings)):
                f.triage = result
                done += 1
                if progress:
                    progress(done, len(findings))
    return findings


# ------------------------------------------------------------------ batch
def run_triage_batch(findings: list[Finding], model: str | None = None,
                     poll_seconds: float = 15.0,
                     progress: Optional[Callable[[str], None]] = None,
                     provider: str | None = None,
                     ) -> list[Finding]:
    """Triage via the Anthropic Message Batches API — 50% of standard cost.

    Best for large, non-interactive runs (nightly re-triage of a whole
    estate). Most batches complete within an hour; results are keyed by
    custom_id, never by position. Findings whose batch entry errors fall
    back to the SSVC baseline, same as run_triage().
    """
    provider_name = resolve_provider_name(provider)
    if provider_name != "anthropic":
        raise ValueError(
            "Batch mode currently requires the Anthropic provider; "
            "use regular parallel mode for OpenAI-compatible endpoints"
        )
    model = resolve_model(provider_name, model, tier="deep")
    provider_client = make_provider(provider_name)
    if not isinstance(provider_client, AnthropicProvider):
        raise RuntimeError("Anthropic provider could not be initialized")
    client = provider_client.client
    rules = RulesBackend()

    requests = [{
        "custom_id": f"finding-{i}",
        "params": {
            "model": model,
            "max_tokens": 1024,
            "system": [{"type": "text", "text": TRIAGE_SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": _finding_payload(f)}],
            "tools": [TRIAGE_TOOL],
            "tool_choice": {"type": "tool", "name": "triage"},
        },
    } for i, f in enumerate(findings)]

    batch = client.messages.batches.create(requests=requests)
    if progress:
        progress(f"batch {batch.id} submitted ({len(requests)} findings)")

    while True:
        batch = client.messages.batches.retrieve(batch.id)
        if batch.processing_status == "ended":
            break
        if progress:
            progress(f"batch {batch.id}: {batch.processing_status} "
                     f"({batch.request_counts.processing} processing)")
        time.sleep(poll_seconds)

    by_id: dict[str, dict] = {}
    for result in client.messages.batches.results(batch.id):
        if result.result.type == "succeeded":
            for block in result.result.message.content:
                if block.type == "tool_use" and block.name == "triage":
                    by_id[result.custom_id] = dict(block.input)

    for i, f in enumerate(findings):
        out = by_id.get(f"finding-{i}")
        if out is None:
            out = rules.triage(f)
            out["backend"] = "rules_fallback"
            out["error"] = "batch entry errored or expired"
        else:
            out = _merge_ai_recommendation(
                f, _validate_recommendation(out),
                f"anthropic:{model} (batch)",
            )
        f.triage = out
    return findings
