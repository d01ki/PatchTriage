"""Layer 4 — Organizational context.

Scanners know nothing about YOUR environment. This layer applies an asset
inventory (simple YAML, checked into your repo) onto findings:

    assets:
      - match: "web-frontend*"        # glob against asset identifier
        criticality: critical         # business criticality
        internet_exposed: true
        system_exposure: open         # SSVC: small|controlled|open
        automatable: yes              # SSVC: yes|no|unknown
        mission_impact: mef_failure   # SSVC organizational consequence
        safety_impact: marginal       # SSVC safety/well-being consequence
        publicly_exposed: yes         # CISA BOD 26-04 cisa:PE (not System Exposure)
        bod2604_applicability: voluntary  # required|voluntary|not_applicable
        reachable: true                # static call/dependency analysis
        runtime_observed: true         # eBPF / Falco / OpenTelemetry evidence
        context_sources: [otel, falco]
        owner: platform-team
        notes: "customer-facing checkout"
      - match: "batch-*"
        criticality: low
        internet_exposed: false

The same CVE on an internet-exposed checkout service and on an internal batch
box should never get the same priority. This file is how the tool learns the
difference.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml

from .models import Finding


_SSVC_CHOICES = {
    "system_exposure": {"small", "controlled", "open", "unknown"},
    "automatable": {"yes", "no", "unknown"},
    "mission_impact": {
        "degraded", "mef_support_crippled", "mef_failure",
        "mission_failure", "unknown",
    },
    "safety_impact": {
        "negligible", "marginal", "critical", "catastrophic", "unknown",
    },
}

_POLICY_CHOICES = {
    "publicly_exposed": {"yes", "no", "unknown"},
    "bod2604_applicability": {"required", "voluntary", "not_applicable",
                              "unknown"},
}


def _as_bool(value, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ValueError(f"inventory field '{field}' must be true or false")


def _as_choice(value, field: str) -> str:
    if field == "automatable" and isinstance(value, bool):
        return "yes" if value else "no"
    if field == "publicly_exposed" and isinstance(value, bool):
        return "yes" if value else "no"
    choices = _SSVC_CHOICES.get(field) or _POLICY_CHOICES[field]
    normalized = str(value or "unknown").strip().lower().replace("-", "_")
    if normalized not in choices:
        allowed = ", ".join(sorted(choices))
        raise ValueError(f"inventory field '{field}' must be one of: {allowed}")
    return normalized


def load_inventory(path: str | Path) -> list[dict]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries = data.get("assets", [])
    for e in entries:
        if "match" not in e:
            raise ValueError(f"inventory entry missing 'match': {e}")
    return entries


def apply_context(findings: list[Finding], inventory: list[dict]) -> int:
    """Apply the first matching inventory rule to each finding's asset.

    Returns the number of findings that matched a rule.
    """
    matched = 0
    for f in findings:
        for rule in inventory:
            if fnmatch.fnmatch(f.asset.identifier, rule["match"]):
                if "criticality" in rule:
                    f.asset.criticality = str(rule["criticality"])
                if "internet_exposed" in rule:
                    f.asset.internet_exposed = _as_bool(
                        rule["internet_exposed"], "internet_exposed")
                if "reachable" in rule:
                    f.asset.reachable = _as_bool(rule["reachable"], "reachable")
                if "runtime_observed" in rule:
                    f.asset.runtime_observed = _as_bool(
                        rule["runtime_observed"], "runtime_observed")
                for field in (*_SSVC_CHOICES, *_POLICY_CHOICES):
                    if field in rule:
                        setattr(f.asset, field, _as_choice(rule[field], field))
                if "context_sources" in rule:
                    sources = rule["context_sources"]
                    if isinstance(sources, str):
                        sources = [sources]
                    f.asset.context_sources = [str(s) for s in (sources or [])]
                if "owner" in rule:
                    f.asset.owner = str(rule["owner"])
                if "notes" in rule:
                    f.asset.context_notes = str(rule["notes"])
                matched += 1
                break
    return matched
