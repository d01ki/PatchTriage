"""Triage audit — the verifiability layer.

Every AI-assisted result is machine-checked against the deterministic signals
it was given. The audit detects structured decision conflicts, unsupported
numeric claims, and unsafe remediation text; it is a review control, not a
proof that arbitrary natural-language output contains no error.

Checks per finding:
  fabricated_numbers   numeric and percentage claims in AI rationale,
                       remediation, and uncertainty text must correspond to
                       real signals or the deterministic service target
  ssvc_consistency     priority and outcome must match the deterministic SSVC
                       Deployer decision table
  fix_consistency      "patch_*" actions require an available fixed version;
                       "mitigate" is for findings without one
  evidence_completeness the SSVC path and confidence provenance must be present
  ai_recommendation_consistency nested AI actions cannot downgrade SSVC, claim
                       KEV is inactive, or prescribe a nonexistent patch

The result is attached to finding.triage["audit"] and surfaced in the CLI
summary and the HTML report.
"""

from __future__ import annotations

import re

from ..models import Finding
from .engine import RulesBackend

_NUMBER = re.compile(r"(?<![A-Za-z0-9_])(?P<value>\d+(?:\.\d+)?)(?P<percent>\s*%)?")
_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_KEV_DOWNGRADE = re.compile(
    r"(?:\b(?:no|not|without)\b.{0,28}\bexploit(?:ation|ed)?\b|"
    r"\bexploit(?:ation|ed)?\b.{0,28}\b(?:absent|none|unlikely)\b)",
    re.IGNORECASE,
)
_PATCH_INSTRUCTION = re.compile(
    r"\b(?:upgrade|update|install|apply\s+(?:the\s+)?patch|"
    r"patch\s+(?:the|this|package|system))\b",
    re.IGNORECASE,
)

_ACTION_RANK = {
    "monitor": 0,
    "investigate": 1,
    "mitigate": 2,
    "patch_scheduled": 2,
    "patch_out_of_cycle": 3,
    "patch_immediately": 4,
}


_SHELL_INSTRUCTION = re.compile(
    r"\b(?:curl|wget|Invoke-Expression|iex|chmod\s+\+x|bash\s+-c)\b"
    r"|\|\s*(?:sh|bash)\b",
    re.IGNORECASE,
)


def _signal_values(f: Finding) -> set[float]:
    e = f.enrichment
    vals = [v for v in (e.epss_score, e.epss_percentile,
                        e.nvd_cvss_score, f.cvss_score) if v is not None]
    # common renderings of the same signals
    return set(vals + [round(v, 1) for v in vals]
               + [round(v, 2) for v in vals])


def _percentage_values(f: Finding) -> set[float]:
    e = f.enrichment
    values: set[float] = set()
    for value in (e.epss_score, e.epss_percentile):
        if value is None:
            continue
        percentage = value * 100 if 0.0 <= value <= 1.0 else value
        values.update((percentage, round(percentage),
                       round(percentage, 1), round(percentage, 2)))
    return values


def _strip_known_tokens(f: Finding, text: str) -> str:
    """Remove CVE ids and version strings so they don't parse as numbers."""
    text = _URL.sub(" ", text)
    text = _DATE.sub(" ", text)
    text = re.sub(r"CVE-\d{4}-\d+", " ", text)
    for token in (
        f.vuln_id, *f.aliases, f.package.version, f.package.fixed_version,
        f.enrichment.nvd_cvss_vector, f.enrichment.nvd_cvss_version,
        f.enrichment.kev_due_date or "",
    ):
        if token:
            text = text.replace(token, " ")
    return text


def _triage_text_fields(triage: dict) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    rationale = triage.get("rationale")
    if rationale:
        fields.append(("rationale", str(rationale)))
    ai = triage.get("ai_recommendation")
    if not isinstance(ai, dict):
        return fields
    if ai.get("rationale"):
        fields.append(("ai_rationale", str(ai["rationale"])))
    for name in ("remediation_steps", "uncertainties"):
        values = ai.get(name) or []
        if isinstance(values, list):
            fields.extend(
                (f"ai_{name}[{index}]", str(value))
                for index, value in enumerate(values)
            )
    return fields


def _numeric_claim_flags(f: Finding, field: str, text: str,
                         deadline_days: int) -> list[str]:
    stripped = _strip_known_tokens(f, text)
    signals = _signal_values(f)
    percentages = _percentage_values(f)
    flags: list[str] = []
    for match in _NUMBER.finditer(stripped):
        rendered = match.group("value")
        value = float(rendered)
        is_percent = bool(match.group("percent"))
        nearby = stripped[
            max(0, match.start() - 18):min(len(stripped), match.end() + 18)
        ].lower()
        is_duration = bool(re.search(
            r"\b(?:day|days|hour|hours|week|weeks|month|months|deadline|sla|target)\b",
            nearby,
        ))
        is_percentage_context = is_percent or bool(re.search(
            r"\b(?:percent|percentage|percentile)\b", nearby,
        ))
        signal_context = bool(re.search(
            r"\b(?:epss|cvss|score|percentile|probability|risk\s+rating)\b",
            nearby,
        ))
        # Ordinals, protocol versions, numbered steps, ports, and other bare
        # prose numbers are not quantitative vulnerability claims. Audit only
        # explicit signal, percentage, or service-target/duration contexts.
        if not (is_percentage_context or is_duration or signal_context):
            continue
        allowed = (
            percentages if is_percent else
            percentages | signals if is_percentage_context else
            {float(deadline_days)} if is_duration else
            signals
        )
        if any(abs(value - known) <= 0.051 for known in allowed):
            continue
        if is_percent:
            flags.append(f"fabricated_percentage:{field}:{rendered}%")
            continue
        # Large bare integers are commonly years or advisory identifiers. They
        # become auditable claims when paired with a duration/SLA unit.
        if is_duration or signal_context or is_percentage_context:
            flags.append(f"fabricated_number:{field}:{rendered}")
    return flags


def audit_finding(f: Finding, rules: RulesBackend) -> dict:
    t = f.triage or {}
    flags: list[str] = []
    baseline = rules.triage(f)
    # 1. fabricated numbers
    text_fields = _triage_text_fields(t)
    for field, text in text_fields:
        flags.extend(_numeric_claim_flags(
            f, field, text, baseline["suggested_deadline_days"],
        ))

    # 2. deterministic SSVC decision respected. KEV is an input to
    # Exploitation=Active, not a shortcut that bypasses stakeholder context.
    if t.get("priority") != baseline["priority"]:
        flags.append(
            f"ssvc_priority_mismatch:{baseline['priority']}->{t.get('priority')}")
    if t.get("action") != baseline["action"]:
        flags.append(
            f"ssvc_action_mismatch:{baseline['action']}->{t.get('action')}")
    if t.get("suggested_deadline_days") != baseline["suggested_deadline_days"]:
        flags.append(
            "ssvc_deadline_mismatch:"
            f"{baseline['suggested_deadline_days']}->"
            f"{t.get('suggested_deadline_days')}")
    actual_ssvc = t.get("ssvc")
    expected_ssvc = baseline["ssvc"]
    if not isinstance(actual_ssvc, dict):
        flags.append("ssvc_missing")
    else:
        if actual_ssvc.get("model") != expected_ssvc["model"]:
            flags.append("ssvc_model_mismatch")
        if actual_ssvc.get("decision") != expected_ssvc["decision"]:
            flags.append(
                "ssvc_decision_mismatch:"
                f"{expected_ssvc['decision']}->{actual_ssvc.get('decision')}")
        if actual_ssvc.get("decision_path") != expected_ssvc["decision_path"]:
            flags.append("ssvc_path_mismatch")
        for key in (
            "exploitation", "system_exposure", "automatable",
            "mission_impact", "safety_impact", "human_impact",
        ):
            actual_point = actual_ssvc.get(key)
            expected_point = expected_ssvc[key]
            if not isinstance(actual_point, dict):
                flags.append(f"ssvc_evidence_missing:{key}")
                continue
            if actual_point.get("value") != expected_point["value"]:
                flags.append(f"ssvc_input_mismatch:{key}")
            if not actual_point.get("source") or not actual_point.get("confidence"):
                flags.append(f"ssvc_evidence_missing:{key}")

    # 3. fix consistency
    action = t.get("action", "")
    has_fix = bool(f.package.fixed_version)
    if action.startswith("patch") and not has_fix:
        flags.append("patch_without_fix")
    if action == "mitigate" and has_fix and t.get("priority") in ("P1", "P2"):
        flags.append("mitigate_despite_available_fix")

    # 4. The nested AI recommendation is advisory, but must not contradict or
    # quietly downgrade the authoritative SSVC action. Its prose is checked
    # above with the same numeric-evidence rules as the top-level rationale.
    ai = t.get("ai_recommendation")
    if isinstance(ai, dict):
        ai_action = ai.get("action")
        expected_action = baseline["action"]
        if ai_action and ai_action != expected_action:
            if _ACTION_RANK.get(str(ai_action), -1) < _ACTION_RANK.get(
                expected_action, -1
            ):
                flags.append(
                    f"ai_action_downgrade:{expected_action}->{ai_action}"
                )
            else:
                flags.append(
                    f"ai_action_mismatch:{expected_action}->{ai_action}"
                )
        remediation = ai.get("remediation_steps") or []
        if not has_fix and isinstance(remediation, list) and any(
            _PATCH_INSTRUCTION.search(str(step)) for step in remediation
        ):
            flags.append("ai_patch_instruction_without_fix")
        if f.enrichment.in_cisa_kev:
            ai_text = " ".join(text for _field, text in text_fields)
            if _KEV_DOWNGRADE.search(ai_text):
                flags.append("ai_kev_exploitation_downgrade_claim")
        ai_text = " ".join(text for _field, text in text_fields)
        known_links = {str(reference) for reference in f.references}
        if (_SHELL_INSTRUCTION.search(ai_text) or any(
                url not in known_links for url in _URL.findall(ai_text))):
            flags.append("ai_unverified_link_or_command")

    return {
        "verified": not flags,
        "flags": flags,
        "baseline_priority": baseline["priority"],
        "ssvc_decision": expected_ssvc["decision"],
        "checks": ["fabricated_numbers", "ssvc_consistency",
                   "fix_consistency", "evidence_completeness",
                   "ai_recommendation_consistency"],
    }


def audit_all(findings: list[Finding]) -> dict:
    """Audit every triaged finding in place; return a summary."""
    rules = RulesBackend()
    verified = 0
    flagged: list[tuple[str, list[str]]] = []
    for f in findings:
        if f.triage is None:
            continue
        result = audit_finding(f, rules)
        f.triage["audit"] = result
        if result["verified"]:
            verified += 1
        else:
            flagged.append((f.vuln_id, result["flags"]))
    return {"total": sum(1 for f in findings if f.triage is not None),
            "verified": verified, "flagged": flagged}
