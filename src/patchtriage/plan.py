"""Layer 6 — Remediation planning.

Individual findings are the wrong unit of work: nobody patches one CVE at a
time. One package upgrade typically closes many findings at once. This layer
groups findings into concrete *actions* ("upgrade libc6 on web-frontend to
2.36-9+deb12u3") and ranks actions by the categorical SSVC Deployer outcome.
No proprietary arithmetic risk score competes with or modifies that outcome.
"""

from __future__ import annotations

from collections import defaultdict
from functools import cmp_to_key
import re

from packaging.version import InvalidVersion, Version
from typing import Optional

from pydantic import BaseModel, Field

from .bod2604 import action_policy
from .dedup import package_identity
from .models import Finding
from .ssvc import ssvc_sort_key

_PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


class Action(BaseModel):
    """One concrete unit of remediation work."""

    action_id: str
    kind: str                      # upgrade | mitigate | investigate
    summary: str                   # human-readable instruction
    asset: str
    package: str
    ecosystem: str = ""
    package_namespace: str = ""
    installed_version: str = ""
    target_version: str = ""
    target_version_candidates: list[str] = Field(default_factory=list)
    finding_keys: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    top_priority: str = "P4"       # best (lowest) triage priority among findings
    deadline_days: int = 90
    kev_count: int = 0
    rationales: list[str] = Field(default_factory=list)
    # Separate CISA BOD 26-04 policy view. ``deadline_days`` above stays the
    # SSVC workflow target; the effective fields name the rule that set them.
    bod2604: Optional[dict] = None
    effective_deadline_days: Optional[int] = None
    effective_rule: str = ""
    obligations: list[str] = Field(default_factory=list)


_SEMVER = re.compile(
    r"^[vV]?(\d+)\.(\d+)(?:\.(\d+))?"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_MAVEN_SPLIT = re.compile(
    r"[._+\-]+|(?<=\d)(?=[A-Za-z])|(?<=[A-Za-z])(?=\d)")
_NATURAL_PART = re.compile(r"\d+|[A-Za-z]+|~|[^A-Za-z0-9~]+")
_MAVEN_QUALIFIERS = {
    "alpha": 0, "a": 0,
    "beta": 1, "b": 1,
    "milestone": 2, "m": 2,
    "rc": 3, "cr": 3,
    "snapshot": 4,
    "": 5, "ga": 5, "final": 5, "release": 5,
    "sp": 6,
}


def _prerelease_key(value: str) -> tuple:
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in value.split(".")
    )


def _semver_key(value: str) -> tuple | None:
    match = _SEMVER.fullmatch(value.strip())
    if not match:
        return None
    major, minor, patch, prerelease = match.groups()
    release = (int(major), int(minor), int(patch or 0))
    # A release is newer than any of its prereleases.
    return release, 1 if prerelease is None else 0, (
        () if prerelease is None else _prerelease_key(prerelease)
    )


def _pep440_key(value: str) -> Version | None:
    try:
        return Version(value.strip())
    except InvalidVersion:
        return None


def _maven_key(value: str) -> tuple | None:
    """Order common Maven ComparableVersion forms conservatively.

    Maven's well-known qualifier order is materially different from SemVer:
    in particular ``sp`` is newer than the base release, while ``rc`` is
    older. Unknown qualifiers sort after the known set, matching Maven's
    lexical fallback.
    """
    tokens = [token.casefold() for token in _MAVEN_SPLIT.split(value.strip())
              if token]
    if not tokens:
        return None
    release: list[int] = []
    index = 0
    while index < len(tokens) and tokens[index].isdigit():
        release.append(int(tokens[index]))
        index += 1
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    if index == len(tokens):
        return tuple(release or [0]), _MAVEN_QUALIFIERS[""], "", ()
    qualifier = tokens[index]
    rank = _MAVEN_QUALIFIERS.get(qualifier, 7)
    qualifier_text = "" if qualifier in _MAVEN_QUALIFIERS else qualifier
    tail = tuple(
        (0, int(token)) if token.isdigit() else (1, token)
        for token in tokens[index + 1:]
    )
    return tuple(release or [0]), rank, qualifier_text, tail


def _debian_order(char: str) -> int:
    if char == "~":
        return -1
    if not char:
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _debian_part_compare(left: str, right: str) -> int:
    """Implement dpkg's verrevcmp ordering for one version component."""
    left_index = right_index = 0
    while left_index < len(left) or right_index < len(right):
        while (
            (left_index < len(left) and not left[left_index].isdigit())
            or (right_index < len(right) and not right[right_index].isdigit())
        ):
            left_char = (
                left[left_index]
                if left_index < len(left) and not left[left_index].isdigit()
                else ""
            )
            right_char = (
                right[right_index]
                if right_index < len(right) and not right[right_index].isdigit()
                else ""
            )
            difference = _debian_order(left_char) - _debian_order(right_char)
            if difference:
                return 1 if difference > 0 else -1
            if left_char:
                left_index += 1
            if right_char:
                right_index += 1

        while left_index < len(left) and left[left_index] == "0":
            left_index += 1
        while right_index < len(right) and right[right_index] == "0":
            right_index += 1
        left_start, right_start = left_index, right_index
        while left_index < len(left) and left[left_index].isdigit():
            left_index += 1
        while right_index < len(right) and right[right_index].isdigit():
            right_index += 1
        left_digits = left[left_start:left_index]
        right_digits = right[right_start:right_index]
        if len(left_digits) != len(right_digits):
            return 1 if len(left_digits) > len(right_digits) else -1
        if left_digits != right_digits:
            return 1 if left_digits > right_digits else -1
    return 0


def _debian_version(value: str) -> tuple[int, str, str]:
    epoch_text, separator, remainder = value.partition(":")
    if separator and epoch_text.isdigit():
        epoch = int(epoch_text)
    else:
        epoch, remainder = 0, value
    upstream, separator, revision = remainder.rpartition("-")
    if not separator:
        upstream, revision = remainder, "0"
    return epoch, upstream, revision


def _debian_compare(left: str, right: str) -> int:
    left_epoch, left_upstream, left_revision = _debian_version(left)
    right_epoch, right_upstream, right_revision = _debian_version(right)
    if left_epoch != right_epoch:
        return 1 if left_epoch > right_epoch else -1
    upstream = _debian_part_compare(left_upstream, right_upstream)
    return upstream or _debian_part_compare(left_revision, right_revision)


def _natural_key(value: str) -> tuple:
    parts = []
    for part in _NATURAL_PART.findall(value.strip()):
        if part == "~":
            parts.append((-1, ""))
        elif part.isdigit():
            parts.append((1, int(part)))
        elif part.isalpha():
            parts.append((2, part.lower()))
        else:
            parts.append((0, part))
    return tuple(parts)


def compare_versions(left: str, right: str, ecosystem: str) -> int:
    """Compare common ecosystem versions without choosing a false scheme."""
    if left == right:
        return 0
    normalized = str(ecosystem or "").strip().lower()
    if normalized in {"debian", "deb"}:
        return _debian_compare(left, right)
    if normalized in {"pypi", "python"}:
        parsers = (_pep440_key,)
    elif normalized == "maven":
        parsers = (_maven_key,)
    elif normalized in {
            "npm", "golang", "go", "cargo", "crates.io", "pub"}:
        # Prefer SemVer, but tolerate scanner-supplied forms such as
        # ``2.0.6rc1`` when both operands have an unambiguous PEP 440 order.
        parsers = (_semver_key, _pep440_key)
    else:
        parsers = (_semver_key, _pep440_key)
    for parser in parsers:
        left_key, right_key = parser(left), parser(right)
        if left_key is not None and right_key is not None:
            return (left_key > right_key) - (left_key < right_key)
    left_key, right_key = _natural_key(left), _natural_key(right)
    return (left_key > right_key) - (left_key < right_key)


def _version_candidates(group: list[Finding], ecosystem: str) -> list[str]:
    candidates = {
        candidate.strip()
        for finding in group
        for candidate in (
            [finding.package.fixed_version]
            + list(finding.package.fixed_version_candidates)
        )
        if candidate.strip()
    }
    compare = lambda left, right: compare_versions(left, right, ecosystem)
    return sorted(candidates, key=cmp_to_key(compare))


def build_plan(findings: list[Finding]) -> list[Action]:
    """Group findings into actions and rank by SSVC action timing."""
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        ecosystem, namespace, normalized_name, installed_version = (
            package_identity(f.package)
        )
        if f.package.fixed_version:
            kind = "upgrade"
        else:
            kind = "mitigate"
        key = (
            kind, f.asset.identifier, ecosystem, namespace,
            normalized_name, installed_version,
        )
        groups[key].append(f)

    actions: list[Action] = []
    ordering: dict[str, tuple] = {}
    for (kind, asset, ecosystem, namespace, _name, installed), group in groups.items():
        pkg = group[0].package.name
        candidates = _version_candidates(group, ecosystem)
        target = candidates[-1] if candidates else ""
        prios = [(g.triage or {}).get("priority", "P4") for g in group]
        top = min(prios, key=lambda p: _PRIORITY_RANK.get(p, 9))
        deadlines = [(g.triage or {}).get("suggested_deadline_days", 90)
                     for g in group]
        if kind == "upgrade":
            summary = f"Upgrade {pkg} to {target} on {asset}"
        else:
            summary = (f"No fixed version confirmed for {pkg} on {asset} - "
                       f"investigate vendor guidance and apply mitigations")
        identity = ":".join((ecosystem, namespace, _name, installed))
        action_id = f"{kind}:{asset}:{identity}"
        top_group = [
            finding for finding in group
            if (finding.triage or {}).get("priority", "P4") == top
        ]
        ordering[action_id] = max(
            (ssvc_sort_key(finding) for finding in (top_group or group)),
            default=(0, 0, 0, 0, 0.0, 0.0),
        )
        actions.append(Action(
            action_id=action_id,
            kind=kind,
            summary=summary,
            asset=asset,
            package=pkg,
            ecosystem=ecosystem,
            package_namespace=namespace,
            installed_version=installed,
            target_version=target,
            target_version_candidates=candidates,
            finding_keys=[g.key for g in group],
            cves=sorted({g.vuln_id for g in group}),
            top_priority=top,
            deadline_days=min(deadlines) if deadlines else 90,
            kev_count=sum(1 for g in group if g.enrichment.in_cisa_kev),
            rationales=[(g.triage or {}).get("rationale", "") for g in group][:3],
            **action_policy(group),
        ))

    actions.sort(key=lambda action: (
        _PRIORITY_RANK.get(action.top_priority, 9),
        *(-value for value in ordering[action.action_id]),
    ))
    return actions
