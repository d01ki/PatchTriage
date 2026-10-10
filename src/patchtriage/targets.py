"""Target registry for the GUI.

A "target" is one system you want to keep patched — an internal service, a
repository, a host. Organizations have many, so PatchTriage lets you register
a list of them, each with:

  * name          human label (used as the finding's asset identifier)
  * url           a link to the system (dashboard, repo, runbook) — shown as a
                  clickable link in the GUI so reviewers/operators can jump
                  straight to it
  * system_exposure, automatable, mission_impact, safety_impact
                  explicit SSVC Deployer context
  * publicly_exposed, bod2604_applicability
                  CISA BOD 26-04 policy inputs, kept separate from SSVC
  * reachable/runtime_observed
                  supplemental confidence evidence
  * source        an attached scan (Trivy/Grype/OSV JSON) or SBOM
                  (CycloneDX/SPDX), stored alongside the registry

Everything is persisted as JSON under the config dir, so the registry
survives restarts and can be version-controlled if desired.
"""

from __future__ import annotations

import json
import hashlib
import re
import shutil
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import config as cfgmod

_LOCK = threading.RLock()
_TARGET_ID = re.compile(r"^[0-9a-f]{12}$")
_WORKSPACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SOURCE_FILE = re.compile(
    r"^[0-9a-f]{12}_source(?:_[0-9a-f]{64})?\.json$")
_CRITICALITIES = {"critical", "high", "medium", "low", "unknown"}
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


class StaleInputError(RuntimeError):
    """A run finished after its target evidence or context was replaced."""


class TargetLimitError(RuntimeError):
    """A workspace reached its configured target limit."""


class SourceQuotaError(RuntimeError):
    """A source write would exceed the workspace evidence quota."""


def _validate_target_id(target_id: str) -> str:
    if not _TARGET_ID.fullmatch(str(target_id)):
        raise ValueError("invalid target id")
    return str(target_id)


def _clean_name(value: str) -> str:
    name = str(value or "").strip()
    if not name:
        raise ValueError("name is required")
    if len(name) > 120:
        raise ValueError("name must be 120 characters or fewer")
    return name


def _clean_url(value: str) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    if len(url) > 2048:
        raise ValueError("url is too long")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("url must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("url must not contain embedded credentials")
    return url


def _clean_criticality(value: str) -> str:
    criticality = str(value or "unknown").strip().lower()
    if criticality not in _CRITICALITIES:
        raise ValueError(
            "criticality must be critical, high, medium, low, or unknown")
    return criticality


def _clean_sources(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("context_sources must be a list")
    return [str(item).strip()[:80] for item in value[:10] if str(item).strip()]


def _clean_ssvc(value: str | None, field: str) -> str:
    if field == "automatable" and isinstance(value, bool):
        return "yes" if value else "no"
    normalized = str(value or "unknown").strip().lower().replace("-", "_")
    if normalized not in _SSVC_CHOICES[field]:
        allowed = ", ".join(sorted(_SSVC_CHOICES[field]))
        raise ValueError(f"{field} must be one of: {allowed}")
    return normalized


def _clean_policy(value: str | None, field: str) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_")
    if normalized not in _POLICY_CHOICES[field]:
        allowed = ", ".join(sorted(_POLICY_CHOICES[field]))
        raise ValueError(f"{field} must be one of: {allowed}")
    return normalized


def _clean_bool(value, field: str, optional: bool = False) -> bool | None:
    if value is None and optional:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be true or false")
    return value


def _clean_workspace_id(workspace_id: str | None) -> str | None:
    if workspace_id is None:
        return None
    value = str(workspace_id)
    if not _WORKSPACE_ID.fullmatch(value):
        raise ValueError("invalid workspace id")
    return value


def targets_dir(workspace_id: str | None = None) -> Path:
    """Return the private target directory for one browser workspace.

    ``None`` preserves the original local/CLI store.  The public GUI passes a
    cryptographically random workspace id held in an HttpOnly cookie, so two
    anonymous visitors never read or write the same registry or evidence.
    """
    workspace_id = _clean_workspace_id(workspace_id)
    d = (cfgmod.config_dir() / "targets" if workspace_id is None else
         cfgmod.config_dir() / "sessions" / workspace_id / "targets")
    d.mkdir(parents=True, exist_ok=True)
    return d


def touch_workspace(workspace_id: str) -> None:
    """Record browser-session activity for retention decisions."""
    workspace_id = _clean_workspace_id(workspace_id)
    if workspace_id is None:
        return
    directory = cfgmod.config_dir() / "sessions" / workspace_id
    directory.mkdir(parents=True, exist_ok=True)
    try:
        directory.touch()
    except OSError:
        pass


def _registry_path(workspace_id: str | None = None) -> Path:
    return targets_dir(workspace_id) / "targets.json"


def load_targets(workspace_id: str | None = None) -> list[dict]:
    with _LOCK:
        p = _registry_path(workspace_id)
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError):
                return []
        return []


def save_targets(targets: list[dict], workspace_id: str | None = None) -> None:
    with _LOCK:
        path = _registry_path(workspace_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(targets, indent=2), encoding="utf-8")
        tmp.replace(path)


def add_target(name: str, url: str = "", criticality: str = "unknown",
               internet_exposed: bool | None = None,
               reachable: bool | None = None,
               runtime_observed: bool | None = None,
               system_exposure: str = "unknown",
               automatable: str = "unknown",
               mission_impact: str = "unknown",
               safety_impact: str = "unknown",
               publicly_exposed: str = "unknown",
               bod2604_applicability: str = "unknown",
               context_sources: list[str] | None = None,
               demo: bool = False,
               workspace_id: str | None = None, *,
               max_targets: int | None = None) -> dict:
    with _LOCK:
        targets = load_targets(workspace_id)
        if max_targets is not None and len(targets) >= max_targets:
            raise TargetLimitError(
                f"target limit reached ({max_targets})")
        target = {
            "id": uuid.uuid4().hex[:12],
            "name": _clean_name(name),
            "url": _clean_url(url),
            "criticality": _clean_criticality(criticality),
            "internet_exposed": _clean_bool(
                internet_exposed, "internet_exposed", optional=True),
            "reachable": _clean_bool(reachable, "reachable", optional=True),
            "runtime_observed": _clean_bool(
                runtime_observed, "runtime_observed", optional=True),
            "system_exposure": _clean_ssvc(
                system_exposure, "system_exposure"),
            "automatable": _clean_ssvc(automatable, "automatable"),
            "mission_impact": _clean_ssvc(mission_impact, "mission_impact"),
            "safety_impact": _clean_ssvc(safety_impact, "safety_impact"),
            "publicly_exposed": _clean_policy(
                publicly_exposed, "publicly_exposed"),
            "bod2604_applicability": _clean_policy(
                bod2604_applicability, "bod2604_applicability"),
            "context_sources": _clean_sources(context_sources),
            "ssvc_overrides": {},
            "demo": bool(demo),
            "source_file": "",
            "source_format": "",
            "source_name": "",
            "source_sha256": "",
            "source_size": 0,
            "source_kind": "",
            "source_provenance": {},
            "input_revision": 0,
            "created_at": time.time(),
        }
        targets.append(target)
        save_targets(targets, workspace_id)
        return target


def _apply_target_fields(target: dict, fields: dict) -> None:
    """Validate and apply fields to an in-memory target record."""
    if fields.get("name") is not None:
        target["name"] = _clean_name(fields["name"])
    if fields.get("url") is not None:
        target["url"] = _clean_url(fields["url"])
    if fields.get("criticality") is not None:
        target["criticality"] = _clean_criticality(fields["criticality"])
    for key in ("internet_exposed", "reachable", "runtime_observed"):
        if key in fields:
            target[key] = _clean_bool(fields[key], key, optional=True)
    for key in _SSVC_CHOICES:
        if key in fields and fields[key] is not None:
            target[key] = _clean_ssvc(fields[key], key)
    for key in _POLICY_CHOICES:
        if key in fields and fields[key] is not None:
            target[key] = _clean_policy(fields[key], key)
    if fields.get("context_sources") is not None:
        target["context_sources"] = _clean_sources(fields["context_sources"])
    for key in (
        "source_file", "source_format", "source_name",
        "source_sha256", "source_kind",
    ):
        if key in fields and fields[key] is not None:
            target[key] = str(fields[key])
    if fields.get("source_size") is not None:
        target["source_size"] = max(0, int(fields["source_size"]))
    if fields.get("source_provenance") is not None:
        provenance = fields["source_provenance"]
        if not isinstance(provenance, dict):
            raise ValueError("source_provenance must be an object")
        target["source_provenance"] = provenance
    if fields.get("input_revision") is not None:
        target["input_revision"] = max(0, int(fields["input_revision"]))
    if fields.get("ssvc_overrides") is not None:
        overrides = fields["ssvc_overrides"]
        if not isinstance(overrides, dict) or len(overrides) > 1000:
            raise ValueError("ssvc_overrides must be an object")
        target["ssvc_overrides"] = overrides


def update_target(target_id: str, workspace_id: str | None = None,
                  **fields) -> dict | None:
    target_id = _validate_target_id(target_id)
    with _LOCK:
        targets = load_targets(workspace_id)
        for target in targets:
            if target["id"] == target_id:
                _apply_target_fields(target, fields)
                save_targets(targets, workspace_id)
                return target
        return None


def update_target_inputs(target_id: str, workspace_id: str | None = None,
                         *, clear_overrides: bool = False,
                         **fields) -> dict | None:
    """Commit changed decision inputs, revision, and invalidation safely.

    Validation happens before the old summary is removed. Invalidation then
    becomes visible before the changed inputs, and the registry update writes
    those inputs together with the new revision in one atomic file replace.
    """
    target_id = _validate_target_id(target_id)
    with _LOCK:
        targets = load_targets(workspace_id)
        for index, current in enumerate(targets):
            if current["id"] != target_id:
                continue
            candidate = dict(current)
            if clear_overrides:
                fields["ssvc_overrides"] = {}
            fields["input_revision"] = int(
                current.get("input_revision") or 0) + 1
            _apply_target_fields(candidate, fields)
            invalidate_result(target_id, workspace_id)
            targets[index] = candidate
            save_targets(targets, workspace_id)
            return candidate
        return None


def delete_target(target_id: str, workspace_id: str | None = None) -> bool:
    target_id = _validate_target_id(target_id)
    with _LOCK:
        targets = load_targets(workspace_id)
        removed_target = next(
            (target for target in targets if target["id"] == target_id), None)
        remaining = [t for t in targets if t["id"] != target_id]
        if len(remaining) == len(targets):
            return False
        directory = targets_dir(workspace_id)
        invalidate_result(target_id, workspace_id)
        source = Path(str((removed_target or {}).get("source_file") or ""))
        if (source.name.startswith(f"{target_id}_source")
                and source.parent.resolve() == directory.resolve()):
            source.unlink(missing_ok=True)
        # Remove legacy/content-addressed sources, including a harmless orphan
        # left by a process failure before the registry switch.
        for candidate in directory.glob(f"{target_id}_source*.json"):
            candidate.unlink(missing_ok=True)
        save_targets(remaining, workspace_id)
        return True


def get_target(target_id: str, workspace_id: str | None = None) -> dict | None:
    target_id = _validate_target_id(target_id)
    return next((t for t in load_targets(workspace_id) if t["id"] == target_id), None)


def _managed_source_path(value: str, directory: Path,
                         target_id: str | None = None) -> Path | None:
    path = Path(str(value or ""))
    try:
        valid_parent = path.parent.resolve() == directory.resolve()
    except OSError:
        return None
    if (not valid_parent or not _SOURCE_FILE.fullmatch(path.name)
            or (target_id is not None
                and not path.name.startswith(f"{target_id}_source"))):
        return None
    return path


def _workspace_source_disk_usage(directory: Path) -> int:
    """Count managed source bytes, including upgrade leftovers/orphans."""
    total = 0
    for candidate in directory.glob("*_source*.json"):
        if not _SOURCE_FILE.fullmatch(candidate.name):
            continue
        try:
            total += candidate.lstat().st_size
        except OSError:
            continue
    return total


def save_source(target_id: str, content: str, fmt: str = "",
                workspace_id: str | None = None, *, filename: str = "",
                source_kind: str = "upload",
                provenance: dict | None = None,
                max_workspace_source_bytes: int | None = None,
                target_updates: dict | None = None) -> Path:
    """Persist an uploaded scan/SBOM for a target and link it in the registry."""
    target_id = _validate_target_id(target_id)
    with _LOCK:
        previous = get_target(target_id, workspace_id)
        if previous is None:
            raise KeyError("no such target")
        encoded = content.encode("utf-8")
        directory = targets_dir(workspace_id)
        if max_workspace_source_bytes is not None:
            previous_path = _managed_source_path(
                str(previous.get("source_file") or ""), directory, target_id)
            replaceable_size = 0
            if previous_path is not None:
                try:
                    replaceable_size = previous_path.lstat().st_size
                except OSError:
                    pass
            current_total = max(
                0, _workspace_source_disk_usage(directory) - replaceable_size)
            if current_total + len(encoded) > max_workspace_source_bytes:
                raise SourceQuotaError(
                    "anonymous workspace evidence quota exceeded")
        digest = hashlib.sha256(encoded).hexdigest()
        # The registry atomically switches to immutable/content-addressed
        # bytes. A crash before that switch leaves the previous source valid.
        path = directory / f"{target_id}_source_{digest}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        try:
            updates = dict(target_updates or {})
            updates.update({
                "source_file": str(path),
                "source_format": fmt,
                "source_name": (filename or path.name)[:255],
                "source_sha256": digest,
                "source_size": len(encoded),
                "source_kind": source_kind,
                "source_provenance": provenance or {},
            })
            updated = update_target_inputs(
                target_id, workspace_id=workspace_id,
                clear_overrides=True,
                **updates,
            )
        except Exception:
            if str(previous.get("source_file") or "") != str(path):
                path.unlink(missing_ok=True)
            raise
        if updated is None:
            path.unlink(missing_ok=True)
            raise KeyError("no such target")
        # The registry already points at the immutable new source. Cleanup is
        # best-effort: a locked old file must not turn a successful commit into
        # a misleading HTTP 500. Any leftover remains included in disk quotas.
        for old_source in directory.glob(f"{target_id}_source*.json"):
            if old_source == path or not _SOURCE_FILE.fullmatch(old_source.name):
                continue
            try:
                old_source.unlink(missing_ok=True)
            except OSError:
                pass
        return path


def report_path(target_id: str, workspace_id: str | None = None) -> Path:
    """Return the legacy fixed report path (kept for upgrade compatibility)."""
    target_id = _validate_target_id(target_id)
    return targets_dir(workspace_id) / f"{target_id}_report.html"


def _generated_report_path(target_id: str, generation: str,
                           workspace_id: str | None = None) -> Path:
    target_id = _validate_target_id(target_id)
    if not re.fullmatch(r"[0-9a-f]{16}", generation):
        raise ValueError("invalid report generation")
    return targets_dir(workspace_id) / f"{target_id}_report_{generation}.html"


def summary_path(target_id: str, workspace_id: str | None = None) -> Path:
    target_id = _validate_target_id(target_id)
    return targets_dir(workspace_id) / f"{target_id}_summary.json"


def invalidate_result(target_id: str, workspace_id: str | None = None) -> None:
    """Remove derived artifacts after any evidence or context change."""
    target_id = _validate_target_id(target_id)
    with _LOCK:
        directory = targets_dir(workspace_id)
        # Delete the commit manifest first so no report remains addressable.
        summary_path(target_id, workspace_id).unlink(missing_ok=True)
        report_path(target_id, workspace_id).unlink(missing_ok=True)
        for candidate in directory.glob(f"{target_id}_report_*.html"):
            candidate.unlink(missing_ok=True)


def bump_input_revision(target_id: str, workspace_id: str | None = None,
                        *, clear_overrides: bool = False) -> dict | None:
    """Mark target context as changed and invalidate stale run artifacts."""
    return update_target_inputs(
        target_id, workspace_id=workspace_id,
        clear_overrides=clear_overrides)


def update_source_provenance_if_current(
        target_id: str, provenance: dict, expected_revision: int,
        expected_source_sha256: str,
        workspace_id: str | None = None) -> dict:
    """Attach coverage only when it describes the still-current evidence."""
    with _LOCK:
        target = get_target(target_id, workspace_id)
        if (target is None
                or int(target.get("input_revision") or 0) != expected_revision
                or str(target.get("source_sha256") or "") !=
                str(expected_source_sha256 or "")):
            raise StaleInputError(
                "target evidence or context changed while assessment was running")
        updated = update_target(
            target_id, workspace_id=workspace_id,
            source_provenance=provenance)
        if updated is None:
            raise StaleInputError("target was deleted while assessment was running")
        return updated


def save_run_artifacts(target_id: str, summary: dict, report_html: str,
                       expected_revision: int, expected_source_sha256: str,
                       workspace_id: str | None = None) -> None:
    """Atomically validate run inputs and publish its report plus summary."""
    target_id = _validate_target_id(target_id)
    with _LOCK:
        target = get_target(target_id, workspace_id)
        if target is None:
            raise StaleInputError("target was deleted while assessment was running")
        revision = int(target.get("input_revision") or 0)
        source_sha = str(target.get("source_sha256") or "")
        if (revision != int(expected_revision)
                or source_sha != str(expected_source_sha256 or "")):
            raise StaleInputError(
                "target evidence or context changed while assessment was "
                "running; the stale result was discarded")

        generation = uuid.uuid4().hex[:16]
        report = _generated_report_path(
            target_id, generation, workspace_id)
        report_tmp = report.with_suffix(".html.tmp")
        report_tmp.write_text(report_html, encoding="utf-8")
        report_tmp.replace(report)

        payload = dict(summary)
        payload["input_revision"] = revision
        payload["source_sha256"] = source_sha
        payload["assessed_at"] = time.time()
        payload["run_generation"] = generation
        payload["report_file"] = report.name
        summary_file = summary_path(target_id, workspace_id)
        summary_tmp = summary_file.with_suffix(".json.tmp")
        try:
            summary_tmp.write_text(
                json.dumps(payload, indent=2), encoding="utf-8")
            # This replace is the commit point. Until it succeeds, the old
            # summary still names the old immutable report.
            summary_tmp.replace(summary_file)
        except Exception:
            summary_tmp.unlink(missing_ok=True)
            report.unlink(missing_ok=True)
            raise
        legacy = report_path(target_id, workspace_id)
        legacy.unlink(missing_ok=True)
        for candidate in targets_dir(workspace_id).glob(
                f"{target_id}_report_*.html"):
            if candidate != report:
                candidate.unlink(missing_ok=True)


def load_summary(target_id: str, workspace_id: str | None = None) -> dict | None:
    """Return a current summary; stale artifacts are never rehydrated."""
    target_id = _validate_target_id(target_id)
    with _LOCK:
        target = get_target(target_id, workspace_id)
        path = summary_path(target_id, workspace_id)
        if target is None or not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if not isinstance(payload, dict):
            return None
        if payload.get("input_revision") != int(target.get("input_revision") or 0):
            return None
        if payload.get("source_sha256", "") != target.get("source_sha256", ""):
            return None
        report_file = payload.get("report_file")
        if report_file:
            generation_match = re.fullmatch(
                rf"{re.escape(target_id)}_report_([0-9a-f]{{16}})\.html",
                str(report_file),
            )
            if not generation_match:
                return None
            report = _generated_report_path(
                target_id, generation_match.group(1), workspace_id)
            if not report.exists():
                return None
        elif not report_path(target_id, workspace_id).exists():
            # Summaries created by older versions used the fixed report path.
            return None
        return payload


def current_report_path(target_id: str,
                        workspace_id: str | None = None) -> Path | None:
    """Resolve the report committed by the current validated summary."""
    target_id = _validate_target_id(target_id)
    with _LOCK:
        summary = load_summary(target_id, workspace_id)
        if summary is None:
            return None
        report_file = summary.get("report_file")
        if report_file:
            match = re.fullmatch(
                rf"{re.escape(target_id)}_report_([0-9a-f]{{16}})\.html",
                str(report_file),
            )
            if not match:
                return None
            report = _generated_report_path(
                target_id, match.group(1), workspace_id)
        else:
            report = report_path(target_id, workspace_id)
        return report if report.exists() else None


def load_current_report(target_id: str,
                        workspace_id: str | None = None) -> bytes | None:
    """Read the committed report under the same lock as invalidation."""
    with _LOCK:
        report = current_report_path(target_id, workspace_id)
        if report is None:
            return None
        try:
            return report.read_bytes()
        except OSError:
            return None


def cleanup_workspaces(max_age_seconds: int = 6 * 60 * 60,
                       *, exclude_workspace_ids: set[str] | None = None) -> int:
    """Delete expired anonymous GUI workspaces and their uploaded evidence."""
    root = cfgmod.config_dir() / "sessions"
    if not root.exists():
        return 0
    cutoff = time.time() - max_age_seconds
    excluded = {
        _clean_workspace_id(workspace_id)
        for workspace_id in (exclude_workspace_ids or set())
    }
    removed = 0
    with _LOCK:
        for directory in root.iterdir():
            if (not directory.is_dir()
                    or not _WORKSPACE_ID.fullmatch(directory.name)):
                continue
            if directory.name in excluded:
                continue
            try:
                if directory.stat().st_mtime < cutoff:
                    shutil.rmtree(directory)
                    removed += 1
            except OSError:
                continue
    return removed
