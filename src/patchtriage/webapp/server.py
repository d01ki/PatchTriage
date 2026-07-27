"""Standard-library HTTP server backing the PatchTriage GUI.

No web framework: one ThreadingHTTPServer + a small router. The browser reads
uploaded files client-side and POSTs their text as JSON, so there is no
multipart parsing. Binds to localhost only.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
import webbrowser
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import urlsplit

from .. import fleet as fleetmod
from .. import targets as tstore
from ..ingest.sbom import is_sbom
from ..ingest.parsers import sniff_format
from ..repository import (
    RepositoryAccessDeniedError,
    RepositoryError,
    RepositoryFetchError,
    RepositoryNotFoundError,
    RepositoryRateLimitError,
    RepositoryTooLargeError,
    fetch_repository_sbom,
    normalize_repository_url,
)
from ..repository_local import scan_public_repository
from ..triage.providers import has_ai_configuration, resolve_provider_name
from .page import INDEX_HTML
from .runner import MAX_WEB_SSVC_INPUTS, run_target

MAX_REQUEST_BYTES = int(os.environ.get("PATCHTRIAGE_MAX_REQUEST_BYTES", 20 * 1024 * 1024))
MAX_SOURCE_BYTES = int(os.environ.get("PATCHTRIAGE_MAX_SOURCE_BYTES", 16 * 1024 * 1024))
MAX_TARGETS_PER_SESSION = int(os.environ.get("PATCHTRIAGE_MAX_TARGETS", 25))
MAX_SESSION_SOURCE_BYTES = int(
    os.environ.get("PATCHTRIAGE_MAX_SESSION_SOURCE_BYTES", 64 * 1024 * 1024))
MAX_ACTIVE_JOBS_PER_SESSION = int(
    os.environ.get("PATCHTRIAGE_MAX_ACTIVE_JOBS_PER_SESSION", 3))
MAX_ACTIVE_JOBS_GLOBAL = int(
    os.environ.get("PATCHTRIAGE_MAX_ACTIVE_JOBS_GLOBAL", 20))
MAX_RETAINED_JOBS = int(os.environ.get("PATCHTRIAGE_MAX_RETAINED_JOBS", 500))
MAX_FLEET_IMPORT_REPOS = int(
    os.environ.get("PATCHTRIAGE_MAX_FLEET_IMPORT_REPOS", 15))
SESSION_COOKIE = "patchtriage_session"
SESSION_TTL_SECONDS = 6 * 60 * 60
_RUN_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_RUN_LOCKS_GUARD = threading.Lock()
_JOB_LOCK = threading.RLock()
_JOBS: dict[str, dict] = {}
_RUN_SLOTS = threading.BoundedSemaphore(
    max(1, int(os.environ.get("PATCHTRIAGE_MAX_CONCURRENT_RUNS", 2))))
_IMPORT_SLOTS = threading.BoundedSemaphore(
    max(1, int(os.environ.get("PATCHTRIAGE_MAX_CONCURRENT_IMPORTS", 2))))

try:
    APP_VERSION = version("patchtriage")
except PackageNotFoundError:
    APP_VERSION = "development"


def _validate_backend(backend: str) -> str:
    allowed = {"rules"}
    if has_ai_configuration():
        allowed.update(("ai", "cascade"))
        # Existing API clients may still send the pre-0.7 backend name.
        if resolve_provider_name() == "anthropic":
            allowed.add("claude")
    if backend not in allowed:
        raise RequestError("backend is not available")
    return backend


def _generic_repository_enabled() -> bool:
    mode = os.environ.get("PATCHTRIAGE_DEPLOYMENT_MODE", "local").lower()
    enabled = os.environ.get(
        "PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES", "false").lower()
    return mode != "public" and enabled in {"1", "true", "yes", "on"}


def _github_import_token() -> str | None:
    """Keep the anonymous hosted importer strictly public-only.

    A token configured for advisory enrichment can also grant access to private
    repositories.  Passing it through an anonymous public endpoint would let a
    caller probe repositories that the service account can read.  Local/Docker
    deployments remain able to use their own token for rate limits or private
    workspaces under the operator's control.
    """
    mode = os.environ.get("PATCHTRIAGE_DEPLOYMENT_MODE", "local").lower()
    if mode == "public":
        return None
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _exception_message(exc: Exception) -> str:
    """Avoid exposing server paths or connector internals on the public GUI."""
    if os.environ.get(
            "PATCHTRIAGE_DEPLOYMENT_MODE", "local").lower() == "public":
        return "assessment failed; retry or use a local deployment for diagnostics"
    return f"{type(exc).__name__}: {exc}"


def _public_job(job: dict) -> dict:
    # Workers mutate job state asynchronously. Snapshot under the same lock so
    # HTTP serialization never iterates a changing dictionary.
    with _JOB_LOCK:
        snapshot = dict(job)
    workspace = snapshot.pop("workspace", "")
    if snapshot.get("state") == "succeeded":
        summary = tstore.load_summary(snapshot["target_id"], workspace)
        if summary is None:
            snapshot["state"] = "failed"
            snapshot["error"] = "completed assessment summary is unavailable"
        else:
            snapshot["summary"] = summary
    return snapshot


def _prune_jobs_locked() -> None:
    """Prune terminal jobs by age/count; never orphan an active worker."""
    cutoff = time.time() - SESSION_TTL_SECONDS
    terminal = [
        (job_id, job) for job_id, job in _JOBS.items()
        if job.get("state") in {"succeeded", "failed"}
    ]
    for job_id, job in terminal:
        if job.get("finished_at", 0) < cutoff:
            _JOBS.pop(job_id, None)
    terminal = sorted(
        ((job_id, job) for job_id, job in _JOBS.items()
         if job.get("state") in {"succeeded", "failed"}),
        key=lambda item: item[1].get("finished_at", 0),
        reverse=True,
    )
    for job_id, _job in terminal[max(1, MAX_RETAINED_JOBS):]:
        _JOBS.pop(job_id, None)


def _cleanup_expired_workspaces() -> int:
    with _JOB_LOCK:
        active_workspaces = {
            job["workspace"] for job in _JOBS.values()
            if job.get("state") in {"queued", "running"}
        }
    return tstore.cleanup_workspaces(
        SESSION_TTL_SECONDS, exclude_workspace_ids=active_workspaces)


def _execute_job(job_id: str) -> None:
    with _JOB_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        workspace = job["workspace"]
        target_id = job["target_id"]
        backend = job["backend"]
        job["state"] = "queued"
    try:
        with _RUN_SLOTS:
            with _JOB_LOCK:
                job = _JOBS.get(job_id)
                if not job:
                    return
                job["state"] = "running"
                job["started_at"] = time.time()
            target = tstore.get_target(target_id, workspace)
            if not target:
                raise ValueError("target was deleted before the run started")
            with _RUN_LOCKS_GUARD:
                run_lock = _RUN_LOCKS.setdefault(
                    (workspace, target_id), threading.Lock())
            with run_lock:
                run_target(
                    target, backend=backend, use_nvd=True,
                    nvd_api_key=os.environ.get("NVD_API_KEY"),
                    workspace_id=workspace,
                )
            with _JOB_LOCK:
                job = _JOBS.get(job_id)
                if job:
                    job.update(state="succeeded", finished_at=time.time())
                    _prune_jobs_locked()
    except Exception as exc:
        with _JOB_LOCK:
            job = _JOBS.get(job_id)
            if job:
                job.update(state="failed",
                           error=_exception_message(exc),
                           finished_at=time.time())
                _prune_jobs_locked()


def _start_job(workspace: str, target_id: str, backend: str) -> dict:
    with _JOB_LOCK:
        _prune_jobs_locked()
        active = next((job for job in _JOBS.values()
                       if job["workspace"] == workspace
                       and job["target_id"] == target_id
                       and job["state"] in {"queued", "running"}), None)
        if active:
            return active
        active_jobs = [job for job in _JOBS.values()
                       if job["state"] in {"queued", "running"}]
        if len(active_jobs) >= MAX_ACTIVE_JOBS_GLOBAL:
            raise RequestError("assessment queue is full; retry later", 429)
        if sum(job["workspace"] == workspace for job in active_jobs) >= \
                MAX_ACTIVE_JOBS_PER_SESSION:
            raise RequestError(
                "anonymous workspace assessment limit reached; wait for an "
                "active run to finish", 429)
        job_id = secrets.token_hex(12)
        job = {
            "job_id": job_id, "workspace": workspace,
            "target_id": target_id, "backend": backend,
            "state": "queued", "created_at": time.time(),
        }
        _JOBS[job_id] = job
    threading.Thread(target=_execute_job, args=(job_id,), daemon=True).start()
    return job


class RequestError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _detect_format(content: str) -> str:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return ""
    return is_sbom(data) or sniff_format(data) or ""


def _public_target(target: dict | None) -> dict | None:
    """Return GUI-safe target metadata without server paths or overrides."""
    if target is None:
        return None
    result = dict(target)
    result["source_file"] = bool(result.get("source_file"))
    result.pop("ssvc_overrides", None)
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "PatchTriage"

    # ------------------------------------------------------------ helpers
    def _workspace(self) -> str:
        existing = getattr(self, "_workspace_id", None)
        if existing:
            return existing
        value = ""
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get(SESSION_COOKIE)
            value = morsel.value if morsel else ""
        except CookieError:
            value = ""
        if not re.fullmatch(r"[0-9a-f]{32}", value):
            value = secrets.token_hex(16)
            _cleanup_expired_workspaces()
        tstore.touch_workspace(value)
        self._workspace_id = value
        return value

    def _session_cookie(self) -> str:
        value = self._workspace()
        secure_mode = os.environ.get(
            "PATCHTRIAGE_COOKIE_SECURE", "auto").strip().lower()
        if secure_mode not in {"auto", "true", "false"}:
            secure_mode = "auto"
        forwarded_proto = self.headers.get(
            "X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        is_secure = (secure_mode == "true" or
                     secure_mode == "auto" and forwarded_proto == "https")
        secure = "; Secure" if is_secure else ""
        return (
            f"{SESSION_COOKIE}={value}; Path=/; Max-Age={SESSION_TTL_SECONDS}; "
            f"HttpOnly; SameSite=Strict{secure}"
        )

    def _security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", self._session_cookie())
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'",
        )

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send(self, body: bytes, ctype="text/html; charset=utf-8", status=200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if content_type != "application/json":
            raise RequestError("Content-Type must be application/json", 415)
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError as exc:
            raise RequestError("invalid Content-Length") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise RequestError("request body is too large", 413)
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RequestError("request body must be valid UTF-8 JSON") from exc
        if not isinstance(body, dict):
            raise RequestError("request body must be a JSON object")
        return body

    def _origin_allowed(self) -> bool:
        """Reject browser cross-site writes while allowing non-browser clients."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlsplit(origin)
        host = self.headers.get("Host", "")
        return parsed.scheme in ("http", "https") and parsed.netloc.lower() == host.lower()

    def log_message(self, *args):  # quiet by default
        pass

    # ------------------------------------------------------------ routing
    def _guard(self, fn):
        """Never drop the connection on an unhandled error — return JSON 500
        so the browser shows a message instead of a dead request."""
        try:
            fn()
        except RequestError as exc:
            self._send_json({"error": str(exc)}, exc.status)
        except BrokenPipeError:
            raise
        except Exception as exc:
            try:
                self._send_json({"error": _exception_message(exc)}, 500)
            except Exception:
                pass

    def do_GET(self):
        self._guard(self._do_GET)

    def do_POST(self):
        if not self._origin_allowed():
            return self._send_json({"error": "cross-origin request rejected"}, 403)
        self._guard(self._do_POST)

    def do_DELETE(self):
        if not self._origin_allowed():
            return self._send_json({"error": "cross-origin request rejected"}, 403)
        self._guard(self._do_DELETE)

    def _do_GET(self):
        workspace = self._workspace()
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(INDEX_HTML.encode("utf-8"))
        if path == "/api/config":
            has_ai = has_ai_configuration()
            backends = ["rules"] + (["ai", "cascade"] if has_ai else [])
            generic_repositories = _generic_repository_enabled()
            return self._send_json({
                "backends": backends,
                "has_key": has_ai,
                "has_ai": has_ai,
                "ai_provider": resolve_provider_name() if has_ai else None,
                "capabilities": ["offline-demo", "ssvc-deployer",
                                 "epss-baseline", "kev-baseline",
                                 "reachability", "runtime-context",
                                 "vendor-advisories", "async-runs",
                                 "github-repository-sbom",
                                 "fleet-import"],
                "version": APP_VERSION,
                "build_sha": os.environ.get("PATCHTRIAGE_BUILD_SHA", "development"),
                "ui_schema_version": 2,
                "deployment_mode": os.environ.get(
                    "PATCHTRIAGE_DEPLOYMENT_MODE", "local"),
                "repository_import": {
                    "github": "dependency-graph-sbom",
                    "github_private_with_token": bool(
                        _github_import_token()),
                    "generic_https_git": (
                        "local-osv-scanner" if generic_repositories
                        else "unavailable"),
                    "executes_repository_code": False,
                },
                "data_isolation": "anonymous-session",
                "retention_hours": SESSION_TTL_SECONDS // 3600,
                "limits": {
                    "targets": MAX_TARGETS_PER_SESSION,
                    "source_bytes": MAX_SOURCE_BYTES,
                    "session_source_bytes": MAX_SESSION_SOURCE_BYTES,
                    "active_jobs_per_session": MAX_ACTIVE_JOBS_PER_SESSION,
                    "ssvc_review_rows": MAX_WEB_SSVC_INPUTS,
                    "fleet_import_repos": MAX_FLEET_IMPORT_REPOS,
                },
                "connectors": {
                    "msrc": "public", "rhsa": "public", "usn": "public",
                    "debian": "public",
                    "ghsa": ("token" if (os.environ.get("GITHUB_TOKEN") or
                                           os.environ.get("GH_TOKEN"))
                             else "public-rate-limit"),
                },
            })
        if path == "/api/targets":
            return self._send_json([
                _public_target(target)
                for target in tstore.load_targets(workspace)
            ])
        if path == "/api/summaries":
            summaries = []
            for target in tstore.load_targets(workspace):
                summary = tstore.load_summary(target["id"], workspace)
                if summary:
                    summaries.append(summary)
            return self._send_json(summaries)
        if path == "/api/fleet/summary":
            return self._send_json(fleetmod.aggregate_fleet(workspace))
        if path == "/api/jobs":
            with _JOB_LOCK:
                visible_jobs = [
                    job
                    for job in _JOBS.values()
                    if job["workspace"] == workspace
                    and job["state"] in {"queued", "running"}
                ]
            jobs = [_public_job(job) for job in visible_jobs]
            return self._send_json(jobs)
        m = re.fullmatch(r"/api/jobs/([0-9a-f]{24})", path)
        if m:
            with _JOB_LOCK:
                job = _JOBS.get(m.group(1))
                if not job or job["workspace"] != workspace:
                    return self._send_json({"error": "no such job"}, 404)
            return self._send_json(_public_job(job))
        m = re.fullmatch(r"/report/([0-9a-f]{12})", path)
        if m:
            report = tstore.load_current_report(m.group(1), workspace)
            if report is not None:
                return self._send(report)
            return self._send(b"report not generated yet", status=404)
        return self._send(b"not found", status=404)

    def _do_POST(self):
        workspace = self._workspace()
        path = self.path.split("?", 1)[0]
        if path == "/api/demo":
            self._read_json()
            existing = next(
                (target for target in tstore.load_targets(workspace)
                 if target.get("demo")),
                None,
            )
            created = existing is None
            try:
                target = existing or tstore.add_target(
                    name="Demo",
                    criticality="critical",
                    internet_exposed=True,
                    reachable=True,
                    runtime_observed=True,
                    system_exposure="open",
                    mission_impact="mef_failure",
                    safety_impact="critical",
                    context_sources=["OpenTelemetry", "Falco"],
                    demo=True,
                    workspace_id=workspace,
                    max_targets=MAX_TARGETS_PER_SESSION,
                )
            except tstore.TargetLimitError as exc:
                return self._send_json({"error": str(exc)}, 429)
            fixture = (resources.files("patchtriage") / "data" / "fixtures"
                       / "trivy_sample.json")
            try:
                tstore.save_source(
                    target["id"], fixture.read_text(encoding="utf-8"), "trivy",
                    workspace_id=workspace, filename="trivy_sample.json",
                    source_kind="demo",
                    provenance={
                        "provider": "bundled-demo", "offline": True,
                        "coverage": {"status": "complete",
                                     "reason": "Bundled scanner fixture"},
                    },
                    max_workspace_source_bytes=MAX_SESSION_SOURCE_BYTES,
                    target_updates={
                        "criticality": "critical",
                        "internet_exposed": True,
                        "reachable": True,
                        "runtime_observed": True,
                        "system_exposure": "open",
                        "mission_impact": "mef_failure",
                        "safety_impact": "critical",
                        "context_sources": ["OpenTelemetry", "Falco"],
                        "ssvc_overrides": {},
                    },
                )
            except tstore.SourceQuotaError as exc:
                if created:
                    tstore.delete_target(target["id"], workspace)
                return self._send_json({"error": str(exc)}, 413)
            target = tstore.get_target(target["id"], workspace)
            return self._send_json(
                _public_target(target), 201 if created else 200)

        if path == "/api/targets":
            body = self._read_json()
            if not body.get("name"):
                return self._send_json({"error": "name is required"}, 400)
            if len(tstore.load_targets(workspace)) >= MAX_TARGETS_PER_SESSION:
                return self._send_json(
                    {"error": f"target limit reached ({MAX_TARGETS_PER_SESSION})"},
                    429)
            try:
                t = tstore.add_target(
                    name=body["name"], url=body.get("url", ""),
                    criticality=body.get("criticality", "unknown"),
                    internet_exposed=body.get("internet_exposed"),
                    reachable=body.get("reachable"),
                    runtime_observed=body.get("runtime_observed"),
                    system_exposure=body.get("system_exposure", "unknown"),
                    mission_impact=body.get("mission_impact", "unknown"),
                    safety_impact=body.get("safety_impact", "unknown"),
                    context_sources=body.get("context_sources"),
                    workspace_id=workspace,
                    max_targets=MAX_TARGETS_PER_SESSION,
                )
            except tstore.TargetLimitError as exc:
                return self._send_json({"error": str(exc)}, 429)
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, 400)
            return self._send_json(_public_target(t), 201)

        if path == "/api/fleet/import":
            body = self._read_json()
            owner_url = body.get("owner_url")
            if not isinstance(owner_url, str) or not owner_url.strip():
                return self._send_json({"error": "owner_url is required"}, 400)
            try:
                limit = int(body.get("limit") or MAX_FLEET_IMPORT_REPOS)
            except (TypeError, ValueError):
                return self._send_json({"error": "limit must be a number"}, 400)
            limit = max(1, min(limit, MAX_FLEET_IMPORT_REPOS))
            context = {
                key: body[key]
                for key in fleetmod.FLEET_CONTEXT_FIELDS
                if isinstance(body.get(key), str)
            }
            if not _IMPORT_SLOTS.acquire(blocking=False):
                return self._send_json(
                    {"error": "repository import capacity is busy; retry later"},
                    429,
                )
            try:
                try:
                    report = fleetmod.import_fleet(
                        owner_url,
                        workspace_id=workspace,
                        limit=limit,
                        include_forks=bool(body.get("include_forks")),
                        include_archived=bool(body.get("include_archived")),
                        github_token=_github_import_token(),
                        context=context,
                        max_targets=MAX_TARGETS_PER_SESSION,
                        max_workspace_source_bytes=MAX_SESSION_SOURCE_BYTES,
                    )
                except RepositoryRateLimitError as exc:
                    return self._send_json({"error": str(exc)}, 429)
                except RepositoryAccessDeniedError as exc:
                    return self._send_json({"error": str(exc)}, 403)
                except RepositoryNotFoundError as exc:
                    return self._send_json({"error": str(exc)}, 404)
                except RepositoryFetchError as exc:
                    return self._send_json({"error": str(exc)}, 502)
                except RepositoryError as exc:
                    return self._send_json({"error": str(exc)}, 400)
                except ValueError as exc:
                    return self._send_json({"error": str(exc)}, 400)
            finally:
                _IMPORT_SLOTS.release()
            return self._send_json(report)

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/context", path)
        if m:
            if not tstore.get_target(m.group(1), workspace):
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            allowed = {
                "criticality", "internet_exposed", "reachable",
                "runtime_observed", "system_exposure",
                "mission_impact", "safety_impact", "context_sources",
            }
            try:
                target = tstore.update_target_inputs(
                    m.group(1), workspace_id=workspace,
                    **{key: value for key, value in body.items()
                       if key in allowed})
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, 400)
            return self._send_json(_public_target(target))

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/ssvc-inputs", path)
        if m:
            target = tstore.get_target(m.group(1), workspace)
            if not target:
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            inputs = body.get("inputs")
            if not isinstance(inputs, list) or len(inputs) > 1000:
                return self._send_json(
                    {"error": "inputs must be a list of at most 1000 items"}, 400)
            overrides = dict(target.get("ssvc_overrides") or {})
            for item in inputs:
                if not isinstance(item, dict):
                    return self._send_json({"error": "invalid SSVC input"}, 400)
                key = str(item.get("finding_key") or "")
                if not key or len(key) > 512:
                    return self._send_json({"error": "invalid finding key"}, 400)
                values = {}
                exploitation = item.get("exploitation", "auto")
                automatable = item.get("automatable", "auto")
                if exploitation != "auto":
                    if exploitation not in {"none", "public_poc", "active"}:
                        return self._send_json(
                            {"error": "invalid Exploitation value"}, 400)
                    values["exploitation"] = exploitation
                if automatable != "auto":
                    if automatable not in {"no", "yes"}:
                        return self._send_json(
                            {"error": "invalid Automatable value"}, 400)
                    values["automatable"] = automatable
                if values:
                    overrides[key] = values
                else:
                    overrides.pop(key, None)
            target = tstore.update_target_inputs(
                m.group(1), workspace_id=workspace,
                ssvc_overrides=overrides)
            return self._send_json({"ok": True, "overrides": len(overrides)})

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/source", path)
        if m:
            if not tstore.get_target(m.group(1), workspace):
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            content = body.get("content", "")
            if not content:
                return self._send_json({"error": "empty file"}, 400)
            if not isinstance(content, str):
                return self._send_json({"error": "content must be text"}, 400)
            size = len(content.encode("utf-8"))
            if size > MAX_SOURCE_BYTES:
                return self._send_json(
                    {"error": f"evidence exceeds the {MAX_SOURCE_BYTES} byte limit"},
                    413)
            fmt = _detect_format(content)
            if not fmt:
                return self._send_json(
                    {"error": "unrecognized file — expected Trivy/Grype/OSV "
                              "JSON or a CycloneDX/SPDX SBOM"}, 400)
            filename = str(body.get("filename") or "evidence.json")[:255]
            try:
                tstore.save_source(
                    m.group(1), content, fmt, workspace,
                    filename=filename, source_kind="upload",
                    provenance={
                        "provider": "upload",
                        "filename": filename,
                        "coverage_status": "provider_reported",
                        "coverage": {
                            "status": (
                                "unknown" if fmt in {"spdx", "cyclonedx"}
                                else "provider_reported"),
                            "reason": (
                                "SBOM component query coverage is evaluated during the run"
                                if fmt in {"spdx", "cyclonedx"} else
                                "Scanner result consumed as supplied; PatchTriage "
                                "cannot verify the scanner invocation's scope"
                            ),
                        },
                    },
                    max_workspace_source_bytes=MAX_SESSION_SOURCE_BYTES,
                )
            except tstore.SourceQuotaError as exc:
                return self._send_json({"error": str(exc)}, 413)
            except KeyError:
                return self._send_json({"error": "no such target"}, 404)
            target = tstore.get_target(m.group(1), workspace) or {}
            return self._send_json({
                "ok": True, "format": fmt, "filename": filename,
                "sha256": target.get("source_sha256", ""), "size": size,
            })

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/repository", path)
        if m:
            target = tstore.get_target(m.group(1), workspace)
            if not target:
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            repository_url = body.get("repository_url")
            if not isinstance(repository_url, str) or not repository_url.strip():
                return self._send_json(
                    {"error": "repository_url is required"}, 400)
            if not _IMPORT_SLOTS.acquire(blocking=False):
                return self._send_json(
                    {"error": "repository import capacity is busy; retry later"},
                    429,
                )
            try:
                try:
                    reference = normalize_repository_url(repository_url)
                    if reference.provider == "github":
                        imported = fetch_repository_sbom(
                            reference,
                            github_token=_github_import_token(),
                            max_bytes=MAX_SOURCE_BYTES,
                        )
                        content = imported.content
                        fmt = "spdx"
                        provenance = imported.provenance.to_dict()
                    elif _generic_repository_enabled():
                        scanned = scan_public_repository(
                            reference.normalized_url,
                            max_output_bytes=MAX_SOURCE_BYTES,
                        )
                        content = scanned.content
                        fmt = scanned.format
                        provenance = scanned.provenance
                    else:
                        raise RepositoryError(
                            "this deployment imports public GitHub repositories; "
                            "generic HTTPS Git scanning is available only in an "
                            "explicitly enabled local/Docker deployment")
                except RepositoryRateLimitError as exc:
                    return self._send_json({"error": str(exc)}, 429)
                except RepositoryAccessDeniedError as exc:
                    return self._send_json({"error": str(exc)}, 403)
                except RepositoryNotFoundError as exc:
                    return self._send_json({"error": str(exc)}, 404)
                except RepositoryTooLargeError as exc:
                    return self._send_json({"error": str(exc)}, 413)
                except RepositoryFetchError as exc:
                    return self._send_json({"error": str(exc)}, 502)
                except RepositoryError as exc:
                    return self._send_json({"error": str(exc)}, 400)
            finally:
                _IMPORT_SLOTS.release()
            size = len(content.encode("utf-8"))
            if size > MAX_SOURCE_BYTES:
                return self._send_json(
                    {"error": f"repository evidence exceeds the "
                              f"{MAX_SOURCE_BYTES} byte limit"}, 413)
            filename = (
                provenance["repository"].replace("/", "_") + f".{fmt}.json")
            try:
                tstore.save_source(
                    target["id"], content, fmt, workspace,
                    filename=filename, source_kind="repository",
                    provenance=provenance,
                    max_workspace_source_bytes=MAX_SESSION_SOURCE_BYTES,
                )
            except tstore.SourceQuotaError as exc:
                return self._send_json({"error": str(exc)}, 413)
            except KeyError:
                return self._send_json({"error": "no such target"}, 404)
            refreshed = tstore.get_target(target["id"], workspace) or target
            return self._send_json({
                "ok": True, "format": fmt, "filename": filename,
                "sha256": refreshed.get("source_sha256", ""),
                "size": size, "provenance": provenance,
            })

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/runs", path)
        if m:
            target = tstore.get_target(m.group(1), workspace)
            if not target:
                return self._send_json({"error": "no such target"}, 404)
            if not target.get("source_file"):
                return self._send_json(
                    {"error": "no scan, SBOM, or repository evidence attached"},
                    400)
            body = self._read_json()
            try:
                backend = _validate_backend(str(body.get("backend", "rules")))
            except RequestError as exc:
                return self._send_json({"error": str(exc)}, exc.status)
            job = _start_job(workspace, target["id"], backend)
            return self._send_json(_public_job(job), 202)

        # Backwards-compatible synchronous endpoint for scripts. The GUI uses
        # /runs and polling so reverse-proxy request timeouts do not interrupt
        # a long enrichment or AI assessment.
        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/run", path)
        if m:
            if os.environ.get(
                    "PATCHTRIAGE_DEPLOYMENT_MODE", "local").lower() == "public":
                return self._send_json({
                    "error": "synchronous runs are disabled in public mode; "
                             "use /runs and poll the returned job",
                }, 410)
            target = tstore.get_target(m.group(1), workspace)
            if not target:
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            try:
                backend = _validate_backend(str(body.get("backend", "rules")))
            except RequestError as exc:
                return self._send_json({"error": str(exc)}, exc.status)
            if not _RUN_SLOTS.acquire(blocking=False):
                return self._send_json(
                    {"error": "assessment capacity is busy; retry later"}, 429)
            try:
                with _RUN_LOCKS_GUARD:
                    run_lock = _RUN_LOCKS.setdefault(
                        (workspace, target["id"]), threading.Lock())
                with run_lock:
                    summary = run_target(
                        target, backend=backend,
                        use_nvd=True,
                        nvd_api_key=os.environ.get("NVD_API_KEY"),
                        workspace_id=workspace)
            except Exception as exc:  # surface to the UI, don't 500 blindly
                return self._send_json(
                    {"error": _exception_message(exc)}, 400)
            finally:
                _RUN_SLOTS.release()
            return self._send_json(summary)

        return self._send_json({"error": "not found"}, 404)

    def _do_DELETE(self):
        workspace = self._workspace()
        m = re.fullmatch(
            r"/api/targets/([0-9a-f]{12})", self.path.split("?", 1)[0])
        if m:
            with _JOB_LOCK:
                active = any(
                    job["workspace"] == workspace
                    and job["target_id"] == m.group(1)
                    and job["state"] in {"queued", "running"}
                    for job in _JOBS.values()
                )
            if active:
                return self._send_json(
                    {"error": "target has an active assessment"}, 409)
            if not tstore.delete_target(m.group(1), workspace):
                return self._send_json({"error": "no such target"}, 404)
            with _RUN_LOCKS_GUARD:
                _RUN_LOCKS.pop((workspace, m.group(1)), None)
            self.send_response(204)
            self._security_headers()
            self.end_headers()
            return
        return self._send_json({"error": "not found"}, 404)


def serve(host: str = "127.0.0.1", port: int = 8765,
          open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    stop_sweeper = threading.Event()

    def sweep_expired_workspaces() -> None:
        while not stop_sweeper.wait(10 * 60):
            _cleanup_expired_workspaces()

    threading.Thread(target=sweep_expired_workspaces, daemon=True).start()
    url = f"http://{host}:{port}/"
    print(f"PatchTriage console: {url}  (Ctrl-C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        stop_sweeper.set()
        httpd.server_close()
