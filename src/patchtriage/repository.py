"""Repository URL normalization and provider-backed SBOM retrieval.

The GitHub provider deliberately uses the Dependency Graph SBOM API instead
of cloning or executing repository content.  Generic HTTPS Git URLs can be
normalized for use by another provider, but this module never fetches them.

An exported SBOM describes the dependencies GitHub knows about.  It is useful
input, not evidence that every manifest was discovered or that a repository is
free of vulnerabilities.  The returned provenance makes that boundary
explicit.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import httpx

from .ingest.sbom import _purl_from_spdx_pkg
from .ingest.versions import declared_constraints, is_manifest, pypi_key
from .models import parse_purl


GITHUB_HOST = "github.com"
GITHUB_API_ROOT = "https://api.github.com"
GITHUB_API_HOST = "api.github.com"
GITHUB_RAW_ROOT = "https://raw.githubusercontent.com"
GITHUB_API_VERSION = "2026-03-10"
GITHUB_USER_AGENT = "patchtriage/0.6"
# GitHub does not document this origin; it was observed on the 302 from
# fetch-report on 2026-11-08. *.blob.core.windows.net is multi-tenant, so only
# the exact host is allowed. If GitHub moves exports, imports fail closed with
# an "unapproved location" error and this set needs updating.
GITHUB_SBOM_DOWNLOAD_HOSTS = frozenset({"dgpproduction.blob.core.windows.net"})
SBOM_POLL_DEADLINE_SECONDS = 60.0
SBOM_POLL_MAX_ATTEMPTS = 20
SBOM_POLL_MAX_DELAY_SECONDS = 10.0
SBOM_POLL_TRANSIENT_RETRIES = 2
SBOM_DOWNLOAD_DEADLINE_SECONDS = 120.0
_TRANSIENT_POLL_STATUSES = frozenset({500, 502, 503, 504})
MAX_SBOM_LINK_BYTES = 64 * 1024
DEFAULT_MAX_SBOM_BYTES = 32 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 45.0
MAX_TREE_BYTES = 16 * 1024 * 1024
MAX_MANIFESTS = 40
MAX_MANIFEST_BYTES = 1024 * 1024

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_SEGMENT_SAFE = "-._~!$&'()*+,;=:@"
_REPORT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")


class _SignedDownloadLogFilter(logging.Filter):
    """Keep httpx's request log line from recording a signed download URL."""

    def filter(self, record: logging.LogRecord) -> bool:
        text = f"{record.msg} {record.args}"
        return not any(host in text for host in GITHUB_SBOM_DOWNLOAD_HOSTS)


logging.getLogger("httpx").addFilter(_SignedDownloadLogFilter())


class RepositoryError(Exception):
    """Base class for repository import failures."""


class RepositoryURLValidationError(RepositoryError, ValueError):
    """The supplied URL is not an unambiguous HTTPS repository URL."""


class UnsupportedRepositoryProvider(RepositoryError):
    """The URL is valid, but no retrieval provider is available for it."""


class RepositoryFetchError(RepositoryError):
    """The provider could not be reached or returned an unexpected response."""


class RepositoryNotFoundError(RepositoryFetchError):
    """The repository or its provider-generated SBOM was not found."""


class RepositoryAccessDeniedError(RepositoryFetchError):
    """The provider rejected authentication or access."""


class RepositoryRateLimitError(RepositoryFetchError):
    """The provider rate limit was reached."""

    def __init__(self, message: str, *, retry_after: str | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class RepositoryResponseError(RepositoryFetchError):
    """The provider returned malformed or unsupported SBOM data."""


class RepositoryTooLargeError(RepositoryResponseError):
    """The provider response exceeded the configured size limit."""


@dataclass(frozen=True)
class RepositoryReference:
    """A normalized repository reference without credentials or query data."""

    original_url: str
    normalized_url: str
    provider: str
    host: str
    repository: str
    owner: str | None = None
    name: str | None = None
    ref: str | None = None
    selector: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RepositoryProvenance:
    """Where an imported SBOM came from and what it can substantiate."""

    provider: str
    repository: str
    ref: str
    resolved_url: str
    api_url: str
    format: str
    component_count: int
    coverage_status: str
    warnings: tuple[str, ...]
    retrieved_at: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["warnings"] = list(self.warnings)
        return data


@dataclass(frozen=True)
class RepositorySbom:
    """Serialized SPDX content suitable for the existing SBOM ingest path."""

    content: str
    provenance: RepositoryProvenance


def _canonical_host(host: str) -> str:
    try:
        canonical = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise RepositoryURLValidationError(
            "repository URL contains an invalid host name") from exc
    if not canonical or canonical.endswith("."):
        raise RepositoryURLValidationError(
            "repository URL must contain an unambiguous host name")
    return canonical


def _decoded_segments(path: str) -> list[str]:
    if "\\" in path or _BAD_PERCENT_RE.search(path):
        raise RepositoryURLValidationError(
            "repository URL contains an invalid path encoding")
    segments: list[str] = []
    for raw_segment in path.split("/"):
        if not raw_segment:
            continue
        segment = unquote(raw_segment)
        if (segment in (".", "..") or "/" in segment or "\\" in segment
                or any(ord(char) < 32 or ord(char) == 127
                       for char in segment)):
            raise RepositoryURLValidationError(
                "repository URL contains an unsafe path segment")
        segments.append(segment)
    return segments


def _encoded_path(segments: list[str]) -> str:
    return "/" + "/".join(quote(segment, safe=_SEGMENT_SAFE)
                            for segment in segments)


def normalize_repository_url(value: str) -> RepositoryReference:
    """Validate and canonicalize a GitHub or generic HTTPS Git URL.

    GitHub URLs resolve to their repository root.  A ``tree/<ref>`` suffix is
    retained as requested provenance, although GitHub's Dependency Graph SBOM
    endpoint itself cannot promise a ref-specific snapshot.

    Generic HTTPS URLs are normalized only.  They remain unsupported by
    :func:`fetch_repository_sbom`, which prevents this module from becoming an
    arbitrary outbound request or clone primitive.
    """
    if not isinstance(value, str) or not value.strip():
        raise RepositoryURLValidationError("repository URL is required")
    candidate = value.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        raise RepositoryURLValidationError(
            "repository URL contains control characters")
    if "\\" in candidate:
        raise RepositoryURLValidationError(
            "repository URL must use forward slashes")

    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise RepositoryURLValidationError(
            "repository URL is malformed") from exc
    if parsed.scheme.lower() != "https":
        raise RepositoryURLValidationError(
            "repository URL must use HTTPS")
    if not parsed.netloc or not parsed.hostname:
        raise RepositoryURLValidationError(
            "repository URL must include a host name")
    if parsed.username is not None or parsed.password is not None:
        raise RepositoryURLValidationError(
            "repository URL must not contain user information")
    if parsed.fragment:
        raise RepositoryURLValidationError(
            "repository URL must not contain a fragment")
    if parsed.query:
        raise RepositoryURLValidationError(
            "repository URL must not contain query parameters")

    host = _canonical_host(parsed.hostname)
    segments = _decoded_segments(parsed.path)
    if not segments:
        raise RepositoryURLValidationError(
            "repository URL must include a repository path")

    if host == GITHUB_HOST:
        if port not in (None, 443):
            raise RepositoryURLValidationError(
                "github.com repository URLs may not use a custom port")
        if len(segments) < 2:
            raise RepositoryURLValidationError(
                "GitHub URL must include both owner and repository")
        owner, name = segments[0], segments[1]
        if name.lower().endswith(".git"):
            name = name[:-4]
        if not _OWNER_RE.fullmatch(owner) or "--" in owner:
            raise RepositoryURLValidationError(
                "GitHub URL contains an invalid owner name")
        if (not _REPOSITORY_RE.fullmatch(name)
                or name in (".", "..") or name.endswith(".git")):
            raise RepositoryURLValidationError(
                "GitHub URL contains an invalid repository name")

        ref: str | None = None
        selector: str | None = None
        extra = segments[2:]
        if extra:
            selector = extra[0].lower()
            if selector != "tree" or len(extra) < 2:
                raise RepositoryURLValidationError(
                    "GitHub URL must point to the repository root or tree/<ref>")
            ref = "/".join(extra[1:])
        normalized = f"https://{GITHUB_HOST}/{owner}/{name}"
        return RepositoryReference(
            original_url=candidate,
            normalized_url=normalized,
            provider="github",
            host=host,
            repository=f"{owner}/{name}",
            owner=owner,
            name=name,
            ref=ref,
            selector=selector,
        )

    if len(segments) < 2:
        raise RepositoryURLValidationError(
            "generic Git repository URL must include a repository path")
    if port is not None and not 1 <= port <= 65535:
        raise RepositoryURLValidationError(
            "repository URL contains an invalid port")
    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host if port in (None, 443) else f"{display_host}:{port}"
    normalized_path = _encoded_path(segments).rstrip("/")
    normalized = urlunsplit(("https", netloc, normalized_path, "", ""))
    return RepositoryReference(
        original_url=candidate,
        normalized_url=normalized,
        provider="generic_https_git",
        host=host,
        repository="/".join(segments),
    )


def _error_detail(raw: bytes) -> str:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return payload["message"][:300]
    return ""


def _raise_for_github_status(response: httpx.Response, raw: bytes) -> None:
    status = response.status_code
    detail = _error_detail(raw)
    suffix = f": {detail}" if detail else ""
    if status == 404:
        raise RepositoryNotFoundError(
            "GitHub repository or Dependency Graph SBOM was not found; "
            "confirm that the repository is visible to the configured "
            f"credentials and dependency graph data is available{suffix}")
    if status == 429 or (status == 403 and (
            response.headers.get("x-ratelimit-remaining") == "0"
            or "retry-after" in response.headers)):
        retry_after = (response.headers.get("retry-after")
                       or response.headers.get("x-ratelimit-reset"))
        raise RepositoryRateLimitError(
            "GitHub API rate limit reached; retry later or configure "
            f"GITHUB_TOKEN{suffix}", retry_after=retry_after)
    if status in (401, 403):
        raise RepositoryAccessDeniedError(
            "GitHub denied access to the repository SBOM; confirm repository "
            f"visibility and GITHUB_TOKEN permissions{suffix}")
    if 300 <= status < 400:
        raise RepositoryFetchError(
            "GitHub API returned an unexpected redirect; repository import "
            "did not follow it")
    raise RepositoryFetchError(
        f"GitHub SBOM API returned HTTP {status}{suffix}")


def _read_response(response: httpx.Response, max_bytes: int,
                   deadline: float | None = None,
                   monotonic: Callable[[], float] = time.monotonic) -> bytes:
    length = response.headers.get("content-length")
    if length:
        try:
            if int(length) > max_bytes:
                raise RepositoryTooLargeError(
                    f"GitHub SBOM exceeds the {max_bytes}-byte import limit")
        except ValueError:
            pass
    parts: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > max_bytes:
            raise RepositoryTooLargeError(
                f"GitHub SBOM exceeds the {max_bytes}-byte import limit")
        if deadline is not None and monotonic() > deadline:
            raise RepositoryFetchError(
                "GitHub SBOM download timed out; retry the import")
        parts.append(chunk)
    return b"".join(parts)


def _read_error_response(response: httpx.Response) -> bytes:
    """Read only enough provider error text to classify it safely.

    A provider error body is diagnostic rather than an SBOM.  Its size must
    not turn a known 404/403/429 into the less useful "SBOM too large" error.
    """
    remaining = 64 * 1024
    parts: list[bytes] = []
    for chunk in response.iter_bytes():
        if remaining <= 0:
            break
        parts.append(chunk[:remaining])
        remaining -= len(parts[-1])
    return b"".join(parts)


def _parse_github_sbom(raw: bytes) -> tuple[dict[str, Any], int]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise RepositoryResponseError(
            "GitHub SBOM response is not UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise RepositoryResponseError(
            "GitHub SBOM response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise RepositoryResponseError(
            "GitHub SBOM response is not a JSON object")
    # The export download is a bare SPDX document; tolerate the {"sbom": ...}
    # envelope the REST schema describes for the same data.
    sbom = payload["sbom"] if "sbom" in payload else payload
    if not isinstance(sbom, dict):
        raise RepositoryResponseError(
            "GitHub SBOM response has an invalid 'sbom' object")
    if not str(sbom.get("spdxVersion", "")).startswith("SPDX-"):
        raise RepositoryResponseError(
            "GitHub SBOM response is not a recognized SPDX document")
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        raise RepositoryResponseError(
            "GitHub SPDX document is missing its packages list")
    if any(not isinstance(package, dict) for package in packages):
        raise RepositoryResponseError(
            "GitHub SPDX document contains an invalid package entry")
    return sbom, len(packages)


def _get_bounded(client: httpx.Client, url: str, headers: dict[str, str],
                 timeout: float, max_bytes: int) -> bytes:
    with client.stream("GET", url, headers=headers, timeout=timeout,
                       follow_redirects=False) as response:
        if response.status_code != 200:
            raise RepositoryFetchError(f"HTTP {response.status_code}")
        return _read_response(response, max_bytes)


def _registry_key(package: dict) -> tuple[str, str] | None:
    """(OSV ecosystem, package key) for a PyPI or npm SPDX package."""
    purl_type, namespace, name, _ = parse_purl(_purl_from_spdx_pkg(package))
    if purl_type == "pypi" and name:
        return "PyPI", pypi_key(name)
    if purl_type == "npm" and name:
        return "npm", f"{namespace}/{name}" if namespace else name
    return None


def _restore_declared_ranges(sbom: dict[str, Any],
                             reference: RepositoryReference,
                             client: httpx.Client, headers: dict[str, str],
                             timeout: float) -> list[str]:
    """Put back the version ranges GitHub's SBOM drops, as ``versionInfo``.

    The Dependency Graph lists ``fastapi>=0.104.0`` as a bare ``fastapi``.
    Without the range, the only release left to check is the newest, which
    is usually the patched one -- so a vulnerable declared floor such as
    ``python-multipart>=0.0.6`` would never be reported. The manifests are
    read as text through GitHub's tree API and raw file host; nothing in the
    repository is executed.
    """
    missing = [p for p in sbom.get("packages") or []
               if not str(p.get("versionInfo") or "").strip()
               and _registry_key(p) is not None]
    if not missing:
        return []
    ref = quote(reference.ref or "HEAD", safe="")
    repo = f"{quote(reference.owner or '', safe='')}/" \
           f"{quote(reference.name or '', safe='')}"
    try:
        tree = json.loads(_get_bounded(
            client, f"{GITHUB_API_ROOT}/repos/{repo}/git/trees/{ref}"
            "?recursive=1", headers, timeout, MAX_TREE_BYTES))
        entries = tree.get("tree") if isinstance(tree, dict) else None
        if not isinstance(entries, list):
            raise RepositoryResponseError("unexpected tree response")
    except (RepositoryFetchError, httpx.HTTPError, ValueError) as exc:
        return [f"{len(missing)} PyPI/npm dependencies are listed without "
                "their declared version range, and the repository file list "
                f"needed to restore it was unavailable ({exc})."]
    paths = sorted(
        (e["path"] for e in entries
         if isinstance(e, dict) and e.get("type") == "blob"
         and isinstance(e.get("path"), str) and is_manifest(e["path"])),
        key=lambda p: (p.count("/"), p))
    warnings: list[str] = []
    if tree.get("truncated"):
        warnings.append("GitHub truncated the repository file list; some "
                        "manifests may not have been read.")
    if len(paths) > MAX_MANIFESTS:
        warnings.append(f"Only the first {MAX_MANIFESTS} of {len(paths)} "
                        "manifests were read.")
        paths = paths[:MAX_MANIFESTS]

    raw_headers = {k: v for k, v in headers.items()
                   if k in {"Authorization", "User-Agent"}}
    manifests: dict[str, str] = {}
    for path in paths:
        try:
            manifests[path] = _get_bounded(
                client, f"{GITHUB_RAW_ROOT}/{repo}/{ref}/"
                f"{quote(path, safe='/')}", raw_headers, timeout,
                MAX_MANIFEST_BYTES).decode("utf-8")
        except (RepositoryFetchError, httpx.HTTPError,
                UnicodeDecodeError) as exc:
            warnings.append(f"{path} could not be read ({exc}).")
    constraints, parse_warnings = declared_constraints(manifests)
    warnings.extend(parse_warnings)

    restored = 0
    for package in missing:
        constraint, sources = constraints.get(_registry_key(package), ("", []))
        if constraint:
            package["versionInfo"] = constraint
            package["sourceInfo"] = (
                f"Declared range from {', '.join(sources)}; restored by "
                "PatchTriage because GitHub's SBOM omits version ranges.")
            restored += 1
    if restored:
        warnings.insert(0, (
            f"GitHub's SBOM omits declared version ranges; {restored} of "
            f"{len(missing)} were restored from {len(manifests)} manifest(s)."))
    if restored < len(missing):
        warnings.append(
            f"{len(missing) - restored} dependencies have no declared range "
            "in a readable manifest and are checked at their newest release.")
    return warnings


def _has_unsafe_url_chars(value: str) -> bool:
    return "\\" in value or any(
        ord(char) <= 32 or ord(char) == 127 for char in value)


def _report_poll_url(value: Any, reference: RepositoryReference) -> str:
    """The polling URL, only if it is this repository's fetch-report route."""
    invalid = RepositoryResponseError(
        "GitHub returned an SBOM report link outside the expected repository "
        "API route; it was not requested")
    if not isinstance(value, str) or _has_unsafe_url_chars(value):
        raise invalid
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise invalid from exc
    prefix = (f"/repos/{reference.owner}/{reference.name}"
              "/dependency-graph/sbom/fetch-report/")
    if (parts.scheme != "https" or parts.hostname != GITHUB_API_HOST
            or parts.username is not None or parts.password is not None
            or port not in (None, 443) or parts.query or parts.fragment
            or not parts.path.casefold().startswith(prefix.casefold())):
        raise invalid
    report_id = parts.path[len(prefix):]
    if not _REPORT_ID_RE.fullmatch(report_id):
        raise invalid
    return f"{GITHUB_API_ROOT}{prefix}{report_id}"


def _check_download_url(value: str | None) -> str:
    """Accept only the HTTPS storage origin GitHub serves exports from."""
    invalid = RepositoryResponseError(
        "GitHub redirected the SBOM download to an unapproved location; it "
        "was not requested")
    if not value or _has_unsafe_url_chars(value):
        raise invalid
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise invalid from exc
    if (parts.scheme != "https"
            or parts.hostname not in GITHUB_SBOM_DOWNLOAD_HOSTS
            or parts.username is not None or parts.password is not None
            or port not in (None, 443)):
        raise invalid
    return value


def _backoff(attempt: int) -> float:
    return min(2.0 ** attempt, SBOM_POLL_MAX_DELAY_SECONDS)


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    """Seconds to wait before polling again, honouring Retry-After."""
    try:
        delay = float(response.headers.get("retry-after", ""))
    except ValueError:
        return _backoff(attempt)
    if not 0 <= delay < float("inf"):
        return _backoff(attempt)
    return max(delay, 1.0)


def _download_github_report(client: httpx.Client, url: str, timeout: float,
                            max_bytes: int,
                            monotonic: Callable[[], float]) -> bytes:
    """Fetch the signed export with a clean request.

    The URL is a bearer capability, so it never reaches an exception message,
    provenance, or report. The request is constructed directly because
    ``client.build_request`` would merge client-level headers and cookies.
    """
    request = httpx.Request(
        "GET", url, headers={"User-Agent": GITHUB_USER_AGENT},
        extensions={"timeout": httpx.Timeout(timeout).as_dict()})
    deadline = monotonic() + SBOM_DOWNLOAD_DEADLINE_SECONDS
    response = client.send(
        request, stream=True, auth=None, follow_redirects=False)
    try:
        if response.status_code != 200:
            raise RepositoryFetchError(
                "GitHub SBOM download failed with HTTP "
                f"{response.status_code}; retry the import")
        return _read_response(response, max_bytes, deadline, monotonic)
    finally:
        response.close()


def _export_github_sbom(
    client: httpx.Client,
    reference: RepositoryReference,
    generate_url: str,
    headers: dict[str, str],
    timeout: float,
    max_bytes: int,
    poll_deadline: float,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
) -> bytes:
    """Run GitHub's generate, poll, and download SBOM export flow."""
    deadline = monotonic() + poll_deadline
    with client.stream("GET", generate_url, headers=headers, timeout=timeout,
                       follow_redirects=False) as response:
        if response.status_code != 201:
            _raise_for_github_status(response, _read_error_response(response))
        try:
            raw = _read_response(response, MAX_SBOM_LINK_BYTES)
        except RepositoryTooLargeError as exc:
            raise RepositoryResponseError(
                "GitHub SBOM report response is unexpectedly large") from exc
    try:
        link = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepositoryResponseError(
            "GitHub SBOM report response is not valid JSON") from exc
    poll_url = _report_poll_url(
        link.get("sbom_url") if isinstance(link, dict) else None, reference)

    not_ready = RepositoryFetchError(
        "GitHub is still generating the SBOM; retry the import shortly")
    location: str | None = None
    transient_failures = 0
    for attempt in range(SBOM_POLL_MAX_ATTEMPTS):
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise not_ready
        try:
            with client.stream("GET", poll_url, headers=headers,
                               timeout=min(timeout, remaining),
                               follow_redirects=False) as response:
                status = response.status_code
                if status == 302:
                    location = response.headers.get("location")
                    break
                if status in _TRANSIENT_POLL_STATUSES and (
                        transient_failures < SBOM_POLL_TRANSIENT_RETRIES):
                    transient_failures += 1
                elif status != 202:
                    _raise_for_github_status(
                        response, _read_error_response(response))
                failed = status != 202
                delay = _retry_delay(response, attempt)
        except httpx.TransportError:
            if transient_failures >= SBOM_POLL_TRANSIENT_RETRIES:
                raise
            transient_failures += 1
            failed = True
            delay = _backoff(attempt)
        if (attempt == SBOM_POLL_MAX_ATTEMPTS - 1
                or delay >= deadline - monotonic()):
            if failed:
                raise RepositoryFetchError(
                    "GitHub SBOM report status check failed with a temporary "
                    "error; retry the import")
            raise not_ready
        sleep(delay)
    return _download_github_report(
        client, _check_download_url(location), timeout, max_bytes, monotonic)


def fetch_github_sbom(
    repository: str | RepositoryReference,
    *,
    github_token: str | None = None,
    client: httpx.Client | None = None,
    max_bytes: int = DEFAULT_MAX_SBOM_BYTES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    poll_deadline: float = SBOM_POLL_DEADLINE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> RepositorySbom:
    """Fetch a GitHub repository's provider-generated SPDX SBOM.

    ``client`` is injectable for policy-specific transports and deterministic
    tests. Public repositories need no token; a local operator may supply one
    for a repository it authorizes. Redirects are never followed
    automatically so an Authorization header cannot be forwarded to another
    origin; the export's temporary download is a separate unauthenticated
    request to GitHub's storage origin.
    """
    reference = (normalize_repository_url(repository)
                 if isinstance(repository, str) else repository)
    if reference.provider != "github" or not reference.owner or not reference.name:
        raise UnsupportedRepositoryProvider(
            f"repository provider '{reference.provider}' is not supported; "
            "this importer currently supports github.com repositories")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    if poll_deadline <= 0:
        raise ValueError("poll_deadline must be positive")

    api_url = (
        f"{GITHUB_API_ROOT}/repos/{quote(reference.owner, safe='')}/"
        f"{quote(reference.name, safe='')}/dependency-graph/sbom/generate-report"
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": GITHUB_USER_AGENT,
    }
    token = github_token if github_token is not None else os.environ.get(
        "GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    owns_client = client is None
    client = client or httpx.Client()
    try:
        try:
            raw = _export_github_sbom(
                client, reference, api_url, headers, timeout, max_bytes,
                poll_deadline, sleep, monotonic)
        except httpx.TimeoutException as exc:
            raise RepositoryFetchError(
                "GitHub SBOM request timed out") from exc
        except httpx.RequestError as exc:
            raise RepositoryFetchError(
                f"GitHub SBOM request failed: {exc.__class__.__name__}") from exc
        sbom, component_count = _parse_github_sbom(raw)
        warnings = [
            "Coverage is limited to dependencies represented in GitHub's "
            "Dependency Graph; it is not proof that every manifest was "
            "discovered or that the repository has no vulnerable components."
        ]
        warnings.extend(_restore_declared_ranges(
            sbom, reference, client, headers, timeout))
    finally:
        if owns_client:
            client.close()

    coverage_status = "provider_reported"
    if reference.ref:
        coverage_status = "partial"
        warnings.append(
            "The GitHub Dependency Graph SBOM endpoint does not accept a ref; "
            f"the requested tree ref '{reference.ref}' was not independently "
            "resolved and the exported graph may represent the default branch."
        )
    if component_count == 0:
        coverage_status = "incomplete"
        warnings.append(
            "GitHub returned an SPDX document with zero packages; treat this "
            "as incomplete coverage, not a clean vulnerability result."
        )

    provenance = RepositoryProvenance(
        provider="github_dependency_graph",
        repository=reference.repository,
        ref=reference.ref or "default_branch",
        resolved_url=reference.normalized_url,
        api_url=api_url,
        format="spdx",
        component_count=component_count,
        coverage_status=coverage_status,
        warnings=tuple(warnings),
        retrieved_at=datetime.now(timezone.utc).isoformat(),
    )
    return RepositorySbom(
        content=json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True),
        provenance=provenance,
    )


def fetch_repository_sbom(
    repository: str | RepositoryReference,
    **kwargs: Any,
) -> RepositorySbom:
    """Dispatch to a safe provider, explicitly rejecting generic Git URLs."""
    reference = (normalize_repository_url(repository)
                 if isinstance(repository, str) else repository)
    if reference.provider != "github":
        raise UnsupportedRepositoryProvider(
            f"repository provider '{reference.provider}' is not supported; "
            "only github.com Dependency Graph SBOM imports are available")
    return fetch_github_sbom(reference, **kwargs)


@dataclass(frozen=True)
class RepositoryEvidence:
    """Evidence acquired from a repository URL, ready for ingestion."""

    content: str
    format: str
    provenance: dict[str, Any]


def generic_repository_enabled() -> bool:
    """Generic HTTPS Git scanning is opt-in and never offered when public."""
    mode = os.environ.get("PATCHTRIAGE_DEPLOYMENT_MODE", "local").lower()
    enabled = os.environ.get(
        "PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES", "false").lower()
    return mode != "public" and enabled in {"1", "true", "yes", "on"}


def acquire_repository_evidence(
    repository_url: str,
    *,
    github_token: str | None,
    max_bytes: int,
    allow_generic: bool,
) -> RepositoryEvidence:
    """Acquire evidence for a repository URL the same way for GUI and CLI.

    github.com uses the Dependency Graph SBOM (no clone, no execution). Other
    HTTPS Git hosts are statically scanned only when ``allow_generic``.
    """
    reference = normalize_repository_url(repository_url)
    if reference.provider == "github":
        imported = fetch_repository_sbom(
            reference, github_token=github_token, max_bytes=max_bytes)
        return RepositoryEvidence(
            imported.content, "spdx", imported.provenance.to_dict())
    if not allow_generic:
        raise RepositoryError(
            "this deployment imports public GitHub repositories; "
            "generic HTTPS Git scanning is available only in an "
            "explicitly enabled local/Docker deployment")
    from .repository_local import scan_public_repository

    scanned = scan_public_repository(
        reference.normalized_url, max_output_bytes=max_bytes)
    return RepositoryEvidence(
        scanned.content, scanned.format, scanned.provenance)
