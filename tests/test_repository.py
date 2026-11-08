"""Safe repository URL handling and GitHub SBOM provider tests."""

from __future__ import annotations

import inspect
import json
import logging

import httpx
import pytest

from patchtriage.repository import (
    RepositoryAccessDeniedError,
    RepositoryFetchError,
    RepositoryNotFoundError,
    RepositoryRateLimitError,
    RepositoryResponseError,
    RepositoryTooLargeError,
    RepositoryURLValidationError,
    UnsupportedRepositoryProvider,
    acquire_repository_evidence,
    fetch_github_sbom,
    fetch_repository_sbom,
    normalize_repository_url,
)


def _github_payload(packages=None):
    if packages is None:
        packages = [
            {
                "SPDXID": "SPDXRef-Package-npm-lodash",
                "name": "lodash",
                "versionInfo": "4.17.20",
                "externalRefs": [],
            },
            {
                "SPDXID": "SPDXRef-Package-pypi-requests",
                "name": "requests",
                "versionInfo": "2.31.0",
                "externalRefs": [],
            },
        ]
    return {
        "sbom": {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "acme-widget",
            "packages": packages,
        }
    }


COMMIT = "a" * 40
BLOB_HOST = "dgpproduction.blob.core.windows.net"
GENERATE_URL = ("https://api.github.com/repos/acme/widget/dependency-graph/"
                "sbom/generate-report")
REPORT_URL = ("https://api.github.com/repos/acme/widget/dependency-graph/"
              "sbom/fetch-report/cd8fa1d3-eddb-4dae-8a91-5c1276e4dc08")
DOWNLOAD_URL = f"https://{BLOB_HOST}/sboms/report.json?sig=SIGNED-SECRET&se=1"


def _bare(packages=None):
    return _github_payload(packages)["sbom"]


def _export_response(request, download):
    """Answer GitHub's export API; ``download`` is the storage response."""
    if str(request.url) == GENERATE_URL:
        return httpx.Response(201, json={"sbom_url": REPORT_URL})
    if str(request.url) == REPORT_URL:
        return httpx.Response(302, headers={"location": DOWNLOAD_URL})
    return download


def _via_export(handler):
    """Serve the export API in front of a handler for everything else."""
    def transport(request: httpx.Request) -> httpx.Response:
        if str(request.url) in (GENERATE_URL, REPORT_URL):
            return _export_response(request, None)
        return handler(request)
    return httpx.MockTransport(transport)


@pytest.mark.parametrize(
    ("url", "normalized", "repository"),
    [
        (
            "https://github.com/acme/widget",
            "https://github.com/acme/widget",
            "acme/widget",
        ),
        (
            " HTTPS://GitHub.com/Acme-Co/widget.py.git/ ",
            "https://github.com/Acme-Co/widget.py",
            "Acme-Co/widget.py",
        ),
        (
            "https://github.com/acme/.github",
            "https://github.com/acme/.github",
            "acme/.github",
        ),
    ],
)
def test_normalize_github_repository_urls(url, normalized, repository):
    ref = normalize_repository_url(url)
    assert ref.provider == "github"
    assert ref.normalized_url == normalized
    assert ref.repository == repository
    assert ref.ref is None


def test_normalize_github_tree_url_preserves_requested_ref_but_resolves_root():
    ref = normalize_repository_url(
        "https://github.com/acme/widget/tree/release/2026.1")
    assert ref.provider == "github"
    assert ref.normalized_url == "https://github.com/acme/widget"
    assert ref.repository == "acme/widget"
    assert ref.selector == "tree"
    assert ref.ref == "release/2026.1"


def test_normalize_generic_https_git_url_without_treating_spoof_as_github():
    ref = normalize_repository_url(
        "https://GitLab.Example:8443/group/subgroup/project.git/")
    assert ref.provider == "generic_https_git"
    assert ref.host == "gitlab.example"
    assert ref.repository == "group/subgroup/project.git"
    assert ref.normalized_url == (
        "https://gitlab.example:8443/group/subgroup/project.git")

    spoof = normalize_repository_url("https://github.com.evil.test/acme/widget")
    assert spoof.provider == "generic_https_git"
    assert spoof.host == "github.com.evil.test"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "git@github.com:acme/widget.git",
        "http://github.com/acme/widget",
        "ssh://github.com/acme/widget",
        "file:///tmp/widget",
        "https://user@github.com/acme/widget",
        "https://user:secret@github.com/acme/widget",
        "https://github.com/acme/widget#readme",
        "https://github.com/acme/widget?tab=readme",
        "https://github.com",
        "https://github.com/acme",
        "https://github.com:444/acme/widget",
        "https://github.com/acme/widget/issues/1",
        "https://github.com/acme/widget/tree",
        "https://github.com/acme/widget/tree/%2e%2e",
        "https://github.com/acme%2Fwidget/other",
        "https://github.com/acme\\widget/repo",
        "https://github.com/acme/widget%ZZ",
        "https://github.com/acme--spoof/widget",
        "https://github.com/acme/widget.git.git",
        "https://gitlab.example/project",
        "https://github.com./acme/widget",
    ],
)
def test_rejects_ambiguous_or_unsafe_repository_urls(url):
    with pytest.raises(RepositoryURLValidationError):
        normalize_repository_url(url)


def test_fetch_public_github_sbom_without_token_returns_spdx_and_provenance():
    observed = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["request"] = request
        return httpx.Response(200, json=_github_payload())

    with httpx.Client(transport=_via_export(handler)) as client:
        result = fetch_repository_sbom(
            "https://github.com/acme/widget.git", client=client)

    assert observed["request"].url.host == BLOB_HOST

    document = json.loads(result.content)
    assert "sbom" not in document
    assert document["spdxVersion"] == "SPDX-2.3"
    assert result.provenance.provider == "github_dependency_graph"
    assert result.provenance.repository == "acme/widget"
    assert result.provenance.ref == "default_branch"
    assert result.provenance.resolved_url == "https://github.com/acme/widget"
    assert result.provenance.format == "spdx"
    assert result.provenance.component_count == 2
    assert result.provenance.coverage_status == "provider_reported"
    assert "not proof" in result.provenance.warnings[0]
    assert result.provenance.to_dict()["warnings"] == list(
        result.provenance.warnings)


def test_github_token_is_optional_and_never_placed_in_url(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            assert request.headers["authorization"] == "Bearer test-secret"
        assert "test-secret" not in str(request.url)
        return _export_response(request, httpx.Response(200, json=_bare()))

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        fetch_github_sbom("https://github.com/acme/widget", client=client)


def test_explicit_token_overrides_environment(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "environment-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            assert request.headers["authorization"] == "Bearer explicit-secret"
        return _export_response(request, httpx.Response(200, json=_bare()))

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        fetch_github_sbom(
            "https://github.com/acme/widget", github_token="explicit-secret",
            client=client,
        )


def test_tree_ref_is_visible_as_partial_not_claimed_as_resolved():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_github_payload())

    with httpx.Client(transport=_via_export(handler)) as client:
        result = fetch_github_sbom(
            "https://github.com/acme/widget/tree/release/2026.1",
            client=client,
        )
    provenance = result.provenance
    assert provenance.ref == "release/2026.1"
    assert provenance.resolved_url == "https://github.com/acme/widget"
    assert provenance.coverage_status == "partial"
    assert any("does not accept a ref" in warning
               for warning in provenance.warnings)


def test_empty_provider_document_is_marked_incomplete_not_clean():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_github_payload([]))

    with httpx.Client(transport=_via_export(handler)) as client:
        result = fetch_github_sbom(
            "https://github.com/acme/widget", client=client)
    assert result.provenance.component_count == 0
    assert result.provenance.coverage_status == "incomplete"
    assert any("zero packages" in warning
               for warning in result.provenance.warnings)


@pytest.mark.parametrize(
    ("status", "headers", "exception"),
    [
        (404, {}, RepositoryNotFoundError),
        (401, {}, RepositoryAccessDeniedError),
        (403, {}, RepositoryAccessDeniedError),
        (429, {"retry-after": "60"}, RepositoryRateLimitError),
        (500, {}, RepositoryFetchError),
        (302, {"location": "https://evil.test/"}, RepositoryFetchError),
    ],
)
def test_github_http_failures_have_specific_exceptions(
        status, headers, exception):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, headers=headers, json={"message": "provider detail"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(exception, match="GitHub"):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client)


def test_github_403_rate_limit_exposes_retry_hint():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "42"},
            json={"message": "API rate limit exceeded"},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RepositoryRateLimitError) as caught:
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client)
    assert caught.value.retry_after == "42"


def test_large_error_body_keeps_specific_http_failure_classification():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"x" * 100_000)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RepositoryNotFoundError):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client,
                max_bytes=10,
            )


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"sbom": []},
        {"sbom": {}},
        {"sbom": {"spdxVersion": "CycloneDX-1.5", "packages": []}},
        {"sbom": {"spdxVersion": "SPDX-2.3"}},
        {"sbom": {"spdxVersion": "SPDX-2.3", "packages": ["bad"]}},
    ],
)
def test_rejects_invalid_github_sbom_schema(payload):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with httpx.Client(transport=_via_export(handler)) as client:
        with pytest.raises(RepositoryResponseError):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client)


@pytest.mark.parametrize("content", [b"not json", b"\xff\xfe"])
def test_rejects_non_json_or_non_utf8_provider_content(content):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content)

    with httpx.Client(transport=_via_export(handler)) as client:
        with pytest.raises(RepositoryResponseError):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client)


def test_response_size_is_limited_even_without_trusted_content_length():
    content = json.dumps(_github_payload()).encode("utf-8")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content)

    with httpx.Client(transport=_via_export(handler)) as client:
        with pytest.raises(RepositoryTooLargeError, match="import limit"):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client,
                max_bytes=len(content) - 1,
            )


def test_content_length_is_rejected_before_parsing():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-length": "9999"}, content=b"{}")

    with httpx.Client(transport=_via_export(handler)) as client:
        with pytest.raises(RepositoryTooLargeError):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client,
                max_bytes=100,
            )


def test_network_timeout_is_wrapped_without_leaking_transport_details():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out to internal host", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RepositoryFetchError, match="timed out") as caught:
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client)
    assert "internal host" not in str(caught.value)


def test_generic_provider_is_explicitly_unsupported_without_network_request():
    requested = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requested
        requested = True
        return httpx.Response(500)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(UnsupportedRepositoryProvider, match="github.com"):
            fetch_repository_sbom(
                "https://gitlab.example/group/project.git", client=client)
    assert requested is False


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_bytes": 0}, "max_bytes"),
        ({"max_bytes": True}, "max_bytes"),
        ({"timeout": 0}, "timeout"),
    ],
)
def test_fetch_limits_must_be_positive(kwargs, message):
    with pytest.raises(ValueError, match=message):
        fetch_github_sbom("https://github.com/acme/widget", **kwargs)


def _versionless(name, purl):
    return {"SPDXID": f"SPDXRef-{name}", "name": name,
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                              "referenceType": "purl",
                              "referenceLocator": purl}]}


def test_declared_ranges_dropped_by_github_are_restored_from_manifests():
    """GitHub lists fastapi>=0.104.0 as a bare fastapi; only the range lets
    a vulnerable declared floor be checked at all."""
    files = {
        "requirements.txt": "fastapi>=0.104.0\npython_multipart>=0.0.6\n",
        "web/package.json": json.dumps({"dependencies": {"@acme/ui": "^1.2.0"}}),
        "README.md": "fastapi==0.1",
    }
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.host == BLOB_HOST:
            return httpx.Response(200, json=_github_payload([
                _versionless("fastapi", "pkg:pypi/fastapi"),
                _versionless("python-multipart", "pkg:pypi/python-multipart"),
                _versionless("@acme/ui", "pkg:npm/%40acme/ui"),
                _versionless("left-pad", "pkg:npm/left-pad"),
            ]))
        if request.url.path.endswith("/commits/HEAD"):
            return httpx.Response(200, json={"sha": COMMIT})
        if f"/git/trees/{COMMIT}" in request.url.path:
            return httpx.Response(200, json={"tree": [
                {"path": path, "type": "blob"} for path in files]})
        assert request.url.host == "raw.githubusercontent.com"
        return httpx.Response(
            200, text=files[request.url.path.split(f"/{COMMIT}/", 1)[1]])

    with httpx.Client(transport=_via_export(handler)) as client:
        result = fetch_github_sbom("https://github.com/acme/widget",
                                   client=client)
    packages = {p["name"]: p for p in json.loads(result.content)["packages"]}
    assert packages["fastapi"]["versionInfo"] == ">=0.104.0"
    # PEP 503: python_multipart in the manifest is python-multipart.
    assert packages["python-multipart"]["versionInfo"] == ">=0.0.6"
    assert packages["@acme/ui"]["versionInfo"] == "^1.2.0"
    assert "requirements.txt" in packages["fastapi"]["sourceInfo"]
    assert "versionInfo" not in packages["left-pad"]
    assert not any("README.md" in url for url in requested)
    assert any("3 of 4 were restored" in w for w in result.provenance.warnings)
    assert any("1 dependencies have no declared range" in w
               for w in result.provenance.warnings)


def test_unavailable_file_list_leaves_sbom_usable_and_says_so():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == BLOB_HOST:
            return httpx.Response(200, json=_github_payload([
                _versionless("fastapi", "pkg:pypi/fastapi")]))
        return httpx.Response(403, json={"message": "rate limited"})

    with httpx.Client(transport=_via_export(handler)) as client:
        result = fetch_github_sbom("https://github.com/acme/widget",
                                   client=client)
    assert "versionInfo" not in json.loads(result.content)["packages"][0]
    assert any("file list" in w and "HTTP 403" in w
               for w in result.provenance.warnings)


class _Clock:
    """A fake clock that advances only when the poller sleeps."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _fetch(handler, clock=None, url="https://github.com/acme/widget", **kwargs):
    clock = clock or _Clock()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return fetch_github_sbom(url, client=client, sleep=clock.sleep,
                                 monotonic=clock.monotonic, **kwargs)


def _flow(*polls, generate=None, download=None, seen=None):
    """Script generate/poll/download; synchronous endpoint calls fail."""
    pending = list(polls)

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        assert not request.url.path.endswith("/dependency-graph/sbom"), (
            "the retired synchronous endpoint must not be called")
        if str(request.url) == GENERATE_URL:
            return generate or httpx.Response(
                201, json={"sbom_url": REPORT_URL})
        if str(request.url) == REPORT_URL:
            return pending.pop(0)
        if request.url.host == BLOB_HOST:
            return download or httpx.Response(200, json=_bare())
        raise AssertionError(f"unexpected request to {request.url.host}")
    return handler


def _ready():
    return httpx.Response(302, headers={"location": DOWNLOAD_URL})


def test_export_polls_through_202_then_downloads_bare_spdx():
    clock = _Clock()
    seen = []
    result = _fetch(_flow(
        httpx.Response(202, headers={"retry-after": "3"}),
        httpx.Response(202),
        _ready(), seen=seen), clock)

    assert clock.sleeps == [3.0, 2.0]
    assert json.loads(result.content)["spdxVersion"] == "SPDX-2.3"
    assert [str(r.url) for r in seen[:2]] == [GENERATE_URL, REPORT_URL]
    assert seen[0].headers["x-github-api-version"] == "2026-03-10"
    assert result.provenance.api_url == GENERATE_URL
    assert result.provenance.component_count == 2


def test_export_ready_immediately_does_not_sleep():
    clock = _Clock()
    _fetch(_flow(_ready()), clock)
    assert clock.sleeps == []


def test_signed_download_gets_no_credentials_or_cookies():
    seen = []
    client = httpx.Client(
        transport=httpx.MockTransport(_flow(_ready(), seen=seen)),
        headers={"Authorization": "Bearer client-default",
                 "X-Api-Key": "client-secret"},
        cookies={"session": "cookie-secret"})
    with client:
        fetch_github_sbom("https://github.com/acme/widget", client=client,
                          github_token="api-secret")
    assert seen[0].headers["authorization"] == "Bearer api-secret"
    download = seen[-1]
    assert download.url.host == BLOB_HOST
    assert "authorization" not in download.headers
    assert "cookie" not in download.headers
    assert "x-api-key" not in download.headers


def test_signed_url_never_reaches_provenance_or_content():
    result = _fetch(_flow(_ready()))
    assert "SIGNED-SECRET" not in result.content
    assert "SIGNED-SECRET" not in json.dumps(result.provenance.to_dict())


@pytest.mark.parametrize(
    ("status", "headers", "exception"),
    [(403, {}, RepositoryAccessDeniedError),
     (404, {}, RepositoryNotFoundError),
     (429, {"retry-after": "7"}, RepositoryRateLimitError),
     (200, {}, RepositoryFetchError)])
def test_fetch_report_failures_are_classified(status, headers, exception):
    with pytest.raises(exception):
        _fetch(_flow(httpx.Response(status, headers=headers,
                                    json={"message": "detail"})))


@pytest.mark.parametrize(
    ("status", "exception"),
    [(403, RepositoryAccessDeniedError), (404, RepositoryNotFoundError),
     (200, RepositoryFetchError)])
def test_generate_report_failures_are_classified(status, exception):
    with pytest.raises(exception):
        _fetch(_flow(generate=httpx.Response(status, json={"message": "x"})))


@pytest.mark.parametrize("status", [301, 403, 404, 500])
def test_download_failure_never_echoes_signed_url(status):
    with pytest.raises(RepositoryFetchError) as caught:
        _fetch(_flow(_ready(), download=httpx.Response(
            status, headers={"location": "https://evil.test/"},
            text="<Error>sig=SIGNED-SECRET</Error>")))
    assert "SIGNED-SECRET" not in str(caught.value)
    assert str(status) in str(caught.value)


def test_poll_deadline_stops_a_report_that_never_finishes():
    clock = _Clock()
    polls = [httpx.Response(202, headers={"retry-after": "5"})
             for _ in range(30)]
    with pytest.raises(RepositoryFetchError, match="still generating"):
        _fetch(_flow(*polls), clock, poll_deadline=12)
    assert clock.now <= 12


def test_poll_attempts_are_capped_even_with_time_remaining():
    clock = _Clock()
    polls = [httpx.Response(202, headers={"retry-after": "1"})
             for _ in range(40)]
    with pytest.raises(RepositoryFetchError, match="still generating"):
        _fetch(_flow(*polls), clock, poll_deadline=10_000)
    assert len(clock.sleeps) == 19


def test_retry_after_past_the_deadline_fails_without_waiting():
    clock = _Clock()
    with pytest.raises(RepositoryFetchError, match="still generating"):
        _fetch(_flow(httpx.Response(202, headers={"retry-after": "3600"})),
               clock, poll_deadline=30)
    assert clock.sleeps == []


@pytest.mark.parametrize("value", ["soon", "-5", "nan", "inf"])
def test_unusable_retry_after_falls_back_to_backoff(value):
    clock = _Clock()
    _fetch(_flow(httpx.Response(202, headers={"retry-after": value}), _ready()),
           clock)
    assert clock.sleeps == [1.0]


@pytest.mark.parametrize(
    "link",
    ["https://evil.test/repos/acme/widget/dependency-graph/sbom/fetch-report/a1",
     "http://api.github.com/repos/acme/widget/dependency-graph/sbom/fetch-report/a1",
     "https://api.github.com/repos/other/repo/dependency-graph/sbom/fetch-report/a1",
     "https://api.github.com/repos/acme/widget/dependency-graph/sbom/fetch-report/a/../../x",
     "https://api.github.com/repos/acme/widget/dependency-graph/sbom/fetch-report/a1?x=1",
     "https://user:pw@api.github.com/repos/acme/widget/dependency-graph/sbom/fetch-report/a1",
     "https://api.github.com:444/repos/acme/widget/dependency-graph/sbom/fetch-report/a1",
     "", None, 7])
def test_report_link_outside_this_repository_is_not_requested(link):
    seen = []
    with pytest.raises(RepositoryResponseError, match="report link"):
        _fetch(_flow(generate=httpx.Response(201, json={"sbom_url": link}),
                     seen=seen))
    assert len(seen) == 1


@pytest.mark.parametrize("content", [b"not json", b"\xff"])
def test_malformed_generate_response_is_rejected(content):
    with pytest.raises(RepositoryResponseError):
        _fetch(_flow(generate=httpx.Response(201, content=content)))


@pytest.mark.parametrize(
    "location",
    ["https://evil.test/x", f"http://{BLOB_HOST}/x",
     f"https://{BLOB_HOST}.evil.test/x",
     "https://attacker.blob.core.windows.net/x",
     f"https://user:pw@{BLOB_HOST}/x",
     f"https://{BLOB_HOST}:8443/x", "/relative", None])
def test_download_redirect_to_unapproved_location_is_not_requested(location):
    seen = []
    headers = {"location": location} if location else {}
    with pytest.raises(RepositoryResponseError, match="unapproved"):
        _fetch(_flow(httpx.Response(302, headers=headers), seen=seen))
    assert all(r.url.host == "api.github.com" for r in seen)


def test_oversized_download_is_stopped_by_streamed_limit():
    with pytest.raises(RepositoryTooLargeError):
        _fetch(_flow(_ready(), download=httpx.Response(
            200, content=b"x" * 5000)), max_bytes=100)


@pytest.mark.parametrize("content", [b'{"spdxVersion": "SPDX-2.3"', b"{}"])
def test_broken_download_payload_is_rejected(content):
    with pytest.raises(RepositoryResponseError):
        _fetch(_flow(_ready(), download=httpx.Response(200, content=content)))


def test_poll_deadline_must_be_positive():
    with pytest.raises(ValueError, match="poll_deadline"):
        fetch_github_sbom("https://github.com/acme/widget", poll_deadline=0)


def test_import_adapters_use_the_export_flow(monkeypatch):
    """The adapter behind GUI/CLI imports and fleet's default fetcher avoid
    the retired endpoint; the flow fails if it is called."""
    from patchtriage import fleet, repository

    real_client = httpx.Client
    monkeypatch.setattr(
        repository.httpx, "Client",
        lambda: real_client(transport=httpx.MockTransport(_flow(_ready()))))

    assert inspect.signature(fleet.import_fleet).parameters[
        "fetch_fn"].default is fetch_github_sbom
    evidence = acquire_repository_evidence(
        "https://github.com/acme/widget", github_token="",
        max_bytes=1024 * 1024, allow_generic=False)
    assert evidence.format == "spdx"
    assert evidence.provenance["api_url"] == GENERATE_URL


def test_anonymous_export_sends_no_authorization(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seen = []
    _fetch(_flow(_ready(), seen=seen))
    assert seen[0].headers["accept"] == "application/vnd.github+json"
    assert all("authorization" not in r.headers for r in seen)


@pytest.mark.parametrize("failure", [
    httpx.Response(503),
    httpx.ConnectError("boom"),
])
def test_transient_poll_failure_is_retried_within_budget(failure):
    polls = [failure, _ready()]
    flow = _flow(*polls)

    def handler(request):
        if isinstance(polls[0], Exception) and str(request.url) == REPORT_URL:
            raise polls.pop(0)
        return flow(request)

    if isinstance(failure, Exception):
        flow = _flow(_ready())
    clock = _Clock()
    result = _fetch(handler, clock)
    assert clock.sleeps == [1.0]
    assert result.provenance.component_count == 2


def test_repeated_transient_poll_failures_surface():
    with pytest.raises(RepositoryFetchError, match="HTTP 503"):
        _fetch(_flow(*[httpx.Response(503) for _ in range(3)]))


def test_permanent_poll_failure_is_not_retried():
    clock = _Clock()
    with pytest.raises(RepositoryNotFoundError):
        _fetch(_flow(httpx.Response(404)), clock)
    assert clock.sleeps == []


def test_slow_download_is_stopped_by_total_deadline():
    clock = _Clock()

    def chunks():
        while True:
            clock.now += 50
            yield b"x"

    with pytest.raises(RepositoryFetchError, match="timed out"):
        _fetch(_flow(_ready(), download=httpx.Response(200, content=chunks())),
               clock)


def test_location_httpx_cannot_parse_fails_as_a_repository_error():
    """httpx rejects it while reading the 302, before any download."""
    location = f"https://{BLOB_HOST}/" + "x" * 70_000
    seen = []
    with pytest.raises(RepositoryFetchError):
        _fetch(_flow(*[httpx.Response(302, headers={"location": location})
                       for _ in range(3)], seen=seen))
    assert all(r.url.host == "api.github.com" for r in seen)


def test_temporary_failure_at_the_deadline_is_not_called_generating():
    with pytest.raises(RepositoryFetchError, match="temporary"):
        _fetch(_flow(httpx.Response(503, headers={"retry-after": "3600"})),
               poll_deadline=30)


def test_secondary_rate_limit_403_is_a_rate_limit():
    with pytest.raises(RepositoryRateLimitError) as caught:
        _fetch(_flow(generate=httpx.Response(
            403, headers={"retry-after": "60",
                          "x-ratelimit-remaining": "12"},
            json={"message": "secondary rate limit"})))
    assert caught.value.retry_after == "60"


def test_oversized_report_link_is_not_called_an_oversized_sbom():
    with pytest.raises(RepositoryResponseError) as caught:
        _fetch(_flow(generate=httpx.Response(201, content=b"x" * 70_000)))
    assert not isinstance(caught.value, RepositoryTooLargeError)


def test_signed_location_is_dropped_from_httpcore_debug_logs(caplog):
    with caplog.at_level(logging.DEBUG, logger="httpcore.http11"):
        logging.getLogger("httpcore.http11").debug(
            "receive_response_headers.complete return_value=%r",
            [(b"Location", DOWNLOAD_URL.encode())])
    assert "SIGNED-SECRET" not in caplog.text


def test_operator_can_approve_a_new_download_host(monkeypatch):
    host = "dgpother.blob.core.windows.net"
    monkeypatch.setenv("PATCHTRIAGE_GITHUB_SBOM_DOWNLOAD_HOSTS", f" {host} ,")

    def handler(request):
        if request.url.host == host:
            return httpx.Response(200, json=_bare())
        return _flow(httpx.Response(
            302, headers={"location": f"https://{host}/r?sig=x"}))(request)

    assert _fetch(handler).provenance.component_count == 2


def test_signed_url_is_not_logged(caplog):
    with caplog.at_level(logging.DEBUG):
        _fetch(_flow(_ready()))
    assert "SIGNED-SECRET" not in caplog.text
    assert "generate-report" in caplog.text


def _versionless_export(files, *, commit=COMMIT, requested=None):
    def handler(request):
        if requested is not None:
            requested.append(str(request.url))
        if request.url.host == BLOB_HOST:
            return httpx.Response(200, json=_bare([
                _versionless("fastapi", "pkg:pypi/fastapi")]))
        if request.url.path.endswith("/commits/HEAD"):
            return httpx.Response(200, json={"sha": commit})
        if "/git/trees/" in request.url.path:
            return httpx.Response(200, json={"tree": [
                {"path": path, "type": "blob"} for path in files]})
        return httpx.Response(200, text=files["requirements.txt"])
    return _via_export(handler)


def test_requested_ref_does_not_mix_its_manifests_with_the_graph():
    requested = []
    with httpx.Client(transport=_versionless_export(
            {"requirements.txt": "fastapi>=1.0\n"},
            requested=requested)) as client:
        result = fetch_github_sbom(
            "https://github.com/acme/widget/tree/feature/x", client=client)
    assert "versionInfo" not in json.loads(result.content)["packages"][0]
    assert not any("raw.githubusercontent" in url or "/git/trees/" in url
                   for url in requested)
    provenance = result.provenance
    assert provenance.requested_ref == "feature/x"
    assert provenance.coverage_status == "partial"
    assert provenance.manifest_commit == ""
    assert any("feature/x" in w and "not combined" in w
               for w in provenance.warnings)


def test_default_branch_manifests_are_pinned_to_one_commit():
    requested = []
    with httpx.Client(transport=_versionless_export(
            {"requirements.txt": "fastapi>=1.0\n"},
            requested=requested)) as client:
        result = fetch_github_sbom(
            "https://github.com/acme/widget", client=client)
    raw = [url for url in requested if "raw.githubusercontent" in url]
    assert raw and all(f"/{COMMIT}/" in url for url in raw)
    assert result.provenance.manifest_commit == COMMIT
    assert result.provenance.evidence_scope.endswith("default_branch")


@pytest.mark.parametrize("sha", ["../../evil", "main", "", None])
def test_invalid_commit_response_is_not_used_in_a_url(sha):
    requested = []
    with httpx.Client(transport=_versionless_export(
            {"requirements.txt": "fastapi>=1.0\n"}, commit=sha,
            requested=requested)) as client:
        result = fetch_github_sbom(
            "https://github.com/acme/widget", client=client)
    assert not any("/git/trees/" in url for url in requested)
    assert result.provenance.manifest_commit == ""
    assert any("file list" in w for w in result.provenance.warnings)
