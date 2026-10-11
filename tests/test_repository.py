"""Safe repository URL handling and GitHub SBOM provider tests."""

from __future__ import annotations

import json

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

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = fetch_repository_sbom(
            "https://github.com/acme/widget.git", client=client)

    request = observed["request"]
    assert str(request.url) == (
        "https://api.github.com/repos/acme/widget/dependency-graph/sbom")
    assert request.headers["accept"] == "application/vnd.github+json"
    assert request.headers["x-github-api-version"] == "2022-11-28"
    assert "authorization" not in request.headers

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
        assert request.headers["authorization"] == "Bearer test-secret"
        assert "test-secret" not in str(request.url)
        return httpx.Response(200, json=_github_payload())

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        fetch_github_sbom("https://github.com/acme/widget", client=client)


def test_explicit_token_overrides_environment(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "environment-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer explicit-secret"
        return httpx.Response(200, json=_github_payload())

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        fetch_github_sbom(
            "https://github.com/acme/widget", github_token="explicit-secret",
            client=client,
        )


def test_tree_ref_is_visible_as_partial_not_claimed_as_resolved():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_github_payload())

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
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

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
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

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RepositoryResponseError):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client)


@pytest.mark.parametrize("content", [b"not json", b"\xff\xfe"])
def test_rejects_non_json_or_non_utf8_provider_content(content):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RepositoryResponseError):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client)


def test_response_size_is_limited_even_without_trusted_content_length():
    content = json.dumps(_github_payload()).encode("utf-8")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RepositoryTooLargeError, match="import limit"):
            fetch_github_sbom(
                "https://github.com/acme/widget", client=client,
                max_bytes=len(content) - 1,
            )


def test_content_length_is_rejected_before_parsing():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-length": "9999"}, content=b"{}")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
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
        if request.url.path.endswith("/dependency-graph/sbom"):
            return httpx.Response(200, json=_github_payload([
                _versionless("fastapi", "pkg:pypi/fastapi"),
                _versionless("python-multipart", "pkg:pypi/python-multipart"),
                _versionless("@acme/ui", "pkg:npm/%40acme/ui"),
                _versionless("left-pad", "pkg:npm/left-pad"),
            ]))
        if "/git/trees/HEAD" in request.url.path:
            return httpx.Response(200, json={"tree": [
                {"path": path, "type": "blob"} for path in files]})
        assert request.url.host == "raw.githubusercontent.com"
        return httpx.Response(
            200, text=files[request.url.path.split("/HEAD/", 1)[1]])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
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
        if request.url.path.endswith("/dependency-graph/sbom"):
            return httpx.Response(200, json=_github_payload([
                _versionless("fastapi", "pkg:pypi/fastapi")]))
        return httpx.Response(403, json={"message": "rate limited"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = fetch_github_sbom("https://github.com/acme/widget",
                                   client=client)
    assert "versionInfo" not in json.loads(result.content)["packages"][0]
    assert any("file list" in w and "HTTP 403" in w
               for w in result.provenance.warnings)
