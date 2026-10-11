"""Constraint-to-release resolution for components without an exact version.

Expected results follow each ecosystem's documented range semantics (npm
semver caret/tilde, PEP 440 specifiers, GitHub Actions major tags); no
network is used.
"""

import json

import httpx
import pytest

from patchtriage.ingest import versions
from patchtriage.ingest.sbom import parse_sbom_components
from patchtriage.ingest.versions import (Release, ResolutionError, choose,
                                         is_concrete)


def _releases(*values):
    return versions._releases(values)


RELEASES = _releases("0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.2.3",
                     "1.2.9", "1.3.0", "1.9.0", "2.0.0", "2.1.0rc1", "2.0.1")


@pytest.mark.parametrize("constraint, expected", [
    ("", "2.0.1"),                 # newest stable; rc excluded
    ("1.*.*", "1.9.0"),            # GitHub Dependency Graph major wildcard
    ("1.2.*", "1.2.9"),
    ("1.x", "1.9.0"),
    ("v1", None),                  # bare major is not a wildcard
    ("^1.2.3", "1.9.0"),           # npm: <2.0.0
    ("^0.2.3", "0.2.9"),           # npm: <0.3.0
    ("^0.0.3", "0.0.3"),           # npm: <0.0.4
    ("~1.2.3", "1.2.9"),           # npm: <1.3.0
    (">=1.2, <1.3", "1.2.9"),      # PEP 440
    (">= 1.2.3 < 2", "1.9.0"),     # npm space-separated
    ("= 1.3.0", "1.3.0"),
    ("==1.2.*", "1.2.9"),
])
def test_choose_newest_release_satisfying_the_constraint(constraint,
                                                         expected):
    if expected is None:
        with pytest.raises(ResolutionError):
            choose(RELEASES, constraint)
        return
    assert choose(RELEASES, constraint).version == expected


def test_registry_latest_pointer_wins_only_without_a_constraint():
    """npm installs dist-tags.latest even when a newer backport exists."""
    assert choose(RELEASES, "", preferred="1.3.0").version == "1.3.0"
    assert choose(RELEASES, "^1.2.3", preferred="1.3.0").version == "1.9.0"


@pytest.mark.parametrize("constraint", ["^9.0.0", "1.2.3 || 2.0.0", "main"])
def test_unsatisfiable_or_unsupported_constraints_fail_visibly(constraint):
    with pytest.raises(ResolutionError):
        choose(RELEASES, constraint)


@pytest.mark.parametrize("value, concrete", [
    ("1.2.3", True), ("v6.0.1", True), ("1:2.36-9+deb12u4", True),
    ("6.*.*", False), (">= 2.5", False), ("^1.2", False), ("6.x", False),
    ("main", False), ("release/v1", False), ("", False),
])
def test_is_concrete(value, concrete):
    assert is_concrete(value) is concrete


class _Stream:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def raise_for_status(self):
        return None

    def iter_bytes(self):
        yield self.body if isinstance(self.body, bytes) else \
            json.dumps(self.body).encode()


class _Client:
    def __init__(self, body):
        self.body = body
        self.urls = []

    def stream(self, method, url, **kwargs):
        self.urls.append(url)
        return _Stream(self.body)


def test_pypi_skips_fully_yanked_and_empty_releases():
    client = _Client({"releases": {
        "1.0.0": [{"yanked": False}], "1.1.0": [{"yanked": True}],
        "1.2.0": []}})
    releases, _ = versions._pypi("demo", client)
    assert [r.version for r in releases] == ["1.0.0"]


def test_crates_skips_yanked_versions():
    client = _Client({"versions": [{"num": "1.0.0"},
                                   {"num": "1.1.0", "yanked": True}]})
    releases, _ = versions._crates("demo", client)
    assert [r.version for r in releases] == ["1.0.0"]


def test_go_proxy_escapes_capitals_and_strips_v():
    client = _Client(b"v1.2.0\nv1.3.0\n")
    releases, _ = versions._go("github.com/Azure/sdk", client)
    assert client.urls[0].endswith("/github.com/!azure/sdk/@v/list")
    assert [r.version for r in releases] == ["1.2.0", "1.3.0"]


def test_github_action_subpath_uses_repository_tags():
    client = _Client([{"ref": "refs/tags/v2.1.0"}, {"ref": "refs/tags/v2"}])
    releases, _ = versions._github_actions(
        "github/codeql-action/init", client)
    assert "/repos/github/codeql-action/git/matching-refs/tags" in client.urls[0]
    assert choose(releases, "2.*.*").version == "2.1.0"


def test_floating_major_tag_loses_to_the_full_release_it_points_at():
    releases = versions._releases(["v6", "v6.0.0"], strip_v=True)
    assert choose(releases, "6.*.*").version == "6.0.0"


def test_oversized_registry_response_is_an_error_not_a_partial_parse(
        monkeypatch):
    monkeypatch.setattr(versions, "MAX_RESPONSE_BYTES", 10)
    with pytest.raises(ResolutionError):
        versions._pypi("demo", _Client({"releases": {"1.0.0": [{}]}}))


def test_resolve_keeps_failures_per_component():
    class Failing:
        def stream(self, method, url, **kwargs):
            raise httpx.ConnectError("down", request=httpx.Request("GET", url))

    requests = [versions.Request(0, "PyPI", "demo", ""),
                versions.Request(1, "npm", "demo", "release/v1")]
    results, errors = versions.resolve(requests, Failing())
    assert [r.version for r in results] == ["", ""]
    assert "PyPI lookup failed" in errors[0]
    assert "not a version range" in errors[1]


def test_spdx_subject_at_a_branch_is_not_counted_as_a_dependency():
    """GitHub lists the repository itself as pkg:github/owner/repo@main."""
    data = {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                           "relationshipType": "DESCRIBES",
                           "relatedSpdxElement": "SPDXRef-root"}],
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "com.github.o/r",
             "versionInfo": "main"},
            {"SPDXID": "SPDXRef-dep", "name": "httpx", "versionInfo": "0.28.1"},
        ],
    }
    assert [p.name for p in parse_sbom_components(data)] == ["httpx"]
    # A described package with a real release is still checked.
    data["packages"][0]["versionInfo"] = "1.4.0"
    assert len(parse_sbom_components(data)) == 2
