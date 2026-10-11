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


@pytest.mark.parametrize("constraint, expected, basis", [
    # No constraint: the newest stable release (rc excluded).
    ("", "2.0.1", "newest release"),
    # Floating refs run the newest matching release.
    ("1.*.*", "1.9.0", "newest"),   # GitHub Dependency Graph major wildcard
    ("1.2.*", "1.2.9", "newest"),
    ("1.x", "1.9.0", "newest"),
    ("==1.2.*", "1.2.9", "newest"),
    ("<1.3", "1.2.9", "newest"),    # no lower bound to check
    # A lower bound still permits its oldest release -- the vulnerable floor
    # a "raise the minimum version" fix addresses.
    ("^1.2.3", "1.2.3", "oldest"),  # npm: >=1.2.3 <2.0.0
    ("^0.2.3", "0.2.3", "oldest"),
    ("^0.0.3", "0.0.3", "oldest"),
    ("~1.2.3", "1.2.3", "oldest"),
    (">=1.2, <1.3", "1.2.3", "oldest"),
    (">= 1.2.3 < 2", "1.2.3", "oldest"),   # npm space-separated
    (">=1.2.4", "1.2.9", "oldest"),        # 1.2.4 itself was never released
    ("= 1.3.0", "1.3.0", "oldest"),
])
def test_choose_release_for_constraint(constraint, expected, basis):
    release, why = choose(RELEASES, constraint)
    assert release.version == expected
    assert why.startswith(basis)


def test_registry_latest_pointer_wins_only_without_a_constraint():
    """npm installs dist-tags.latest even when a newer backport exists."""
    assert choose(RELEASES, "", preferred="1.3.0")[0].version == "1.3.0"
    assert choose(RELEASES, "1.x", preferred="1.3.0")[0].version == "1.9.0"


@pytest.mark.parametrize("constraint", ["^9.0.0", "1.2.3 || 2.0.0", "main",
                                        "v1"])
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
    assert choose(releases, "2.*.*")[0].version == "2.1.0"


def test_floating_major_tag_loses_to_the_full_release_it_points_at():
    releases = versions._releases(["v6", "v6.0.0"], strip_v=True)
    assert choose(releases, "6.*.*")[0].version == "6.0.0"


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


def test_manifest_ranges_are_read_without_executing_anything():
    constraints, warnings = versions.declared_constraints({
        "requirements.txt": (
            "# core\nfastapi>=0.104.0\nuvicorn[standard]>=0.24.0  # server\n"
            "-r dev.txt\ngit+https://example.com/x.git\nflask \\\n  >=2.0\n"
            "Pillow>=10.1.0\n"),
        "pyproject.toml": (
            '[project]\ndependencies = ["pillow<12", "httpx"]\n'
            '[build-system]\nrequires = ["setuptools>=68"]\n'
            '[tool.poetry.dependencies]\npython = "^3.10"\n'
            'requests = {version = "^2.31", extras = ["socks"]}\n'),
        "app/package.json": json.dumps({
            "dependencies": {"react": "^18.2.0", "local": "file:../x"},
            "devDependencies": {"lodash": "*"}}),
        "broken/package.json": "{not json",
    })
    assert constraints[("PyPI", "fastapi")][0] == ">=0.104.0"
    assert constraints[("PyPI", "uvicorn")][0] == ">=0.24.0"
    assert constraints[("PyPI", "flask")][0] == ">=2.0"
    # pip must satisfy every file that declares a package.
    assert constraints[("PyPI", "pillow")] == (
        "<12,>=10.1.0", ["pyproject.toml", "requirements.txt"])
    assert constraints[("PyPI", "httpx")][0] == ""
    assert constraints[("PyPI", "setuptools")][0] == ">=68"
    assert constraints[("PyPI", "requests")][0] == "^2.31"
    assert ("PyPI", "python") not in constraints
    assert constraints[("npm", "react")][0] == "^18.2.0"
    assert ("npm", "local") not in constraints
    assert constraints[("npm", "lodash")][0] == ""
    assert warnings and "broken/package.json" in warnings[0]


@pytest.mark.parametrize("path, manifest", [
    ("requirements.txt", True), ("requirements-dev.in", True),
    ("dev-requirements.txt", True), ("requirements/prod.txt", True),
    ("svc/pyproject.toml", True), ("web/package.json", True),
    ("web/node_modules/x/package.json", False), ("setup.py", False),
    ("notes.txt", False), ("package-lock.json", False),
])
def test_is_manifest(path, manifest):
    assert versions.is_manifest(path) is manifest
