"""Resolve SBOM version constraints to a concrete release for OSV lookup.

Provider SBOMs often record what a manifest *declares* rather than what is
installed: GitHub's Dependency Graph drops ``pydantic>=2.5`` to a package with
no version, and records ``uses: actions/checkout@v6`` as ``6.*.*``. OSV can
only match concrete versions, so such components would otherwise go
unchecked -- or worse, be sent as an opaque string and come back "clean".

This module asks each ecosystem's public registry for its releases and picks
the newest stable release that satisfies the declared constraint (the newest
release overall when there is none). That is what a fresh install resolves
today, not necessarily what a deployment runs, so every resolved version is
labelled as inferred and the caller keeps coverage incomplete.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import quote

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

TIMEOUT_SECONDS = 15
MAX_WORKERS = 4
MAX_LOOKUPS = 200
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

# A range or wildcard ("4.*.*", ">= 2.5", "^1.2") is a constraint, not an
# installed version.
_CONSTRAINT_CHARS = set("*<>=~^|, ")


def is_concrete(value: str) -> bool:
    """True for a release identifier OSV can match, not a range or ref.

    Branch refs such as ``main`` or ``release/v1`` are rejected too: OSV
    would compare them as opaque strings and report nothing.
    """
    value = str(value or "").strip()
    if (not value or _CONSTRAINT_CHARS & set(value) or "/" in value
            or not any(ch.isdigit() for ch in value)):
        return False
    # "6.x" / "6.X" is npm/GitHub wildcard syntax, not a release.
    return not any(part in {"x", "X"} for part in value.split("."))


class ResolutionError(ValueError):
    """The constraint cannot be evaluated or nothing satisfies it."""


@dataclass(frozen=True)
class Release:
    version: str        # the value OSV is queried with
    parsed: Version


# ------------------------------------------------------------ constraints
def _parse(value: str) -> Version | None:
    try:
        return Version(str(value).strip().lstrip("vV"))
    except InvalidVersion:
        return None


def parse(value: str) -> Version | None:
    """Public form of the release parser, tolerant of a leading "v"."""
    return _parse(value)


def in_range(version: Version, events: list) -> bool | None:
    """Evaluate one OSV ECOSYSTEM/SEMVER range; None when unparseable."""
    bounds = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        kind, value = next(iter(event.items()))
        if kind == "limit":
            continue
        bound = Version("0") if str(value) == "0" else _parse(value)
        if bound is None or kind not in {"introduced", "fixed",
                                         "last_affected"}:
            return None
        bounds.append((bound, kind))
    affected = False
    for bound, kind in sorted(bounds, key=lambda item: item[0]):
        if kind == "introduced" and version >= bound:
            affected = True
        elif kind == "fixed" and version >= bound:
            affected = False
        elif kind == "last_affected" and version > bound:
            affected = False
    return affected


def _wildcard_prefix(constraint: str) -> tuple[int, ...] | None:
    """``6.*.*`` / ``6.x`` / ``v6`` -> (6,); None when not a wildcard."""
    parts = constraint.strip().lstrip("vV").split(".")
    prefix: list[int] = []
    for index, part in enumerate(parts):
        if part in {"*", "x", "X"}:
            if any(p not in {"*", "x", "X"} for p in parts[index:]):
                raise ResolutionError(f"unsupported wildcard '{constraint}'")
            return tuple(prefix)
        if not part.isdigit():
            return None
        prefix.append(int(part))
    return None


def _caret_tilde(constraint: str) -> str | None:
    """npm/Cargo/Composer ``^1.2.3`` and ``~1.2.3`` as PEP 440 ranges."""
    match = re.fullmatch(r"([\^~])\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?",
                         constraint.strip())
    if not match:
        return None
    op, major, minor, patch = match.groups()
    x, y, z = int(major), int(minor or 0), int(patch or 0)
    lower = f"{x}.{y}.{z}"
    if op == "~":
        # ~1.2.3 / ~1.2 -> <1.3 ; ~1 -> <2
        upper = f"{x}.{y + 1}" if minor is not None else f"{x + 1}"
    elif x > 0 or minor is None:
        upper = f"{x + 1}"                  # ^1.2.3 -> <2 ; ^0 -> <1
    elif y > 0 or patch is None:
        upper = f"0.{y + 1}"                # ^0.2.3 -> <0.3 ; ^0.0 -> <0.1
    else:
        upper = f"0.0.{z + 1}"              # ^0.0.3 -> <0.0.4
    return f">={lower},<{upper}"


def _specifier(constraint: str) -> SpecifierSet:
    text = constraint.strip()
    if "||" in text:
        raise ResolutionError(f"unsupported alternative range '{constraint}'")
    converted = _caret_tilde(text)
    if converted is None:
        # npm writes ">=1.2 <2" and some SBOMs "= 1.2"; PEP 440 wants commas
        # and "==".
        text = re.sub(r"(?<=[\d*])\s+(?=[<>=!~])", ",", text)
        text = re.sub(r"(^|,)\s*=\s*(?=\d)", r"\1==", text)
        text = re.sub(r"(?<=[<>=])\s*v(?=\d)", "", text)
        converted = text.replace(" ", "")
    try:
        return SpecifierSet(converted)
    except InvalidSpecifier as exc:
        raise ResolutionError(
            f"constraint '{constraint}' is not a version range") from exc


def choose(releases: list[Release], constraint: str,
           preferred: str = "") -> Release:
    """Newest stable release satisfying ``constraint``.

    ``preferred`` is the registry's own "latest" pointer (npm dist-tag),
    honoured when there is no constraint because that is what a plain install
    selects even when a newer backport exists.
    """
    stable = [r for r in releases if not r.parsed.is_prerelease]
    constraint = str(constraint or "").strip()
    if not constraint:
        if preferred:
            for release in stable:
                if release.version == preferred:
                    return release
        matching = stable
    else:
        prefix = _wildcard_prefix(constraint)
        if prefix is not None:
            matching = [r for r in stable
                        if r.parsed.release[:len(prefix)] == prefix]
        else:
            spec = _specifier(constraint)
            matching = [r for r in stable if spec.contains(r.parsed)]
    if not matching:
        raise ResolutionError(
            f"no stable release satisfies '{constraint or 'any'}'")
    # A floating major tag ("v6") equals 6.0.0; prefer the full release.
    return max(matching, key=lambda r: (r.parsed, r.version.count(".")))


# ------------------------------------------------------------ registries
def _get_json(client: httpx.Client, url: str,
              headers: dict[str, str] | None = None):
    return json.loads(_get_bytes(client, url, headers))


def _get_bytes(client: httpx.Client, url: str,
               headers: dict[str, str] | None = None) -> bytes:
    with client.stream("GET", url, headers=headers or {},
                       timeout=TIMEOUT_SECONDS,
                       follow_redirects=True) as response:
        response.raise_for_status()
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise ResolutionError(f"registry response exceeded "
                                      f"{MAX_RESPONSE_BYTES} bytes")
            chunks.append(chunk)
    return b"".join(chunks)


def _releases(values, strip_v: bool = False) -> list[Release]:
    out = []
    for value in values:
        value = str(value or "").strip()
        parsed = _parse(value)
        if parsed is not None and value:
            out.append(Release(value.lstrip("vV") if strip_v else value,
                               parsed))
    return out


def _pypi(name, client):
    data = _get_json(client, f"https://pypi.org/pypi/{quote(name, safe='')}/json")
    releases = data.get("releases") or {}
    live = [version for version, files in releases.items()
            if isinstance(files, list) and files
            and not all(isinstance(f, dict) and f.get("yanked")
                        for f in files)]
    return _releases(live), ""


def _npm(name, client):
    data = _get_json(
        client, f"https://registry.npmjs.org/{quote(name, safe='@/')}",
        {"Accept": "application/vnd.npm.install-v1+json"})
    tags = data.get("dist-tags") or {}
    return (_releases((data.get("versions") or {}).keys()),
            str(tags.get("latest") or ""))


def _crates(name, client):
    data = _get_json(
        client, f"https://crates.io/api/v1/crates/{quote(name, safe='')}",
        {"User-Agent": "patchtriage (version resolution)"})
    return _releases(v.get("num") for v in data.get("versions") or []
                     if isinstance(v, dict) and not v.get("yanked")), ""


def _rubygems(name, client):
    data = _get_json(
        client, f"https://rubygems.org/api/v1/versions/{quote(name, safe='')}.json")
    return _releases(v.get("number") for v in data
                     if isinstance(v, dict) and not v.get("prerelease")), ""


def _nuget(name, client):
    data = _get_json(
        client, "https://api.nuget.org/v3-flatcontainer/"
        f"{quote(name.lower(), safe='')}/index.json")
    return _releases(data.get("versions") or []), ""


def _go(name, client):
    # The module proxy escapes capitals as "!" + lowercase.
    escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)
    text = _get_bytes(
        client, f"https://proxy.golang.org/{quote(escaped, safe='/!')}/@v/list"
    ).decode("utf-8", "replace")
    return _releases(text.split(), strip_v=True), ""


def _packagist(name, client):
    data = _get_json(client, f"https://repo.packagist.org/p2/{quote(name, safe='/')}.json")
    entries = (data.get("packages") or {}).get(name) or []
    return _releases(e.get("version") for e in entries
                     if isinstance(e, dict)), ""


def _github_actions(name, client):
    # "owner/repo/path/to/action" is versioned by the repository's tags.
    owner_repo = "/".join(name.split("/")[:2])
    # Deliberately unauthenticated: the action name comes from untrusted
    # SBOM content, and a service token could reveal private repositories'
    # tags. Rate-limit failures stay visible per component.
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    data = _get_json(
        client, f"https://api.github.com/repos/{quote(owner_repo, safe='/')}"
        "/git/matching-refs/tags", headers)
    tags = [str(ref.get("ref", "")).removeprefix("refs/tags/")
            for ref in data if isinstance(ref, dict)]
    # OSV records GitHub Actions versions without the tag's "v".
    return _releases(tags, strip_v=True), ""


REGISTRIES: dict[str, Callable] = {
    "PyPI": _pypi, "npm": _npm, "crates.io": _crates, "RubyGems": _rubygems,
    "NuGet": _nuget, "Go": _go, "Packagist": _packagist,
    "GitHub Actions": _github_actions,
}

REGISTRY_LABELS = {
    "PyPI": "PyPI", "npm": "npm", "crates.io": "crates.io",
    "RubyGems": "RubyGems", "NuGet": "NuGet", "Go": "Go module proxy",
    "Packagist": "Packagist", "GitHub Actions": "GitHub tags",
}


# ------------------------------------------------------------ batch
@dataclass(frozen=True)
class Request:
    index: int
    ecosystem: str      # OSV ecosystem name
    name: str
    constraint: str     # "" when the SBOM gave no version at all


@dataclass(frozen=True)
class Resolution:
    request: Request
    version: str = ""
    error: str = ""


def resolve(requests: list[Request], client: httpx.Client
            ) -> tuple[list[Resolution], list[str]]:
    """Resolve each request concurrently; failures stay per component."""
    errors: list[str] = []
    if len(requests) > MAX_LOOKUPS:
        errors.append(f"{len(requests) - MAX_LOOKUPS} component(s) exceeded "
                      "the registry lookup limit and stay unchecked")
        requests = requests[:MAX_LOOKUPS]

    def one(request: Request) -> Resolution:
        fetch = REGISTRIES[request.ecosystem]
        try:
            # Reject refs such as "release/v1" before touching the network.
            if (request.constraint
                    and _wildcard_prefix(request.constraint) is None):
                _specifier(request.constraint)
            releases, preferred = fetch(request.name, client)
            chosen = choose(releases, request.constraint, preferred)
        except ResolutionError as exc:
            return Resolution(request, error=(
                f"{request.name} ({request.constraint or 'no version'}): "
                f"{exc}"))
        except (httpx.HTTPError, json.JSONDecodeError, AttributeError,
                TypeError, ValueError) as exc:
            detail = str(exc) or exc.__class__.__name__
            return Resolution(request, error=(
                f"{request.name} ({request.constraint or 'no version'}): "
                f"{REGISTRY_LABELS[request.ecosystem]} lookup failed: "
                f"{detail}"))
        return Resolution(request, version=chosen.version)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(one, requests))
    errors.extend(r.error for r in results if r.error)
    return results, errors


def retrieved_at() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
