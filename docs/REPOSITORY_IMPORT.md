# Repository import and coverage model

PatchTriage can acquire vulnerability evidence from a repository URL, but it
does not claim that every URL, host, manifest, or ecosystem can be scanned.
Unsupported or incomplete inputs are reported explicitly instead of being
shown as a clean result.

## Supported acquisition paths

| Deployment | Repository input | Acquisition | Repository code executed? |
|---|---|---|---|
| Hosted/public | Public `https://github.com/owner/repo` | GitHub Dependency Graph SPDX SBOM API | No |
| Local Python | Public GitHub | GitHub Dependency Graph SPDX SBOM API | No |
| Local Docker | Public GitHub | GitHub Dependency Graph SPDX SBOM API | No |
| Local with operator token | Token-authorized private GitHub | GitHub Dependency Graph SPDX SBOM API | No |
| Local Docker, opt-in | Other public HTTPS Git URL | Disposable clone + OSV-Scanner v2 source scan | No |

The hosted anonymous importer never passes a configured service token, so it
cannot read private GitHub repositories. A local operator may provide
`GITHUB_TOKEN` or `GH_TOKEN`; that token can read a private GitHub repository
only when GitHub authorizes it. Private generic Git hosts, URL-embedded
credentials, SSH/scp syntax, `git://`, and `file://` are rejected. GitHub URLs
may end in `.git`. A `tree/<ref>` selector is retained in provenance, but
GitHub's SBOM endpoint does not accept a ref; PatchTriage labels that result
`partial`.

## Why hosted generic cloning is disabled

Letting an anonymous internet user make the web process clone an arbitrary URL
creates SSRF, DNS-rebinding, resource-exhaustion, credential-helper, and parser
attack surfaces. Application-level URL validation is not a substitute for a
network egress policy and isolated workers. The hosted importer therefore uses
an allowlisted provider API and never clones arbitrary URLs.

The opt-in local scanner is intended for a reviewer or operator who controls
the machine. It still applies defense in depth:

- HTTPS only, without user information;
- a preflight public-IP check;
- Git protocol allowlist (`https` only);
- disabled credential helpers and interactive prompts;
- disabled hooks, submodules, and Git LFS smudge;
- a trusted empty OSV-Scanner configuration, so repository-local ignore and
  package-override rules cannot suppress findings;
- shallow, single-branch checkout with blob filtering;
- disposable checkout directory;
- clone and scan timeouts;
- repository byte and file-count limits;
- OSV-Scanner `--no-resolve` and `--all-packages` static scanning;
- no package-manager, build, test, or remediation command.

For an organization-wide public generic-repository service, move acquisition
to isolated workers with no application secrets, CPU/memory/PID/disk limits,
an outbound firewall that blocks private and metadata networks, cancellation,
and guaranteed cleanup.

## Coverage states

Every result carries source provenance and a coverage status:

- `complete`: the bundled fixture was fully consumed, or all SBOM components
  were queryable and the OSV requests completed.
- `provider_reported`: GitHub returned a Dependency Graph SBOM and all of its
  queryable components were processed, or an uploaded scanner report was
  consumed as supplied. This does not prove that the provider found every
  manifest or that the original scanner invocation covered the whole target.
- `partial`: the provider could not honor an exact selector, such as a GitHub
  tree ref.
- `incomplete`: one or more components were unqueryable or an external lookup
  failed.
- `no_supported_manifest`: the local static scanner found no supported package
  inventory (including OSV-Scanner's documented no-packages exit state).
- `no_package_inventory`: a supported manifest was present, but the scanner
  produced no package inventory; zero findings are therefore not a clean bill
  of health.

### Components without an exact version

Provider SBOMs often record what a manifest declares rather than what is
installed. GitHub's Dependency Graph lists `fastapi>=0.104.0` as a bare
`fastapi` with no version, and `uses: actions/checkout@v6` as `6.*.*`. OSV
can only match concrete versions, so PatchTriage:

1. restores dropped PyPI/npm ranges from the repository's
   `requirements*.txt`/`.in`, `requirements/*.txt`, `pyproject.toml` (PEP 621,
   PEP 735, Poetry, `build-system`) and `package.json`, read as text via
   GitHub's tree API and raw file host (the package's SPDX `sourceInfo` names
   the manifest);
2. chooses one registry release per constraint, from PyPI, npm, crates.io,
   RubyGems, NuGet, the Go module proxy, Packagist, or the action
   repository's public tags:
   - a range with a lower bound (`>=0.104.0`, `^1.2.3`, `~=2.0`) is checked at
     the **oldest release it permits**. The range still allows installing it,
     and raising that floor is the remediation;
   - a floating ref (`6.*.*`, `1.x`, `==1.2.*`) or a bare upper bound is
     checked at the **newest matching release**, which is what runs;
   - a dependency with no declared range is checked at the **newest release**.

Checking only the newest release would report almost nothing, because the
newest release is usually the patched one. The chosen version and its basis
are labelled *inferred* in the summary, decision path, and report, and
coverage stays `incomplete`: none of these is necessarily what is deployed.
Commit a lockfile or upload scanner output to assess exact versions.

Refs such as `release/v1` or `main`, unsupported range syntax (`||`), Maven,
and failed registry lookups stay unchecked and are named in the result. The
SPDX document's own subject (GitHub's `pkg:github/owner/repo@main`) is not
counted as a dependency. OSV's API does not compare GitHub Actions versions,
so actions are queried by name and OSV's affected ranges are evaluated
locally; a range that cannot be evaluated keeps the finding.

`No findings reported` describes the record count only. It is never converted
into “no vulnerabilities,” and any non-`complete` coverage status remains a
prominent warning in both the GUI and HTML report. The summary retains
component counts, query counts, failures, warnings, source hash, repository,
resolved commit when available, scanner/provider, and retrieval time.

## Local and hosted UI parity

Both deployments serve the same `INDEX_HTML` and API contract. `/api/config`
reports the deployment mode and available repository providers. The interface
does not fork into a separate local page; it adjusts the repository help text
and rejects unavailable acquisition paths with a specific error.

The GUI uses background assessment jobs (`POST .../runs`, then
`GET /api/jobs/{job_id}`) and persists completed summaries. A refresh restores
the current result. Replacing evidence or changing target/SSVC context deletes
the old summary and HTML report before another assessment.

## Configuration

The Docker Compose GUI enables the local generic importer by default:

```bash
docker compose up gui
```

To disable it locally:

```bash
PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES=false docker compose up gui
```

An internet-facing deployment should set:

```text
PATCHTRIAGE_DEPLOYMENT_MODE=public
PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES=false
PATCHTRIAGE_COOKIE_SECURE=true
```

In a local deployment, `GITHUB_TOKEN` or `GH_TOKEN` can raise the GitHub API
rate limit and authorize private GitHub repositories. The hosted anonymous
repository endpoint intentionally ignores those tokens. `NVD_API_KEY` raises
the NVD rate limit; it is not required to enable NVD enrichment.
