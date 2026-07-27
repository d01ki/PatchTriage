# PatchTriage

[![Deploy](https://github.com/d01ki/PatchTriage/actions/workflows/deploy.yml/badge.svg)](https://github.com/d01ki/PatchTriage/actions/workflows/deploy.yml)
[![CI](https://github.com/d01ki/PatchTriage/actions/workflows/ci.yml/badge.svg)](https://github.com/d01ki/PatchTriage/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Decision model: CERT/CC SSVC Deployer](https://img.shields.io/badge/decision-CERT%2FCC%20SSVC%20Deployer-5b5bd6.svg)](https://certcc.github.io/SSVC/howto/deployer_tree/)

PatchTriage turns scanner evidence into environment-specific patch deployment
decisions. It ingests vulnerability scans or SBOMs, deduplicates findings,
adds exploitation and vendor evidence, and applies the deterministic
[CERT/CC SSVC Deployer model](https://certcc.github.io/SSVC/howto/deployer_tree/).

The output is a defensible action queue with one of four plain-language SSVC
outcomes: **Immediate**, **Out-of-Cycle**, **Scheduled**, or **Defer**.

**Live tool:** [https://patch-triage.com/](https://patch-triage.com/)

> AI never chooses the SSVC outcome and never invents a score. Optional AI
> backends can improve explanations and remediation guidance only. Their
> outcome, action, deadline, numeric claims, and remediation text are checked
> against the deterministic result and flagged when they conflict.

## Why PatchTriage uses SSVC

PatchTriage is an **SSVC-first patch deployment decision tool**. It implements
the published CERT/CC Deployer decision model (`ssvc:DT_DP:1.0.0`) rather than
inventing a proprietary risk score. For every finding, the engine records the
four decision points that determine deployment timing:

```text
Exploitation + System Exposure + Automatable + Human Impact
                              |
                              v
           Defer / Scheduled / Out-of-Cycle / Immediate
```

Mission Impact and Safety Impact are combined through the published Human
Impact table. CISA KEV can establish `Exploitation = Active`, but it does not
bypass the SSVC tree; EPSS and CVSS remain visible supporting evidence instead
of silently becoming a new score. Unknown inputs use the official conservative
defaults and are flagged for confirmation.

The implementation is checked offline against all **72 Deployer paths** and
all **16 Human Impact combinations** with `patchtriage verify`. See the
[reviewer validation protocol](docs/VALIDATION.md).

## DEMO

click 
[![Watch Demo](docs/demo.png)](https://youtu.be/UxSTwKSwf0U)

Or watch directly:
https://youtu.be/UxSTwKSwf0U


## Quick start with Docker

Docker is the shortest path to the GUI:

```bash
git clone https://github.com/d01ki/PatchTriage
cd PatchTriage
./run.sh
```

Open [http://localhost:8765](http://localhost:8765). The equivalent command is:

```bash
docker compose up gui
```

To make the locally running container use the repository access granted to a
GitHub token:

```bash
GITHUB_TOKEN=... docker compose up gui
```

Stop the console with `./run.sh --stop` or `docker compose down`. Targets,
attached evidence, reports, and caches persist in Docker volumes.

To run the bundled air-gapped demonstration instead:

```bash
docker compose run --rm demo
# HTML: ./out/demo_report.html
# JSON: ./out/demo_report.json
```

## Local installation

Python 3.10 or newer is required.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .\.venv\Scripts\Activate.ps1

python -m pip install -e .
patchtriage serve
```

The GUI opens at [http://127.0.0.1:8765](http://127.0.0.1:8765). If the
console script is not on `PATH`, use:

```bash
python -m patchtriage.cli serve
```

Useful entry points:

```bash
patchtriage serve       # GUI
patchtriage demo        # reproducible offline demo
patchtriage start       # guided CLI workflow
patchtriage run --help  # scriptable pipeline
patchtriage remediate   # create and verify an isolated dependency patch
patchtriage fleet URL   # import a GitHub org and build one fleet queue
patchtriage verify      # offline conformance and repeatability proof
```



The **Upload evidence** button accepts:

- Trivy JSON;
- Grype JSON;
- osv-scanner JSON;
- CycloneDX JSON SBOM;
- SPDX JSON SBOM.

Scanner JSON already contains vulnerabilities. An SBOM contains components,
not vulnerability findings, so PatchTriage resolves its packages through
[OSV.dev](https://osv.dev) before assessment. That SBOM path therefore needs
network access; the bundled demo does not.

The **Import repository** button has two acquisition paths behind the same GUI
and API contract:

- `github.com` URLs use GitHub's Dependency Graph SBOM API. Repository code is
  not cloned or executed. A local deployment reads `GITHUB_TOKEN` or `GH_TOKEN`
  from the environment and uses the repository access granted to that token.
- The local Docker GUI can also accept generic HTTPS Git URLs. It clones
  into a disposable directory with hooks, submodules, LFS, and interactive
  prompts disabled, then uses the pinned OSV-Scanner v2 binary in
  static source-scan mode. A trusted empty scanner configuration prevents the
  repository from supplying ignore rules. Package managers and repository code
  are never run.

A GitHub `tree/<ref>` is retained as provenance, but GitHub's SBOM endpoint is
repository-wide, so the result is marked partial instead of claiming a
ref-specific scan.

See [Repository import and coverage model](docs/REPOSITORY_IMPORT.md) for the
support matrix, threat boundary, coverage states, and deployment controls.

## Authoritative decision points: CISA Vulnrichment

The hardest SSVC inputs to answer are the vulnerability-specific ones. CISA
publishes them itself: through the **Vulnrichment** program it acts as an
Authorized Data Publisher on the CVE record, adding **Exploitation**,
**Automatable**, and **Technical Impact**. PatchTriage reads those decision
points straight from the official CVE record and prefers them over its own
heuristics, because "CISA assessed this" outranks "we inferred it".

What that changes, measured on a 12-CVE mix of KEV headliners and quiet
library CVEs:

| | Before | With Vulnrichment |
|---|---:|---:|
| Findings needing analyst confirmation | 12 / 12 | **3 / 12** |
| Automatable answered authoritatively | 0 | **9** |
| Corrected *down* from the conservative "assume Yes" | — | **4** |

That last row matters most: those four findings were being over-prioritized
by the conservative default. The bundled offline demo shows the same effect —
CVE-2023-4911 is KEV-listed, but CISA publishes Automatable = No for it
(local privilege escalation is not automatable at scale), so it lands on
**Out-of-Cycle** instead of Immediate.

Roughly half of all CVEs carry a Vulnrichment assessment. The rest keep the
existing honest behavior: the official conservative default, visibly flagged
for confirmation. Absence of an assessment is never read as absence of risk,
and a local exploit reference that contradicts a published `none` is surfaced
as a conflict rather than silently dropped.

Cached for a week on disk; `--no-vulnrichment` disables the lookup, and the
offline demo ships a bundled snapshot so it still needs no network.

## Fleet: assess an organization, not one repository

One deployed system is a *target*; an organization's repositories are a
*fleet*. The **Import organization…** button (GUI) and `patchtriage fleet`
(CLI) list a GitHub account's public repositories, turn each recently pushed
one into a target with its Dependency Graph SBOM attached — the exact same
no-clone, no-execution path and provenance rules as a single-repository
import — and merge the per-target SSVC results into one organization-wide,
outcome-ordered action queue.

```bash
patchtriage fleet https://github.com/your-org --limit 10 \
    --ssvc-exposure controlled --ssvc-mission-impact mef_support_crippled \
    --html fleet_report.html -o fleet.json
```

Boundaries, stated plainly:

- Aggregation never re-decides anything. Every finding's outcome was produced
  per target by the deterministic SSVC engine; the fleet view only merges and
  orders those results.
- Forks and archived repositories are skipped by default (`--include-forks`
  / `--include-archived` to opt in), and the listing reports exactly what was
  skipped or capped, so a fleet result is always explainable as "these
  repositories, chosen by this rule".
- Shared SSVC context supplied at import time is a starting point for
  triage, not a per-system assessment. Review each target's context in the
  GUI before treating its decision as final; unknown values use the official
  conservative defaults and stay flagged.
- One repository's failure (no dependency graph, too large) never aborts the
  rest; a provider rate limit or a target/quota ceiling stops the remainder
  visibly instead of half-succeeding in silence. Re-running an import is
  idempotent — already-imported repositories are recognized, not duplicated.
- Per-target coverage states carry into the fleet report, and unassessed
  targets are listed and excluded from every total, so an incomplete fleet
  can never look complete.

The hosted deployment caps repositories per import request
(`PATCHTRIAGE_MAX_FLEET_IMPORT_REPOS`, default 15) inside the existing
per-session target and evidence quotas, and its anonymous importer remains
public-repositories-only.

## What target context means

The GUI asks only for organizational inputs that belong to the official SSVC
Deployer method. Describe the deployed target and the credible consequence of
its failure, not the vulnerability itself.

| GUI field | What to assess | CERT/CC values | Default when unknown |
|---|---|---|---|
| System Exposure | How attackers can reach this deployed system | Small, Controlled, Open | Open |
| Mission Impact | Effect on Mission Essential Functions (MEFs) | Degraded, MEF Support Crippled, MEF Failure, Mission Failure | MEF Support Crippled |
| Safety Impact | Highest credible harm to people, systems, environment, finances, or well-being | Negligible, Marginal, Critical, Catastrophic | Marginal |

The SSVC engine evaluates the remaining decision points as follows:

- **Exploitation** is derived from authoritative threat evidence. A CISA KEV
  listing is Active; CISA's published Vulnrichment assessment is used next;
  public exploit evidence can establish Public PoC. The GUI lets an analyst
  confirm the value for each finding. An analyst input cannot downgrade
  authoritative CISA KEV Active evidence; a conflicting input is kept visible
  and flagged for confirmation.
- **Automatable** is vulnerability-specific. PatchTriage prefers CISA's
  published Vulnrichment value, then CVSS v4 `AU`. If neither is available,
  the official conservative default is Yes and the GUI asks an analyst to
  confirm or replace the value. It is intentionally not a target-wide field.
- **Human Impact** is derived by the published CERT/CC table from the target's
  Mission Impact and Safety Impact.

`Unknown` is a PatchTriage capture state, not an additional SSVC value. The
official conservative default is applied and the inferred field remains
visibly marked for confirmation.

Official definitions:

- [SSVC Deployer decision tree](https://certcc.github.io/SSVC/howto/deployer_tree/)
- [System Exposure](https://certcc.github.io/SSVC/reference/decision_points/system_exposure/)
- [Automatable](https://certcc.github.io/SSVC/reference/decision_points/automatable/)
- [Mission Impact](https://certcc.github.io/SSVC/reference/decision_points/mission_impact/)
- [Safety Impact](https://certcc.github.io/SSVC/reference/decision_points/safety_impact/)
- [Human Impact](https://certcc.github.io/SSVC/reference/decision_points/human_impact/)

## Reading the result

SSVC produces a categorical deployment decision, not a numerical risk score.

| Outcome | Plain-language action | PatchTriage operational target |
|---|---|---:|
| Immediate | Act now | 3 days |
| Out-of-Cycle | Use the next available deployment opportunity | 14 days |
| Scheduled | Include in normal maintenance | 30 days |
| Defer | Monitor and reassess | 90 days |

The day targets are PatchTriage workflow defaults; they are not additional
CERT/CC decision values. Organizations should map them to their own policy.

### Where GUI data is stored

The scan/SBOM upload and generated HTML report are processed on the machine
running PatchTriage and stored under its configuration directory. With Docker
Compose this is the `config` volume mounted at
`/home/patchtriage/.config/patchtriage`.

The web GUI assigns each browser a random HttpOnly session cookie. Targets,
uploads, run summaries, and reports are stored in a separate server directory for that
anonymous session, so one visitor cannot list or open another visitor's data.
Anonymous session data expires after six hours. Refreshing the page restores
the latest summary. Changing evidence, target context, or vulnerability-level
SSVC inputs invalidates the old summary and report before another run.

This is anonymous isolation, not user authentication. A person who obtains a
session cookie can access that session, so the public demo should not receive
confidential production scans. Use the local Docker deployment or add an
authentication proxy when assessing sensitive assets.

### Why Scheduled has no SSVC score

That is intentional. A Scheduled result is a complete SSVC outcome, not a
missing calculation. The GUI and HTML report still show:

- the four decision-point values and their evidence sources;
- confidence and any values that need confirmation;
- CVSS;
- EPSS 30-day probability;
- CISA KEV status;
- fixed-version availability;
- vendor advisories and the machine-audit result.

CVSS, EPSS, KEV, and fix availability remain visible as supporting evidence.
Inside the same outcome, the SSVC decision points are compared first, followed
by EPSS and CVSS tie-breakers. No values are added together into a score, and
no tie-breaker can override the categorical outcome.

### Zero findings and incomplete coverage

PatchTriage separates these states:

- **No findings reported** means a supplied scanner result contained no
  vulnerability records, or every queryable SBOM component was checked and no
  matching OSV record was returned.
- **Coverage incomplete or bounded** means at least one component lacked a
  usable package identity/version, an OSV batch/detail request failed, a
  provider returned no packages, no supported repository manifest was
  detected, or the original scanner/provider scope could not be independently
  verified.

A bounded result says exactly what was and was not checked, names the skipped
components, and gives the remedy — because "no findings" is the most
dangerous thing a scanner can display:

```text
10 of 21 component(s) were checked against OSV and none had a known
vulnerability. 11 component(s) could not be checked because the source lists
them without a resolved version: uvicorn, pytest, rich, fastapi, httpx and 6
more. Everything that could be checked was CI/workflow tooling, so no
application dependency was actually assessed. Commit a lockfile (uv.lock,
poetry.lock, package-lock.json, pinned requirements.txt) or upload scanner
output for full coverage.
```

That last warning matters most. **GitHub's Dependency Graph lists a
repository's dependencies without resolved versions when no lockfile is
committed**, and OSV cannot match a range. The entries that remain checkable
are then the GitHub Actions in your workflows — so a repository import can
report zero findings having examined nothing you actually ship. PatchTriage
says so rather than letting the empty result read as a clean bill of health.

Neither state is an SSVC Defer decision or proof that the target is secure.
Every non-`complete` status is highlighted in both the GUI and downloadable
HTML report. The result records total, queryable, queried, skipped, and failed
components so the operator can decide whether the evidence is sufficient.

## Bundled demo

The demo uses frozen Trivy, Grype, EPSS, CISA KEV, and NVD evidence, so it
works without a network or API key. Its three deduplicated findings illustrate
why severity alone is not the deployment decision:

| SSVC outcome | Vulnerability | Package | CVSS | EPSS | CISA KEV |
|---|---|---|---:|---:|---|
| Immediate | CVE-2023-4911 | libc6 | 7.8 | 0.856 | Yes |
| Scheduled | CVE-2024-3094 | xz-utils | 10.0 | 0.372 | No |
| Scheduled | CVE-2021-23337 | lodash | 7.2 | 0.018 | No |

The known-exploited finding is surfaced before the CVSS 10.0 finding, while
the exact outcome remains explainable from the SSVC path and target context.
This small demo proves pipeline behavior, not real-world effectiveness.

## Scriptable usage

```bash
# Scanner output to JSON and self-contained HTML reports
patchtriage run trivy.json grype.json \
  --assets assets.yaml \
  --html report.html \
  -o report.json

# SBOM to assessed findings through OSV.dev
patchtriage run sbom.spdx.json --html report.html

# Enter explicit target context without an inventory
patchtriage run trivy.json \
  --ssvc-exposure open \
  --ssvc-mission-impact mef_failure \
  --ssvc-safety-impact critical

# Skip slower NVD enrichment; retain EPSS and CISA KEV
patchtriage run trivy.json --no-nvd

# Query every vendor connector, or disable vendor advisories
patchtriage run trivy.json --vendor-sources all
patchtriage run trivy.json --no-vendor-advisories
```

An advanced `--ssvc-automatable yes|no` override exists for cases where an
analyst has established the value for the vulnerabilities in that run. Do not
use it as a generic property of the target.

Example `assets.yaml`:

```yaml
assets:
  - match: "web-frontend*"
    system_exposure: open
    mission_impact: mef_failure
    safety_impact: critical
```

Generate inputs with scanners you already use:

```bash
trivy image --format json -o trivy.json myorg/web-frontend:1.4
grype myorg/web-frontend:1.4 -o json > grype.json
osv-scanner scan source --format json --recursive ./repo > osv.json
```

## Apply and verify a dependency patch

`patchtriage remediate` turns a confirmed upgrade action from the JSON report
into a real repository diff. It clones the local repository's committed
`HEAD` into an isolated output directory, changes the dependency declaration,
refreshes a supported lockfile with package lifecycle scripts disabled, runs
the checks explicitly supplied by the operator, and rescans with OSV-Scanner
when it is available.

For a local guided workflow, run the command without arguments. It walks
through the report, local Git repository, upgrade action, verification
commands, and output directory, shows the execution plan for confirmation,
then prints the exact Git commands for reviewing or applying the patch:

```bash
patchtriage remediate
```

The existing `patchtriage start` wizard also offers this remediation step
after it creates a JSON and HTML triage report.

```bash
# 1. Produce findings and the package-level action queue.
patchtriage run osv.json -o report.json

# 2. Patch the highest-priority confirmed upgrade in an isolated clone.
patchtriage remediate report.json \
  --repository ./application \
  --output-dir ./out/application-remediation \
  --check "npm test"

# Select another report action when needed.
patchtriage remediate report.json \
  --repository ./application \
  --action-id 'upgrade:application:npm::lodash:4.17.20' \
  --output-dir ./out/lodash-remediation
```

The output contains:

- `workspace/`: a Git clone on a `patchtriage/<package>-<version>` branch;
- `remediation.patch`: the reviewable binary-safe Git diff;
- `remediation.json`: source commit, action, commands, changed files, scan
  result, and verification status;
- `osv-remediation.json`: the post-change scan when OSV-Scanner is available.

Direct dependency editing currently supports npm/pnpm `package.json`, Python
`requirements*.txt`, PEP 621 `pyproject.toml`, and Poetry dependency sections.
Lockfile refresh supports `package-lock.json`, `pnpm-lock.yaml`, and `uv.lock`
when their package-manager executable is installed. Unsupported lockfiles are
left unchanged and called out in the result. The command never modifies the
source checkout and never pushes, merges, or deploys a change.

Docker can work with a repository mounted from the host:

```bash
docker run --rm \
  -v "$PWD/application:/repo" \
  -v "$PWD/out:/out" \
  patchtriage remediate /out/report.json \
    --repository /repo \
    --output-dir /out/application-remediation
```

## Evidence connectors

Core enrichment uses EPSS, CISA KEV, and optionally NVD. Vendor connectors are
selected from package and distribution metadata by default.

| Source | Evidence returned |
|---|---|
| Microsoft MSRC | Update document and CVRF/CSAF reference |
| Red Hat RHSA | Advisory, severity, and released packages |
| Ubuntu USN | Advisory, affected packages, and fixed versions |
| Debian Security Tracker | Distribution release status and fixed versions |
| GitHub GHSA | Advisory, ecosystem packages, patched version, and vulnerable functions |

The public evidence connectors work without credentials. In a local
deployment, `GITHUB_TOKEN`/`GH_TOKEN` supplies the repository access granted
to that token and raises GitHub API rate limits; `NVD_API_KEY` raises the NVD
rate limit. Connector failures are recorded per finding and do not abort the
assessment.

## Optional AI explanations

The `ai` backend is provider-neutral. Choose exactly where finding evidence is
sent; PatchTriage never switches providers implicitly when more than one is
configured.

Anthropic:

```bash
python -m pip install -e ".[anthropic]"
export PATCHTRIAGE_AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY=...

patchtriage run trivy.json --triage ai --html report.html
patchtriage run trivy.json --triage cascade --html report.html
```

OpenAI:

```bash
export PATCHTRIAGE_AI_PROVIDER=openai
export OPENAI_API_KEY=...
export PATCHTRIAGE_AI_MODEL=<model-id>

patchtriage run trivy.json --triage ai --html report.html
```

OpenAI-compatible gateways and local runtimes such as Ollama:

```bash
export PATCHTRIAGE_AI_PROVIDER=ollama
export PATCHTRIAGE_AI_BASE_URL=http://localhost:11434/v1
export PATCHTRIAGE_AI_MODEL=<local-model-id>

patchtriage run trivy.json --triage ai --html report.html
```

- `rules`: deterministic SSVC only; default and suitable for CI.
- `ai`: deterministic SSVC plus a provider-generated explanation.
- `cascade`: screens every result and escalates only urgent, uncertain, or
  audit-failing explanations to the larger configured model.
- `claude`: deprecated compatibility alias for `ai --provider anthropic`.

If an API call fails, the finding falls back to deterministic output. The
audit rejects outcome, action, deadline, or signal claims that conflict with
the evidence.

## Pipeline

```text
scan JSON / SBOM
        |
        v
ingest -> deduplicate -> apply target context -> enrich threat/vendor evidence
        -> SSVC Deployer decision -> machine audit -> remediation plan
        -> JSON + self-contained HTML report
        -> isolated dependency patch -> checks + rescan -> reviewable diff
```

Aliases such as CVE and GHSA are merged conservatively. Correlation keeps the
package ecosystem, purl namespace, installed version, and asset identity, so
same-name packages or different installed versions are not silently combined.
Remediation version ordering handles common SemVer, PEP 440, Maven qualifier,
and Debian-style forms and retains conflicting candidates instead of
discarding them. Evidence
provenance is retained in the JSON result. The HTML report has no CDN
dependency and can be opened offline or attached to a review ticket.

## Reproducibility and reviewer verification

Run the current engine's offline proof from a clean checkout:

```bash
python -m pip install -e .
patchtriage verify --repeats 100 --output verification_report.json
```

The verification command checks:

- all 72 published SSVC Deployer decision-table paths;
- all 16 published Human Impact combinations;
- target-registry context reaching the production decision engine unchanged;
- conservative handling of unknown context;
- repeated deterministic decision hashes;
- the frozen end-to-end ingest-to-audit pipeline;
- detection of altered outcomes, actions, deadlines, and decision paths.

The output includes SHA-256 fingerprints for the expectation data, frozen
inputs, engine source, and decisions. Run it twice and compare
`input_fingerprint` and `decision_fingerprint`; timestamps and environment
metadata may differ.

See [docs/VALIDATION.md](docs/VALIDATION.md) for the reviewer protocol. Files
under `benchmarks/` are retained as historical engineering artifacts and are
not evidence of the current SSVC engine's real-world effectiveness.

## Deployment notes

The GUI binds to localhost by default. For a trusted container or platform
service, bind explicitly and supply its assigned port:

```bash
patchtriage serve --host 0.0.0.0 --port 8765 --no-browser
```

Do not use `patchtriage demo` as a web-service start command: it writes a
report and exits, so no port remains open. The production demo at
[patch-triage.com](https://patch-triage.com/) runs the same container entry
point on AWS Lightsail. Place any non-demo internet-facing instance behind the
access controls appropriate for vulnerability and asset data.

Use explicit deployment settings behind TLS termination:

```bash
PATCHTRIAGE_DEPLOYMENT_MODE=public
PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES=false
PATCHTRIAGE_COOKIE_SECURE=true
PATCHTRIAGE_BUILD_SHA=<deployed-git-sha>
```

`/api/config` exposes the application version, build SHA, UI schema version,
repository capabilities, retention, and anonymous-workspace limits. Local and
hosted deployments serve the same HTML and API; unavailable capabilities are
reported and disabled rather than implemented as a separate interface.

## Limits

- Automatic patching currently covers supported direct npm and Python
  dependency declarations; arbitrary source-level vulnerability fixes are not
  generated.
- Remediation creates an isolated review workspace and patch artifact. It does
  not push, merge, deploy, or modify the source checkout.
- It is not a replacement for a vulnerability scanner.
- No tool can correctly scan every repository URL or ecosystem. Unsupported,
  inaccessible, or insufficiently described inputs fail explicitly or
  produce `coverage_incomplete`; they are never presented as a clean result.
- An empty result is not proof that a target is secure.
- SSVC depends on accurate organizational context and current threat evidence.
- The built-in evaluation compares queue orderings on the supplied inventory;
  it is not independent ground truth for remediation effectiveness.
- Human review remains required for inferred inputs and important deployment
  decisions.

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
patchtriage verify --repeats 25 --output verification_report.json
```

## License

[Apache License 2.0](LICENSE)
