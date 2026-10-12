# PatchTriage : Evidence-Driven Patch Prioritization

[![Black Hat Europe 2026](https://img.shields.io/badge/Black%20Hat%20Europe%202026-Arsenal-000000)](https://blackhat.com/europe/arsenal-overview.html)
[![Deploy](https://github.com/d01ki/PatchTriage/actions/workflows/deploy.yml/badge.svg)](https://github.com/d01ki/PatchTriage/actions/workflows/deploy.yml)
[![CI](https://github.com/d01ki/PatchTriage/actions/workflows/ci.yml/badge.svg)](https://github.com/d01ki/PatchTriage/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Decision model: CERT/CC SSVC Deployer](https://img.shields.io/badge/decision-CERT%2FCC%20SSVC%20Deployer-5b5bd6.svg)](https://certcc.github.io/SSVC/howto/deployer_tree/)

PatchTriage turns vulnerability scans or SBOMs into environment-specific patch
decisions. It deduplicates findings, adds exploitation and vendor evidence, and
applies the deterministic
[CERT/CC SSVC Deployer model](https://certcc.github.io/SSVC/howto/deployer_tree/)
to produce an action queue: **Immediate**, **Out-of-Cycle**, **Scheduled**, or
**Defer**.

> AI never chooses the SSVC outcome and never invents a score. Optional AI
> backends only explain; their claims are checked against the deterministic
> result.

**Live tool:** [patch-triage.com](https://patch-triage.com/) ·
**Demo video:** [youtu.be/UxSTwKSwf0U](https://youtu.be/UxSTwKSwf0U)

## Quick start (Windows PowerShell)

You need [Docker Desktop](https://www.docker.com/products/docker-desktop/) and
Git. Python is not required.

**1. Clone**

```powershell
git clone https://github.com/d01ki/PatchTriage
cd PatchTriage
```

**2. Set up** (builds the container image once)

```powershell
docker compose build
```

**3. Run** — pick one.

| | Command | Best for |
|---|---|---|
| A | `docker compose up -d gui` → open <http://localhost:8765> | Repository URL, file picker, reviewing results |
| B | `docker compose run --rm start` | Guided run in the terminal |
| C | `docker compose run --rm demo` | Offline demo, no network or keys |

**4. Open the report**

```powershell
Invoke-Item .\out\report.html        # B: guided run
Invoke-Item .\out\demo_report.html   # C: demo
```

**5. Stop** the GUI with `docker compose down` (targets and caches are kept).

### A. Web GUI

1. Select **+ Add target**, name the system, and answer the SSVC context you
   know (unknown is fine; it is flagged for confirmation).
2. Select **Import repository** and paste an HTTPS repository URL, or
   **Upload SBOM** to pick a scan/SBOM file.
3. Select **Run triage**, then **Open full report**.

### B. Guided terminal run

The wizard asks, in order (if it first asks **Run setup first?**, answer `n`;
keys come from the [optional settings](#optional-settings) below — see
[#22](https://github.com/d01ki/PatchTriage/issues/22)):

1. **Input** — a scan or SBOM path. The PatchTriage folder is visible to the
   container, so copy the file there first and enter its name:
   `Copy-Item C:\path\to\sbom.json .` → `sbom.json`
2. **Target context** — SSVC System Exposure, Mission Impact, Safety Impact
   (press Enter for `unknown`).
3. **Backend** — `rules` (deterministic) unless an AI provider is configured.
4. **Report** — written to `.\out\report.html` and `.\out\report.json`.
5. **Local patch** (optional) — prepare a dependency upgrade in an isolated
   clone.

Repository URLs are currently GUI-only in Docker (tracked in
[#19](https://github.com/d01ki/PatchTriage/issues/19)).

### Optional settings

Set these in the same PowerShell window before `docker compose ...`. All are
optional.

| Variable | Purpose |
|---|---|
| `$env:GITHUB_TOKEN = "..."` | Private repositories; higher GitHub rate limits |
| `$env:NVD_API_KEY = "..."` | Faster NVD enrichment |
| `$env:PATCHTRIAGE_AI_PROVIDER = "anthropic"` + `$env:ANTHROPIC_API_KEY = "..."` | AI explanations ([details](docs/GUIDE.md#optional-ai-explanations)) |
| `$env:PATCHTRIAGE_PORT = "9000"` | Use another GUI port |

### Inputs

Trivy, Grype, or osv-scanner JSON; CycloneDX or SPDX JSON SBOMs (resolved
online through [OSV.dev](https://osv.dev)); GitHub repository URLs (GUI).
A result marked **coverage incomplete** names what could not be checked — an
empty result is never proof of safety.

## Reading the result

| Outcome | Action | Workflow target |
|---|---|---:|
| Immediate | Act now | 3 days |
| Out-of-Cycle | Next available deployment opportunity | 14 days |
| Scheduled | Normal maintenance | 30 days |
| Defer | Monitor and reassess | 90 days |

Day targets are PatchTriage workflow defaults, not CERT/CC values. CISA
BOD 26-04 is evaluated separately next to SSVC and is decision support, not a
compliance attestation.

## More documentation

- [Guide](docs/GUIDE.md) — SSVC model, CISA Vulnrichment, BOD 26-04, fleet
  import, scripted `run` options, dependency remediation, evidence connectors,
  AI backends, deployment, limits, development
- [Repository import and coverage model](docs/REPOSITORY_IMPORT.md)
- [Reviewer validation protocol](docs/VALIDATION.md)

macOS/Linux users can use the same `docker compose` commands, or `./run.sh`.

## License

[Apache License 2.0](LICENSE)
