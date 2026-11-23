# PatchTriage architecture

This document maps the implementation: which module owns which step, where
the trust boundaries are, and how the CLI, GUI, and hosted deployment share
one engine. For how to use PatchTriage and how to read its results, see
[GUIDE.md](GUIDE.md); for the reviewer proof, see [VALIDATION.md](VALIDATION.md);
for repository acquisition, see [REPOSITORY_IMPORT.md](REPOSITORY_IMPORT.md);
for threats and mitigations, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Pipeline

```text
scanner JSON / SBOM / repository
  -> ingest -> deduplicate -> target context -> enrich
  -> SSVC Deployer decision -> BOD 26-04 response policy
  -> machine audit (and optional AI explanation)
  -> remediation plan -> evaluation -> JSON + self-contained HTML report
```

`src/patchtriage/assess.py` runs this sequence once for both the CLI and the
web GUI, so the two entry points cannot drift into separate business logic.

| Step | Module | Responsibility |
|---|---|---|
| Ingest | `ingest/parsers.py`, `ingest/sbom.py`, `ingest/versions.py` | Parse Trivy, Grype, OSV-Scanner and related scanner JSON; resolve SBOM components through OSV.dev; choose a concrete release when evidence gives only a version constraint. Unsupported or incomplete input stays visible as coverage. |
| Deduplicate | `dedup.py` | Merge aliases (CVE, GHSA) conservatively while keeping ecosystem, purl namespace, installed version, and asset identity apart. |
| Target context | `context.py`, `targets.py` | Apply organizational context (System Exposure, Mission Impact, Safety Impact) from the target registry or explicit input; record defaults and unknowns. |
| Enrich | `enrich/clients.py`, `enrich/vendors.py` | Add EPSS, CISA KEV, NVD, CISA Vulnrichment, and vendor advisories (MSRC, Red Hat, Ubuntu, Debian, GitHub). Exploit-DB is searched live per CVE and never written to disk. |
| Decide (SSVC) | `ssvc.py` | Deterministic CERT/CC Deployer model `ssvc:DT_DP:1.0.0`: Exploitation, System Exposure, Automatable, Human Impact -> Defer / Scheduled / Out-of-Cycle / Immediate. |
| Decide (policy) | `bod2604.py` | Separate CISA BOD 26-04 response policy `cisa:DT_BOD2604:1.0.0`, evaluated after SSVC and attached as `triage["bod2604"]` and `triage["effective"]`. Decision support, not a compliance attestation. |
| Audit and explain | `triage/engine.py`, `triage/audit.py`, `triage/providers.py` | Rules backend or optional AI provider explanations; the audit rejects claims that contradict evidence or the deterministic decision. AI never selects the outcome. |
| Plan | `plan.py` | Package-level action queue and deadlines. |
| Evaluate | `evalcmp.py` | Compare queue orderings on the supplied inventory. This is behavior on that dataset, not proof of effectiveness. |
| Report | `report/html.py`, `report/fleet.py`, `presentation.py` | Self-contained offline HTML (no CDN) and JSON; shared human-facing labels. |
| Data model | `models.py` | Pydantic models for findings, evidence, decisions, and actions. |

## Entry points

| Entry point | Code | Notes |
|---|---|---|
| CLI | `cli.py` (`patchtriage` = `patchtriage.cli:app`) | Commands: `run`, `remediate`, `setup`, `start`, `serve`, `verify`, `demo`, `fleet`. |
| Web GUI | `webapp/server.py`, `webapp/runner.py`, `webapp/page.py` | Standard-library HTTP server and a single self-contained page. Runs are asynchronous jobs (`/api/targets/<id>/runs`, `/api/jobs/<id>`) so a request never waits for a full assessment. |
| Fleet | `fleet.py`, `org.py`, `report/fleet.py` | Import a GitHub owner's repositories and aggregate one organization-wide view. |
| Repository acquisition | `repository.py`, `repository_local.py` | GitHub Dependency Graph SBOM export by default; opt-in local disposable clone plus OSV-Scanner for other public HTTPS Git hosts. Repository code is never executed. |
| Remediation | `remediation.py` | Operator-authorized only: clone the committed revision into an isolated workspace, update supported npm/Python manifests, refresh lockfiles with lifecycle scripts disabled, run requested checks, rescan. Never modifies the source checkout, pushes, merges, or deploys. |
| Reviewer proof | `validation.py`, `data/ssvc_validation.json` | `patchtriage verify`: 72 Deployer paths, 16 Human Impact pairs, context sensitivity, unknown context, repeatability, frozen end-to-end pipeline, and tamper detection, with SHA-256 fingerprints. BOD 26-04 conformance lives in `tests/test_bod2604.py`. |
| Offline demo | `cli.py demo`, `data/demo_*.json`, `data/demo_assets.yaml` | Bundled snapshots; no network and no keys. Kept separate from live caches. |

## Evidence, decisions, and explanations stay distinct

- Evidence keeps its source, retrieval time, and whether it is authoritative,
  confirmed, inferred, or defaulted. Lookup failure is not absence.
- The SSVC result, the BOD 26-04 result, and the effective action are stored
  separately; the effective action names the rule that determined it.
- CVSS and EPSS are supporting evidence. KEV membership informs Exploitation
  without bypassing the decision tree. No combined score is invented.
- AI output is untrusted text checked against evidence; provider failure keeps
  the deterministic result and reports the failure.

## State and storage

| Data | Location | Notes |
|---|---|---|
| User configuration and API keys | `~/.config/patchtriage/config.json`, or `PATCHTRIAGE_CONFIG_DIR` | Written atomically by `patchtriage setup`; values are mirrored into the process environment only when unset. |
| Provider cache | `PATCHTRIAGE_CACHE_DIR` | 24-hour cache for vendor feeds. Exploit-DB is never cached. |
| GUI sessions | `<config dir>/sessions/<workspace>/` | `HttpOnly; SameSite=Strict` session cookie, 6-hour retention, per-session and global job limits. |
| Reports | Paths passed to `--output` / `--html`; `./out` in Docker | Generated artifacts are git-ignored. |

## Deployment

- Local: `patchtriage serve` or `docker compose up --build gui`, bound to
  localhost and answering only loopback hosts unless
  `PATCHTRIAGE_ALLOWED_HOSTS` lists more.
- Hosted: `.github/workflows/deploy.yml` deploys **every push to `main`** to
  patch-triage.com (AWS Lightsail) in public mode
  (`PATCHTRIAGE_DEPLOYMENT_MODE=public`, generic repositories disabled, secure
  cookies) and checks `/api/config` `build_sha`. Its concurrency group cancels
  an in-progress deploy, so merges should be spaced out.
- CI (`.github/workflows/ci.yml`): pytest on Python 3.10-3.15 and Windows
  (`-m "not network"`), the Node GUI state test, the offline demo,
  `patchtriage verify --repeats 100`, the Docker Compose demo, and a
  non-blocking live-provider job.

See GUIDE.md "Deployment notes" for the public-mode settings and AI budget.
