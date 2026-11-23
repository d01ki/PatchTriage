# PatchTriage threat model

Scope: the PatchTriage CLI, the web GUI in local and public mode, the hosted
demo at patch-triage.com, and the CI/deploy workflows. Mitigations cite the
code or tests that implement them; items without such evidence are listed as
residual risks. Module responsibilities are described in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Assets

| Asset | Why it matters |
|---|---|
| Decision integrity (SSVC, BOD 26-04, effective action) | A wrong or silently altered outcome misdirects patching. |
| Scan contents, SBOMs, target context | Reveal an organization's software inventory and weaknesses. |
| Credentials: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `PATCHTRIAGE_AI_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN` / `GH_TOKEN` | Spend or access on the operator's behalf. Stored in `~/.config/patchtriage/config.json` or the environment. |
| Operator AI budget in public mode | Anonymous visitors could otherwise spend the operator's provider key. |
| Deploy credentials (`LIGHTSAIL_*` GitHub secrets) | Control of the production host. |
| Source checkout during remediation | Must not be modified outside the isolated workspace. |

## Trust boundaries

```text
browser (anonymous, public mode) --HTTP--> webapp/server.py
operator CLI ---------------------------> cli.py / assess.py
assess.py --> OSV, NVD, EPSS, KEV, Vulnrichment, vendor feeds, Exploit-DB  (untrusted responses)
assess.py --> optional AI provider                                          (untrusted output)
repository.py --> GitHub Dependency Graph SBOM export                       (untrusted SBOM)
repository_local.py --> disposable clone + OSV-Scanner (local opt-in only)  (untrusted repository)
remediation.py --> isolated workspace + package manager (operator-authorized)
GitHub Actions deploy.yml --> Lightsail over SSH (on every push to main)
```

All scanner files, SBOMs, advisories, repository content, and AI responses
are untrusted data, never instructions.

## Threats and mitigations (STRIDE)

| Category | Threat | Mitigation in code | Evidence |
|---|---|---|---|
| Spoofing | DNS rebinding against the local GUI | Host header must be loopback or listed in `PATCHTRIAGE_ALLOWED_HOSTS` (`_host_allowed`) | `tests/test_security_hardening.py` (`test_rebinding_host_is_refused_locally`, `test_configured_public_hostname`) |
| Spoofing | Hosted importer used to read private repositories | Public mode never passes the service token to anonymous imports | `test_public_mode_import_token_blocks_the_service_token` |
| Tampering | Altered outcomes, actions, deadlines, or decision paths | Pinned expectation data separate from the engine; fingerprints and tamper checks | `patchtriage verify`, `tests/test_ssvc.py`, `tests/test_bod2604.py`, [VALIDATION.md](VALIDATION.md) |
| Tampering | AI explanation contradicts evidence or changes the outcome | AI never selects outcomes; audit rejects contradictory claims; deterministic fallback on provider failure | `triage/audit.py`, `tests/test_triage_backends.py` |
| Tampering | Prompt injection through advisories or scan text into AI output | AI text is checked against evidence; links and commands in AI output are flagged | `test_ai_links_and_commands_are_flagged` |
| Tampering | Repository-local config suppresses findings or runs code | Trusted empty OSV-Scanner config; hooks, submodules, LFS, credential helpers disabled; no build or package-manager commands | `repository_local.py`, `tests/test_repository_local.py`, [REPOSITORY_IMPORT.md](REPOSITORY_IMPORT.md) |
| Tampering | Remediation writes outside the isolated clone or leaks environment | Clone of the committed revision; allowlisted environment (`PATCHTRIAGE_REMEDIATION_PASS_ENV` to extend); lifecycle scripts disabled | `remediation.py`, `tests/test_remediation.py` |
| Repudiation | A decision cannot be explained later | Decision record keeps inputs, provenance, defaults, model version, and matching path | `ssvc.py`, `bod2604.py`, JSON report |
| Information disclosure | Cross-session data exposure | Per-session workspaces, `HttpOnly; SameSite=Strict` cookie (`Secure` per `PATCHTRIAGE_COOKIE_SECURE`, default `auto`), cookie-less reads create no session | `test_cookie_less_reads_create_no_session_directories`, `test_report_lookup_without_a_session_creates_no_directory`, `tests/test_cache_isolation.py` |
| Information disclosure | Secret in configuration or logs | Atomic config writes; non-string or non-object config ignored; keys masked for display (`config.mask`) | `tests/test_config.py`, `test_config_save_is_atomic_and_leaves_no_temp_file` |
| Information disclosure | Untrusted text rendered as HTML | `html.escape` in `report/html.py` and `report/fleet.py`; `esc()` in `webapp/page.py` | `tests/test_web_enhancements.py` |
| Information disclosure | SSRF through repository URLs | Hosted mode uses the allowlisted GitHub API only; local generic clone requires HTTPS, public IPs, connects to checked addresses | `tests/test_repository.py`, `test_clone_connects_to_the_checked_addresses` |
| Denial of service | Large uploads, slow bodies, many sessions or jobs | Request/source/session byte limits, connection slots, stalled-body timeout, session capacity, per-session and global job limits, finding limits marked incomplete | `webapp/server.py` `MAX_*` settings, `test_stalled_body_times_out`, `test_connection_limit_releases_slots`, `test_public_mode_refuses_new_sessions_at_capacity`, `test_finding_limit_marks_the_run_incomplete` |
| Denial of service / cost | Anonymous use of the operator's AI key | Public AI is opt-in (`PATCHTRIAGE_PUBLIC_AI=true`) with a server-wide hourly run budget and a per-run finding cap | `test_ai_requires_opt_in_when_public` and the budget tests in `tests/test_security_hardening.py` |
| Elevation of privilege | Imported repository code executes | Imports never run repository code or lifecycle scripts; remediation checks run only through the explicit operator workflow | [REPOSITORY_IMPORT.md](REPOSITORY_IMPORT.md), `remediation.py` |
| Elevation of privilege | Compromised CI action or base image | Actions pinned to commit SHAs, base images pinned by digest; Dependabot proposes updates | `.github/workflows/*.yml`, `.github/dependabot.yml` |

## AI-assisted development risks

PatchTriage is also developed with AI coding agents. The same rules apply to
that workflow:

- Repository content, scan fixtures, advisories, and web pages read during
  development are untrusted and cannot authorize actions.
- A change to `ssvc.py`, `bod2604.py`, `data/ssvc_validation.json`, or the
  effective-action rules needs explicit intent, independent expectation data,
  and the conformance checks in [VALIDATION.md](VALIDATION.md). Expected
  results must never be generated from the engine under test.
- Merging to `main` deploys production, so merge and push require human
  approval; agent tooling must not merge on its own.
- Agent permission rules are prefix-based and are not a security boundary;
  CI, branch protection, and review remain the enforcement layers.

## Residual risks and review triggers

- The workflows in `.github/workflows/` run no secret scan or dependency
  vulnerability audit. Pull requests also show a GitGuardian secret check from
  a GitHub App, which is configured outside this repository. Python
  dependencies are lower bounds resolved at build time.
- Every push to `main` deploys production; there is no path filter and no
  manual approval gate in `deploy.yml`.
- The local generic-Git scanner relies on application-level checks, not an
  egress firewall; it is therefore disabled in public mode.
- The hosted demo has no authentication; it is not intended for confidential
  scans.
- External provider data can be wrong or stale; provenance is shown, but its
  correctness is not verified.

Reassess this model when adding an entry point, an external provider, an AI
capability, a deployment mode, authentication, or persistent storage.
