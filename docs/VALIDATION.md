# Reviewer Validation Protocol

This document defines the evidence that applies to the **current SSVC-based
implementation**. Earlier benchmark files remain in the repository as project
history, but are explicitly excluded from every current claim.

## What the offline proof establishes

Run from a clean checkout:

```bash
python -m pip install -e .
patchtriage verify --repeats 100 --output verification_report.json
```

The command requires no network and no API keys. It produces a machine-readable
report with seven checks:

| Check | Cases | Question answered |
|---|---:|---|
| Official SSVC Deployer table | 72 | Does every Exploitation / System Exposure / Automatable / Human Impact path match the published Deployer outcome? |
| Official Human Impact table | 16 | Does every Mission Impact / Safety Impact pair produce the published Human Impact? |
| Target-context mapping sensitivity | 3 | Do registry values reach the decision engine unchanged, and can context alone change the outcome for the same active CVE? |
| Unknown context | 1 | Are conservative defaults and required confirmations explicit instead of hidden? |
| Repeatability | `3 × repeats` | Does the same frozen evidence produce one and only one decision hash? |
| Frozen end-to-end pipeline | 3 findings | Do parse, deduplication, context, enrichment, triage, and audit agree across two complete runs? |
| Tamper detection | 4 alterations | Are altered outcome, action, deadline, and decision-path data detected? |

Expected values live in `src/patchtriage/data/ssvc_validation.json`, separate
from the implementation in `src/patchtriage/ssvc.py`. They were transcribed
from the published [CERT/CC SSVC Deployer decision
table](https://certcc.github.io/SSVC/howto/deployer_tree/) and [Human Impact
table](https://certcc.github.io/SSVC/reference/decision_points/human_impact/).
The report hashes both the expectation file and the engine source so the exact
artifacts under test are visible.

## The target-input falsification test

The strongest local test deliberately keeps these inputs identical:

- vulnerability: the bundled Trivy record for `CVE-2023-4911`;
- package and fixed version;
- exploitation evidence: frozen CISA KEV / Active;
- deterministic engine and SSVC model.

Each case is parsed from Trivy, mapped through the same conversion used by the
GUI, enriched from frozen snapshots, and sent through the production SSVC
backend. Only the target context is changed:

| Target context | Expected and observed SSVC outcome |
|---|---|
| Open, Mission Failure, Critical safety | Immediate |
| Controlled, MEF Failure, Critical safety | Out-of-Cycle |
| Small, Degraded mission, Negligible safety | Scheduled |

Automatable is held constant by the same official conservative `Yes` default
because the frozen evidence has no CVSS v4 `AU` value; it is not a target-wide
GUI input. If target input is ignored,
this test cannot pass: the three findings have the same vulnerability and
threat evidence but must produce three different published SSVC paths. Each row
in the JSON evidence records both
`target_context_entered` and `target_context_consumed`.

## How a reviewer should reproduce it

1. Record the repository commit SHA and use a clean environment.
2. Disconnect the network or provide no API credentials.
3. Run the command above twice. The repeat count may differ; it is recorded in
   the report but deliberately excluded from the decision fingerprint.
4. Confirm that every check is `passed: true`.
5. Compare `input_fingerprint` and `decision_fingerprint` between runs. Both
   must match. `generated_at` and environment metadata may differ.
6. Inspect the target-sensitivity observations and confirm that the entered and
   consumed context objects are identical.
7. Retain the JSON report as the review artifact. CI also publishes it as the
   `reviewer-verification` artifact on every change to `main` and every pull
   request.

The input manifest contains SHA-256 hashes for the official expectation data,
fixed scanner samples, frozen enrichment snapshots, target inventory, SSVC
engine, and GUI-to-engine target conversion.

## CISA BOD 26-04 policy checks

`patchtriage verify` covers the SSVC Deployer only; it is not BOD
verification. The separate BOD 26-04 policy (`cisa:DT_BOD2604:1.0.0`) is
checked by the offline test suite:

```bash
python -m pytest tests/test_bod2604.py -q
```

Expected outcomes live in `tests/fixtures/bod2604_decision_table.json`,
transcribed from the CERT/CC CSV (`data/csv/cisa/cisa_bod_26_04_1_0_0.csv`,
commit `396ade5`) together with that file's SHA-256. The tests compare all 16
input combinations and cover unresolved KEV lookups, CISA's
Automatable/Technical Impact default and its limits, Publicly Exposed staying
distinct from System Exposure, provisional outcomes, forensic-triage and
fix-on-upgrade obligations, and the named effective-deadline rules. Table
conformance does not establish legal compliance.

## Live evidence connectors and GUI views

The offline proof uses frozen snapshots, so live connectors are outside it.
NVD, CISA KEV, Vulnrichment, Microsoft, Red Hat, Ubuntu, Debian, GitHub and
Exploit-DB lookups are tested offline with mocked responses
(`tests/test_vendor_advisories.py`, `tests/test_enrichment_clients.py`),
including failure isolation. Exploit-DB is queried live per CVE and never
stored; an entry there is public PoC evidence for SSVC Exploitation, so live
runs can differ from the frozen demo. The GUI SBOM flow (add target, attach
SBOM, run, report) is covered offline against a mocked OSV.dev. The only
network-marked test (`python -m pytest tests -q -m network`) repeats that flow
against the live providers and can exceed its 60-second client timeout when
they are slow. CI runs it in a separate non-blocking job and excludes it from
the required unit tests with `-m "not network"`; report the exclusion when you
do the same locally.

The GUI decision-tree view draws branch outcomes supplied by the engine
(`ssvc.human_impact_branches`); `tests/test_web_enhancements.py` checks every
served branch against the Deployer table and the outcome counts against the
findings.

## What this proof does not establish

This is a conformance, input-propagation, integrity, and reproducibility proof.
It does **not** prove that the tool improves real-world remediation outcomes or
that an organization's context labels are correct. Those are external-validity
questions and need independently labeled data.

For a defensible outcome study, preregister and run a new prospective
evaluation:

1. Freeze a new scanner corpus, enrichment snapshots, target profiles, tool
   commit, and hashes before observing results.
2. Have target owners label System Exposure, Mission Impact, and Safety Impact
   without seeing PatchTriage output. Label vulnerability-specific Automatable
   independently from the target profile or adjudicate the tool's CVSS-based
   inference.
3. Have at least two independent security practitioners assign expected SSVC
   outcomes from the official tables; adjudicate disagreements and report
   inter-rater agreement.
4. Keep a holdout set that is not used while changing the implementation.
5. Predeclare primary metrics: exact SSVC outcome agreement and urgent-outcome
   precision/recall. Report queue reduction only at a declared urgent-recall
   threshold. Treat KEV recall and EPSS mass as secondary threat-evidence
   metrics, not SSVC ground truth.
6. Publish the raw permitted inputs, labels, adjudication record, environment,
   command, JSON outputs, and SHA-256 manifest.

Until that study exists, the historical benchmark is useful only as historical
engineering evidence and must not be described as performance of the current
SSVC engine.
