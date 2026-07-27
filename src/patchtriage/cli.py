"""PatchTriage CLI.

Quick start (reviewers: this needs NO network and NO API keys):

    patchtriage demo

First-time interactive setup and guided run:

    patchtriage setup     # asks for API keys step by step, validates, saves
    patchtriage start     # asks what to triage, runs, opens the report

Scriptable usage:

    patchtriage run trivy.json grype.json --assets assets.yaml \
        --html report.html -o report.json --triage cascade
"""

from __future__ import annotations

import glob as globmod
import json
import os
import shutil
import sys
import webbrowser
from importlib import resources
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import config as cfgmod
from .context import apply_context, load_inventory
from .dedup import dedup
from .enrich.clients import enrich
from .evalcmp import evaluate
from .ingest.parsers import load_file
from .models import Asset
from .plan import build_plan
from .presentation import priority_definition
from .report.html import render_html
from .ssvc import ssvc_order_key
from .triage.audit import audit_all
from .triage.engine import get_backend, run_triage, run_triage_batch

app = typer.Typer(add_completion=False, help="AI-assisted patch triage pipeline")
console = Console()


@app.callback()
def _load_config() -> None:
    """Export keys saved by `patchtriage setup` into the environment.

    Environment variables set by the user always take precedence.
    """
    # Never let a console that can't encode a character (e.g. cp932 on
    # Windows) crash a run: unencodable characters degrade to '?'.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (OSError, ValueError):
                pass
    cfgmod.apply_to_env()


def _pipeline(files, fmt, asset_override, inventory_path, use_nvd, nvd_api_key,
              triage_backend, model, limit, escalation_model=None, jobs=4,
              batch=False, vendor_sources="auto", github_token=None,
              use_vulnrichment=True):
    # Layer 1 - ingest
    raw = []
    for f in files:
        with console.status(f"reading {f} "
                            "(SBOMs are resolved online via OSV.dev)..."):
            replace_identity = bool(
                asset_override and asset_override.identifier)
            parsed = load_file(
                f, fmt=fmt,
                asset=asset_override if replace_identity else None,
            )
            if asset_override and not replace_identity:
                updates = {
                    key: value for key, value in {
                        "criticality": asset_override.criticality,
                        "internet_exposed": asset_override.internet_exposed,
                        "reachable": asset_override.reachable,
                        "runtime_observed": asset_override.runtime_observed,
                        "system_exposure": asset_override.system_exposure,
                        "automatable": asset_override.automatable,
                        "mission_impact": asset_override.mission_impact,
                        "safety_impact": asset_override.safety_impact,
                    }.items()
                    if value is not None and value != "unknown"
                }
                for raw_finding in parsed:
                    raw_finding.asset = raw_finding.asset.model_copy(
                        update=updates)
        console.print(f"[dim]ingested {len(parsed):>5} findings from {f}[/dim]")
        raw += parsed

    # Layer 2 - dedup
    findings = dedup(raw)
    console.print(f"[bold]{len(raw)} raw -> {len(findings)} deduplicated findings[/bold]")

    # Layer 4 - context (before triage so the AI sees it)
    if inventory_path:
        matched = apply_context(findings, load_inventory(inventory_path))
        console.print(f"[dim]asset context applied to {matched} findings "
                      f"from {inventory_path}[/dim]")

    # Layer 3 - enrich
    source_label = " + vendor advisories" if vendor_sources else ""
    with console.status(f"enriching with EPSS / CISA KEV / NVD{source_label}..."):
        enrich(findings, nvd_api_key=nvd_api_key, use_nvd=use_nvd,
               vendor_sources=vendor_sources, github_token=github_token,
               use_vulnrichment=use_vulnrichment)

    # Layer 5 - deterministic SSVC screening comes before --limit. Scanner
    # severity alone must never exclude a low-CVSS KEV or context-urgent item.
    rules_backend = get_backend("rules")
    run_triage(findings, rules_backend, jobs=1)
    ranked = sorted(findings, key=ssvc_order_key)
    subset = ranked[:limit] if limit else ranked
    if batch and triage_backend == "claude":
        run_triage_batch(subset, model or "claude-opus-4-8",
                         progress=lambda msg: console.print(f"[dim]{msg}[/dim]"))
    elif triage_backend != "rules":
        backend = get_backend(triage_backend, model, escalation_model)
        n_jobs = max(1, jobs)
        with console.status(f"triaging {len(subset)} findings via "
                            f"'{triage_backend}' ({n_jobs} workers)..."):
            run_triage(subset, backend, jobs=n_jobs)
        if triage_backend == "cascade":
            esc = sum(1 for f in subset
                      if (f.triage or {}).get("escalated"))
            console.print(f"[dim]cascade: {esc}/{len(subset)} findings "
                          f"escalated to the frontier model[/dim]")
    fell_back = sum(1 for f in subset
                    if (f.triage or {}).get("backend") == "rules_fallback")
    if fell_back:
        console.print(f"[yellow]{fell_back} findings fell back to the rules "
                      f"baseline after API errors (tagged in the report)[/yellow]")

    # Audit - every AI decision is machine-verified against its signals
    summary = audit_all(subset)
    if summary["flagged"]:
        console.print(f"[yellow]audit: {summary['verified']}/{summary['total']} "
                      f"decisions verified; {len(summary['flagged'])} flagged "
                      f"for human review:[/yellow]")
        for vid, flags in summary["flagged"][:10]:
            console.print(f"  [yellow]FLAG {vid}: {', '.join(flags)}[/yellow]")
    else:
        console.print(f"[green]audit: {summary['verified']}/{summary['total']} "
                      f"decisions verified against deterministic signals[/green]")

    # Layer 6 - plan
    actions = build_plan(subset)
    # practicality evaluation
    eval_rows = evaluate(subset)
    return findings, subset, actions, eval_rows


def _emit(findings, subset, actions, eval_rows, output, html):
    _print_actions(actions)
    _print_eval(eval_rows)
    if html:
        html_path = Path(html)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_html(subset, actions, eval_rows),
                             encoding="utf-8")
        console.print(f"HTML report: [bold]{html}[/bold]")
    if output:
        report = {
            "findings": [f.model_dump(mode="json") for f in findings],
            "actions": [a.model_dump(mode="json") for a in actions],
            "evaluation": [r.model_dump(mode="json") for r in eval_rows],
        }
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, default=str),
                               encoding="utf-8")
        console.print(f"JSON report: [bold]{output}[/bold]")


@app.command()
def run(
    files: list[Path] = typer.Argument(
        ..., help="Scanner JSON (Trivy/Grype/OSV) or CycloneDX/SPDX SBOM "
                  "(SBOMs are resolved online via OSV.dev)"),
    fmt: Optional[str] = typer.Option(None, help="Force format: trivy|grype|osv"),
    assets: Optional[Path] = typer.Option(None, help="Asset inventory YAML (Layer 4)"),
    asset_id: Optional[str] = typer.Option(None, help="Override asset identifier"),
    criticality: str = typer.Option("unknown", help="Asset criticality override"),
    exposed: Optional[bool] = typer.Option(
        None, "--exposed/--not-exposed", help="Asset internet exposure evidence"),
    ssvc_exposure: str = typer.Option(
        "unknown", "--ssvc-exposure",
        help="SSVC System Exposure: small|controlled|open|unknown"),
    ssvc_automatable: str = typer.Option(
        "unknown", "--ssvc-automatable",
        help="SSVC Automatable: yes|no|unknown"),
    ssvc_mission_impact: str = typer.Option(
        "unknown", "--ssvc-mission-impact",
        help="SSVC Mission Impact: degraded|mef_support_crippled|mef_failure|mission_failure|unknown"),
    ssvc_safety_impact: str = typer.Option(
        "unknown", "--ssvc-safety-impact",
        help="SSVC Safety Impact: negligible|marginal|critical|catastrophic|unknown"),
    reachable: Optional[bool] = typer.Option(
        None, "--reachable/--not-reachable",
        help="Static analysis says the vulnerable path is reachable"),
    runtime_observed: Optional[bool] = typer.Option(
        None, "--runtime-observed/--not-runtime-observed",
        help="eBPF/Falco/OpenTelemetry observed the component or path at runtime"),
    no_nvd: bool = typer.Option(
        False, "--no-nvd", help="Skip NVD (faster; EPSS/KEV only)"),
    no_vulnrichment: bool = typer.Option(
        False, "--no-vulnrichment",
        help="Skip CISA Vulnrichment SSVC decision points (Exploitation, "
             "Automatable, Technical Impact)"),
    nvd_api_key: Optional[str] = typer.Option(None, envvar="NVD_API_KEY"),
    vendor_sources: str = typer.Option(
        "auto", help="Vendor advisories: auto|all|msrc,rhsa,usn,debian,ghsa"),
    no_vendor_advisories: bool = typer.Option(
        False, "--no-vendor-advisories",
        help="Skip Microsoft/RHSA/USN/Debian/GHSA lookups"),
    github_token: Optional[str] = typer.Option(
        None, envvar="GITHUB_TOKEN",
        help="Optional GitHub token (raises GHSA API rate limits)"),
    triage: Optional[str] = typer.Option(
        None, help="Triage backend: rules|claude|cascade "
                   "(default: your `patchtriage setup` choice, else rules)"),
    model: Optional[str] = typer.Option(
        None, help="Model id (claude: triage model; cascade: screening model)"),
    escalation_model: Optional[str] = typer.Option(
        None, help="cascade only: frontier model for escalated findings"),
    jobs: int = typer.Option(4, help="Parallel API calls for claude/cascade"),
    batch: bool = typer.Option(
        False, "--batch",
        help="claude only: use the Message Batches API (50% cost, ~1h latency)"),
    output: Optional[Path] = typer.Option(None, "-o", help="Write full JSON report"),
    html: Optional[Path] = typer.Option(None, help="Write self-contained HTML dashboard"),
    limit: Optional[int] = typer.Option(
        None, help="Report top-N after deterministic SSVC screening"),
):
    """Ingest -> dedup -> context -> enrich -> triage -> plan -> report."""
    triage = triage or cfgmod.load().get("default_backend") or "rules"
    override = None
    if (asset_id or exposed is not None or reachable is not None
            or runtime_observed is not None or criticality != "unknown"
            or ssvc_exposure != "unknown" or ssvc_automatable != "unknown"
            or ssvc_mission_impact != "unknown"
            or ssvc_safety_impact != "unknown"):
        override = Asset(identifier=asset_id or "", kind="host",
                         criticality=criticality, internet_exposed=exposed,
                         reachable=reachable,
                         runtime_observed=runtime_observed,
                         system_exposure=ssvc_exposure,
                         automatable=ssvc_automatable,
                         mission_impact=ssvc_mission_impact,
                         safety_impact=ssvc_safety_impact)
    findings, subset, actions, eval_rows = _pipeline(
        files, fmt, override, assets, not no_nvd, nvd_api_key, triage, model,
        limit, escalation_model=escalation_model, jobs=jobs, batch=batch,
        vendor_sources=None if no_vendor_advisories else vendor_sources,
        github_token=github_token or os.environ.get("GH_TOKEN"),
        use_vulnrichment=not no_vulnrichment)
    _emit(findings, subset, actions, eval_rows, output, html)


@app.command()
def setup():
    """Interactive first-run wizard: enter API keys step by step, get them
    validated live, and save defaults to ~/.config/patchtriage/config.json.
    """
    cfg = cfgmod.load()
    console.print("\n[bold]PatchTriage setup[/bold] - press Enter to skip or "
                  "keep the current value.\n")
    # Hidden input requires a real terminal; piped/CI stdin would hang on
    # Windows' getpass, so fall back to visible input there.
    hidden = sys.stdin.isatty()

    # 1. Anthropic API key (enables the claude/cascade backends)
    current = cfg.get("ANTHROPIC_API_KEY", "")
    label = "Anthropic API key (sk-ant-...)"
    if current:
        label += f" [current: {cfgmod.mask(current)}]"
    while True:
        key = typer.prompt(label, default="", show_default=False,
                           hide_input=hidden).strip()
        if not key:
            key = current
            if not key:
                console.print("[dim]skipped - the deterministic 'rules' "
                              "backend needs no key[/dim]")
            break
        with console.status("validating key against the Anthropic API..."):
            ok, msg = cfgmod.validate_anthropic_key(key)
        if ok:
            console.print(f"[green]OK: {msg}[/green]")
            break
        console.print(f"[red]{msg}[/red]")
        if not typer.confirm("Try again?", default=True):
            key = current
            break
    if key:
        cfg["ANTHROPIC_API_KEY"] = key

    # 2. NVD API key (optional - only raises NVD rate limits)
    current_nvd = cfg.get("NVD_API_KEY", "")
    label = "NVD API key (optional, faster NVD enrichment)"
    if current_nvd:
        label += f" [current: {cfgmod.mask(current_nvd)}]"
    nvd = typer.prompt(label, default="", show_default=False,
                       hide_input=hidden).strip()
    if nvd:
        cfg["NVD_API_KEY"] = nvd

    # 3. GitHub token (optional - public GHSA works without one)
    current_github = cfg.get("GITHUB_TOKEN", "")
    label = "GitHub token (optional, raises GHSA advisory rate limits)"
    if current_github:
        label += f" [current: {cfgmod.mask(current_github)}]"
    github = typer.prompt(label, default="", show_default=False,
                          hide_input=hidden).strip()
    if github:
        cfg["GITHUB_TOKEN"] = github

    # 4. Default triage backend
    has_key = bool(cfg.get("ANTHROPIC_API_KEY"))
    choices = ["rules", "claude", "cascade"] if has_key else ["rules"]
    default_backend = cfg.get("default_backend",
                              "cascade" if has_key else "rules")
    if has_key:
        while True:
            backend = typer.prompt(
                f"Default triage backend {choices} - cascade screens with a "
                f"fast model and escalates only what matters",
                default=default_backend).strip().lower()
            if backend in choices:
                break
            console.print(f"[red]pick one of {choices}[/red]")
    else:
        backend = "rules"
    cfg["default_backend"] = backend

    path = cfgmod.save(cfg)
    console.print(f"\n[green]Saved to {path}[/green] "
                  "(environment variables always take precedence)")
    console.print("\nNext steps:\n"
                  "  [bold]patchtriage demo[/bold]   offline demo, no keys needed\n"
                  "  [bold]patchtriage start[/bold]  guided run on your own scans\n")


@app.command()
def start():
    """Guided run: answer a few questions, get a prioritized patch plan."""
    if not cfgmod.config_path().exists():
        console.print("[yellow]No saved configuration found.[/yellow]")
        if typer.confirm("Run setup first?", default=True):
            setup()
    cfgmod.apply_to_env()
    cfg = cfgmod.load()

    # 1. what to triage
    console.print("\n[bold]1. Input[/bold] - PatchTriage reads "
                  "Trivy / Grype / osv-scanner JSON, or a CycloneDX / SPDX "
                  "SBOM.\n[dim]No scans? Point it at an SBOM (e.g. GitHub's "
                  "SPDX export) - packages are resolved online via OSV.dev, "
                  "no local scanner needed.\nHave a scanner? "
                  "trivy image --format json -o trivy.json nginx:1.24[/dim]")
    while True:
        pattern = typer.prompt("Path or glob (e.g. scans/*.json)").strip()
        files = sorted(Path(p) for p in globmod.glob(pattern))
        if files:
            console.print(f"[dim]{len(files)} file(s): "
                          f"{', '.join(str(f) for f in files[:5])}"
                          f"{' ...' if len(files) > 5 else ''}[/dim]")
            break
        console.print(f"[red]no files match {pattern!r}[/red]")
        if os.name != "nt" and len(pattern) > 2 and pattern[1] == ":" \
                and pattern[2] in "\\/":
            console.print("[yellow]that looks like a Windows path, but this "
                          "is not a Windows machine - copy the file here "
                          "first (e.g. scp), or run patchtriage where the "
                          "file lives[/yellow]")

    # 2. environment context
    console.print("\n[bold]2. Asset context[/bold] - the same CVE on an "
                  "exposed checkout service and an internal batch box should "
                  "never rank the same.")
    assets_path = typer.prompt("assets.yaml inventory (Enter to skip)",
                               default="", show_default=False).strip()
    inventory = Path(assets_path) if assets_path else None
    override = None
    if inventory is None:
        def ask_ssvc(label: str, choices: tuple[str, ...]) -> str:
            while True:
                value = typer.prompt(
                    f"{label} [{' / '.join(choices)}]",
                    default="unknown",
                ).strip().lower().replace("-", "_")
                if value in choices:
                    return value
                console.print(f"[red]pick one of {', '.join(choices)}[/red]")

        exposure = ask_ssvc(
            "SSVC System Exposure", ("open", "controlled", "small", "unknown"))
        mission = ask_ssvc(
            "SSVC Mission Impact",
            ("mission_failure", "mef_failure", "mef_support_crippled",
             "degraded", "unknown"),
        )
        safety = ask_ssvc(
            "SSVC Safety Impact",
            ("catastrophic", "critical", "marginal", "negligible", "unknown"),
        )
        reachable = typer.confirm(
            "Is the vulnerable path confirmed reachable?", default=False)
        runtime_observed = typer.confirm(
            "Was the component/path observed at runtime?", default=False)
        if (any(value != "unknown" for value in
                (exposure, mission, safety))
                or reachable or runtime_observed):
            override = Asset(
                identifier="interactive", kind="host",
                system_exposure=exposure,
                mission_impact=mission, safety_impact=safety,
                reachable=reachable or None,
                runtime_observed=runtime_observed or None,
            )

    # 3. triage backend
    console.print("\n[bold]3. Triage backend[/bold]")
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    choices = ["rules", "claude", "cascade"] if has_key else ["rules"]
    if not has_key:
        console.print("[dim]no Anthropic key configured - run "
                      "`patchtriage setup` to enable claude/cascade[/dim]")
    default_backend = cfg.get("default_backend",
                              "cascade" if has_key else "rules")
    if default_backend not in choices:
        default_backend = choices[0]
    while True:
        backend = typer.prompt(f"Backend {choices}",
                               default=default_backend).strip().lower()
        if backend in choices:
            break
        console.print(f"[red]pick one of {choices}[/red]")

    use_nvd = typer.confirm(
        "Enrich with NVD (official CVSS/CWE - slower without an NVD key)?",
        default=bool(os.environ.get("NVD_API_KEY")))

    # 4. outputs
    console.print("\n[bold]4. Report[/bold]")
    html = typer.prompt("HTML report path", default="report.html").strip()
    output = typer.prompt("JSON report path", default="report.json").strip()

    try:
        findings, subset, actions, eval_rows = _pipeline(
            files, None, override, inventory, use_nvd,
            os.environ.get("NVD_API_KEY"), backend, None, None,
            vendor_sources="auto",
            github_token=(os.environ.get("GITHUB_TOKEN") or
                          os.environ.get("GH_TOKEN")))
    except ValueError as exc:  # unrecognized format
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    _emit(findings, subset, actions, eval_rows, Path(output), Path(html))
    _offer_browser(Path(html))


def _offer_browser(html: Path) -> None:
    """Offer to open the report — but never in a headless/container context."""
    resolved = html.resolve()
    if _is_headless():
        console.print(f"\n[bold]Open the report:[/bold] {resolved}")
        if _in_container():
            console.print("[dim](running in a container - open the file on "
                          "your host via the mounted volume)[/dim]")
        return
    if typer.confirm("Open the HTML report in your browser?", default=True):
        try:
            webbrowser.open(resolved.as_uri())
        except Exception:
            console.print(f"[dim]open it manually: {resolved}[/dim]")


def _in_container() -> bool:
    return (Path("/.dockerenv").exists()
            or os.environ.get("PATCHTRIAGE_IN_CONTAINER") == "1")


def _is_headless() -> bool:
    if _in_container():
        return True
    # Linux without a display server has no browser to open
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY") \
            and not os.environ.get("WAYLAND_DISPLAY"):
        return True
    return False


@app.command()
def serve(
    port: int = typer.Option(8765, help="Port to listen on"),
    host: str = typer.Option("127.0.0.1", help="Bind address"),
    no_browser: bool = typer.Option(False, "--no-browser",
                                    help="Don't auto-open a browser"),
):
    """Launch the local web console (GUI): register targets, import scans /
    SBOMs, run triage, and browse reports - each target links out to its
    system."""
    from .webapp import serve as _serve
    open_browser = not (no_browser or _is_headless())
    _serve(host=host, port=port, open_browser=open_browser)


@app.command()
def verify(
    output: Path = typer.Option(
        Path("verification_report.json"),
        help="Write the reviewer-readable JSON evidence report",
    ),
    repeats: int = typer.Option(
        25, min=2, max=1000,
        help="Repeat each fixed target-context decision this many times",
    ),
):
    """Verify SSVC conformance, target sensitivity, and reproducibility offline."""
    from .validation import write_validation_report

    with console.status("running offline reproducibility verification..."):
        report = write_validation_report(output, repeats=repeats)
    table = Table(title="Reviewer verification")
    table.add_column("Evidence")
    table.add_column("Cases", justify="right")
    table.add_column("Result")
    for check in report["checks"]:
        result = "[green]PASS[/green]" if check["passed"] else "[red]FAIL[/red]"
        table.add_row(check["name"].replace("_", " "), str(check["cases"]), result)
    console.print(table)
    console.print(f"Input fingerprint: [bold]{report['input_fingerprint']}[/bold]")
    console.print(f"Decision fingerprint: [bold]{report['decision_fingerprint']}[/bold]")
    console.print(f"JSON evidence: [bold]{output.resolve()}[/bold]")
    if report["status"] != "pass":
        raise typer.Exit(code=1)


@app.command()
def demo(
    html: Path = typer.Option(Path("demo_report.html"), help="HTML output path"),
    output: Path = typer.Option(Path("demo_report.json"), help="JSON output path"),
):
    """Fully offline demo: bundled scanner outputs + bundled EPSS/KEV/NVD snapshots.

    No network, no API keys. This is what reviewers should run first.
    """
    data = resources.files("patchtriage") / "data"
    tmp = Path(".patchtriage_demo")
    tmp.mkdir(exist_ok=True)

    # Seed the bundled snapshot into an ISOLATED cache dir, not the user's
    # real ~/.cache/patchtriage. The demo KEV/EPSS snapshot only covers a
    # handful of CVEs; writing it into the shared cache would silently break
    # KEV enrichment on real scans until the 24h TTL expired.
    demo_cache = (tmp / "cache").resolve()
    demo_cache.mkdir(parents=True, exist_ok=True)
    for src, dst in (("demo_epss.json", "epss.json"),
                     ("demo_kev.json", "kev.json"),
                     ("demo_nvd.json", "nvd.json"),
                     ("demo_vulnrichment.json", "vulnrichment.json")):
        (demo_cache / dst).write_text((data / src).read_text(encoding="utf-8"),
                                      encoding="utf-8")
    previous_cache_dir = os.environ.get("PATCHTRIAGE_CACHE_DIR")
    os.environ["PATCHTRIAGE_CACHE_DIR"] = str(demo_cache)
    console.print("[dim]using isolated offline enrichment snapshot in "
                  f"{demo_cache}[/dim]")

    fixtures = resources.files("patchtriage") / "data" / "fixtures"
    files = []
    for name in ("trivy_sample.json", "grype_sample.json"):
        p = tmp / name
        p.write_text((fixtures / name).read_text(encoding="utf-8"),
                     encoding="utf-8")
        files.append(p)
    assets_yaml = tmp / "assets.yaml"
    assets_yaml.write_text((data / "demo_assets.yaml").read_text(encoding="utf-8"),
                           encoding="utf-8")

    try:
        findings, subset, actions, eval_rows = _pipeline(
            files, None, None, assets_yaml, True, None, "rules", None, None,
            vendor_sources=None)
        _emit(findings, subset, actions, eval_rows, output, html)
    finally:
        if previous_cache_dir is None:
            os.environ.pop("PATCHTRIAGE_CACHE_DIR", None)
        else:
            os.environ["PATCHTRIAGE_CACHE_DIR"] = previous_cache_dir
        shutil.rmtree(tmp, ignore_errors=True)
    console.print("\n[bold green]Demo complete.[/bold green] Open "
                  f"[bold]{html}[/bold] in a browser. To try the AI backend: "
                  "export ANTHROPIC_API_KEY=... and re-run with "
                  "`patchtriage run ... --triage claude`.")


@app.command()
def fleet(
    owner_url: str = typer.Argument(
        ..., help="GitHub account URL, e.g. https://github.com/your-org"),
    limit: int = typer.Option(
        10, min=1, max=100,
        help="Repositories to import (most recently pushed first)"),
    include_forks: bool = typer.Option(
        False, "--include-forks", help="Also import forked repositories"),
    include_archived: bool = typer.Option(
        False, "--include-archived", help="Also import archived repositories"),
    no_assess: bool = typer.Option(
        False, "--no-assess",
        help="Import targets only; run assessments later (GUI or rerun)"),
    triage: str = typer.Option(
        "rules", help="Triage backend for the per-target assessments"),
    ssvc_exposure: str = typer.Option(
        "unknown", "--ssvc-exposure",
        help="Shared SSVC System Exposure for every imported target"),
    ssvc_mission_impact: str = typer.Option(
        "unknown", "--ssvc-mission-impact",
        help="Shared SSVC Mission Impact for every imported target"),
    ssvc_safety_impact: str = typer.Option(
        "unknown", "--ssvc-safety-impact",
        help="Shared SSVC Safety Impact for every imported target"),
    github_token: Optional[str] = typer.Option(
        None, envvar="GITHUB_TOKEN",
        help="Optional token (rate limits; local private repositories)"),
    output: Optional[Path] = typer.Option(
        None, "-o", help="Write the fleet rollup as JSON"),
    html: Path = typer.Option(
        Path("fleet_report.html"), help="Write the fleet HTML report"),
    no_nvd: bool = typer.Option(
        False, "--no-nvd", help="Skip NVD during assessment (faster)"),
):
    """Import a GitHub account's repositories and build one fleet queue.

    Every repository becomes a registered target with its Dependency Graph
    SBOM attached (identical provenance and boundaries to a single-repository
    import), each target is assessed by the deterministic SSVC engine, and
    the per-target results merge into one organization-wide, outcome-ordered
    action queue.
    """
    from . import targets as tstore
    from .fleet import aggregate_fleet, import_fleet
    from .report.fleet import render_fleet_html
    from .webapp.runner import run_target

    with console.status(
            f"listing and importing repositories from {owner_url}..."):
        report = import_fleet(
            owner_url,
            limit=limit,
            include_forks=include_forks,
            include_archived=include_archived,
            github_token=github_token,
            context={
                "system_exposure": ssvc_exposure,
                "mission_impact": ssvc_mission_impact,
                "safety_impact": ssvc_safety_impact,
            },
        )

    table = Table(title=f"Fleet import - {report['owner']}")
    for col in ("Repository", "Status", "Detail"):
        table.add_column(col)
    for row in report["results"]:
        status = row["status"]
        style = {"imported": "green", "already_imported": "cyan",
                 "failed": "red"}.get(status, "yellow")
        detail = str(row.get("error", ""))
        if status == "imported":
            detail = (f"{row.get('component_count', 0)} components "
                      f"({row.get('coverage_status', '')})")
        table.add_row(row["repository"], f"[{style}]{status}[/{style}]",
                      detail[:80])
    console.print(table)
    listing = report["listing"]
    skipped = listing["skipped_forks"] + listing["skipped_archived"]
    if skipped:
        console.print(
            f"[dim]skipped {listing['skipped_forks']} fork(s) and "
            f"{listing['skipped_archived']} archived; use --include-forks / "
            "--include-archived to import them[/dim]")
    for warning in listing["warnings"]:
        console.print(f"[yellow]note:[/yellow] {warning}")
    if report["stopped_reason"]:
        console.print(f"[red]stopped:[/red] {report['stopped_reason']}")

    fleet_ids = [row["target_id"] for row in report["results"]
                 if row.get("target_id")]
    if not fleet_ids:
        console.print("[red]no targets were imported; nothing to assess[/red]")
        raise typer.Exit(code=1)

    if not no_assess:
        failures = 0
        for index, target_id in enumerate(fleet_ids, 1):
            target = tstore.get_target(target_id)
            if target is None:
                continue
            label = f"[{index}/{len(fleet_ids)}] {target['name']}"
            try:
                with console.status(f"assessing {label}..."):
                    summary = run_target(
                        target, backend=triage, use_nvd=not no_nvd,
                        nvd_api_key=os.environ.get("NVD_API_KEY"))
                outcome = summary.get("outcomes") or {}
                console.print(
                    f"{label}: {summary.get('total', 0)} finding(s) - "
                    f"immediate {outcome.get('immediate', 0)}, "
                    f"out-of-cycle {outcome.get('out_of_cycle', 0)}")
            except Exception as exc:
                failures += 1
                console.print(f"[red]{label}: assessment failed - {exc}[/red]")
        if failures:
            console.print(
                f"[yellow]{failures} target(s) failed assessment; they are "
                "listed as not assessed in the fleet report[/yellow]")

    rollup = aggregate_fleet(target_ids=fleet_ids)
    outcomes = rollup["outcomes"]
    console.print(
        f"\n[bold]Fleet:[/bold] {rollup['targets_assessed']}/"
        f"{rollup['targets_total']} targets assessed - "
        f"[bold red]{outcomes['immediate']} immediate[/bold red], "
        f"[yellow]{outcomes['out_of_cycle']} out-of-cycle[/yellow], "
        f"{outcomes['scheduled']} scheduled, {outcomes['defer']} defer - "
        f"{rollup['kev_total']} on CISA KEV")
    if rollup["queue"]:
        queue_table = Table(title="Cross-target action queue (top 10)")
        for col in ("Outcome", "Target", "Action", "KEV", "Due"):
            queue_table.add_column(col)
        for entry in rollup["queue"][:10]:
            style = {"P1": "bold red", "P2": "yellow"}.get(
                entry.get("top_priority"), "")
            outcome_text = str(entry.get("outcome_label", ""))
            outcome_cell = (f"[{style}]{outcome_text}[/{style}]"
                            if style else outcome_text)
            queue_table.add_row(
                outcome_cell, entry.get("target_name", ""),
                str(entry.get("summary", ""))[:60],
                str(entry.get("kev_count") or "-"),
                f"{entry.get('deadline_days', 90)}d")
        console.print(queue_table)

    html.write_text(render_fleet_html(
        rollup, title=f"PatchTriage - Fleet Report - {report['owner']}"),
        encoding="utf-8")
    console.print(f"fleet HTML report: [bold]{html.resolve()}[/bold]")
    if output is not None:
        output.write_text(
            json.dumps({"import": report, "rollup": rollup}, indent=2),
            encoding="utf-8")
        console.print(f"fleet JSON rollup: [bold]{output.resolve()}[/bold]")


def _print_actions(actions) -> None:
    table = Table(title="Remediation plan - SSVC deployment outcome first")
    for col in ("#", "SSVC outcome", "Action", "CVEs", "KEV", "Due"):
        table.add_column(col)
    for i, a in enumerate(actions[:15], 1):
        style = {"P1": "bold red", "P2": "yellow"}.get(a.top_priority, "")
        priority = priority_definition(a.top_priority)
        pri_text = priority["ssvc_outcome"]
        pri = f"[{style}]{pri_text}[/{style}]" if style else pri_text
        table.add_row(str(i), pri, a.summary[:60], str(len(a.cves)),
                      str(a.kev_count) if a.kev_count else "-",
                      f"{a.deadline_days}d")
    console.print(table)


def _print_eval(rows) -> None:
    table = Table(title="Outcome check: CVSS vs EPSS vs KEV-first vs SSVC")
    for col in ("Budget", "KEV CVSS", "KEV EPSS", "KEV first", "KEV SSVC",
                "Urgent CVSS", "Urgent EPSS", "Urgent KEV", "Urgent SSVC"):
        table.add_column(col)
    for r in rows:
        best_kev = max(r.kev_baseline, r.kev_epss, r.kev_kev, r.kev_ssvc)
        best_urgent = max(
            r.urgent_cvss, r.urgent_epss, r.urgent_kev, r.urgent_ssvc
        )

        def best(value, maximum, text):
            return f"[bold green]{text}[/bold green]" if value == maximum else text

        table.add_row(
            f"top {r.k}",
            best(r.kev_baseline, best_kev, f"{r.kev_baseline}/{r.kev_total}"),
            best(r.kev_epss, best_kev, f"{r.kev_epss}/{r.kev_total}"),
            best(r.kev_kev, best_kev, f"{r.kev_kev}/{r.kev_total}"),
            best(r.kev_ssvc, best_kev, f"{r.kev_ssvc}/{r.kev_total}"),
            best(r.urgent_cvss, best_urgent,
                 f"{r.urgent_cvss}/{r.urgent_total}"),
            best(r.urgent_epss, best_urgent,
                 f"{r.urgent_epss}/{r.urgent_total}"),
            best(r.urgent_kev, best_urgent,
                 f"{r.urgent_kev}/{r.urgent_total}"),
            best(r.urgent_ssvc, best_urgent,
                 f"{r.urgent_ssvc}/{r.urgent_total}"),
        )
    console.print(table)


if __name__ == "__main__":
    app()
