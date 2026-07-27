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
from .plan import Action, build_plan
from .presentation import priority_definition
from .report.html import render_html
from .ssvc import ssvc_order_key
from .triage.audit import audit_all
from .triage.engine import get_backend, run_triage, run_triage_batch
from .triage.providers import has_ai_configuration

app = typer.Typer(
    add_completion=False,
    help="SSVC patch triage and verified dependency remediation",
)
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
              ai_provider=None, ai_base_url=None, use_vulnrichment=True):
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
    with console.status(
            f"enriching with EPSS / CISA KEV / Vulnrichment / NVD{source_label}..."):
        enrich(findings, nvd_api_key=nvd_api_key, use_nvd=use_nvd,
               vendor_sources=vendor_sources, github_token=github_token,
               use_vulnrichment=use_vulnrichment)

    # Layer 5 - deterministic SSVC screening comes before --limit. Scanner
    # severity alone must never exclude a low-CVSS KEV or context-urgent item.
    rules_backend = get_backend("rules")
    run_triage(findings, rules_backend, jobs=1)
    ranked = sorted(findings, key=ssvc_order_key)
    subset = ranked[:limit] if limit else ranked
    if batch and triage_backend in {"ai", "claude"}:
        run_triage_batch(
            subset,
            model,
            progress=lambda msg: console.print(f"[dim]{msg}[/dim]"),
            provider=("anthropic" if triage_backend == "claude"
                      else ai_provider),
        )
    elif batch:
        raise ValueError(
            "--batch is supported only with the 'ai' backend and the "
            "Anthropic provider"
        )
    elif triage_backend != "rules":
        backend = get_backend(
            triage_backend,
            model,
            escalation_model,
            provider=ai_provider,
            base_url=ai_base_url,
        )
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
    _print_decision_quality(subset)
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
        None, help="Triage backend: rules|ai|cascade "
                   "(default: your `patchtriage setup` choice, else rules)"),
    provider: Optional[str] = typer.Option(
        None, "--provider",
        help="AI provider: anthropic|openai|openai-compatible|ollama"),
    ai_base_url: Optional[str] = typer.Option(
        None, "--ai-base-url",
        help="OpenAI-compatible API base URL (for gateways/local models)"),
    model: Optional[str] = typer.Option(
        None, help="Model id (ai: model; cascade: screening model)"),
    escalation_model: Optional[str] = typer.Option(
        None, help="cascade only: frontier model for escalated findings"),
    jobs: int = typer.Option(4, help="Parallel API calls for ai/cascade"),
    batch: bool = typer.Option(
        False, "--batch",
        help="Anthropic AI only: use the Message Batches API"),
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
        ai_provider=provider, ai_base_url=ai_base_url,
        use_vulnrichment=not no_vulnrichment)
    _emit(findings, subset, actions, eval_rows, output, html)


def _prompt_existing_path(
    label: str,
    *,
    default: str,
    directory: bool,
) -> Path:
    """Prompt until the operator provides an existing file or directory."""
    expected = "directory" if directory else "file"
    while True:
        value = typer.prompt(label, default=default).strip()
        path = Path(value).expanduser()
        if path.exists() and (
            path.is_dir() if directory else path.is_file()
        ):
            return path
        console.print(f"[red]{path} is not an existing {expected}[/red]")


def _upgrade_action_table(actions: list[Action]) -> None:
    table = Table(title="Confirmed dependency upgrades")
    table.add_column("#", justify="right")
    table.add_column("Priority")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("CVEs", justify="right")
    for index, action in enumerate(actions, start=1):
        table.add_row(
            str(index),
            action.top_priority,
            action.package,
            f"{action.installed_version or '?'} -> {action.target_version}",
            str(len(action.cves)),
        )
    console.print(table)


def _prompt_upgrade_action(report: Path) -> str:
    from .remediation import load_upgrade_actions

    actions = load_upgrade_actions(report)
    if not actions:
        raise ValueError("the report contains no confirmed upgrade action")
    _upgrade_action_table(actions)
    while True:
        selected = typer.prompt(
            "Upgrade number to patch",
            default=1,
        )
        try:
            index = int(selected)
        except (TypeError, ValueError):
            index = 0
        if 1 <= index <= len(actions):
            return actions[index - 1].action_id
        console.print(
            f"[red]pick a number from 1 to {len(actions)}[/red]"
        )


def _prompt_check_commands() -> list[str]:
    from .remediation import RemediationError, parse_check_command

    console.print(
        "\n[bold]Verification commands[/bold] - add one command at a time. "
        "Shell operators are not accepted; enter separate commands instead."
    )
    console.print(
        "[dim]Examples: npm test  |  python -m pytest  |  cargo test[/dim]"
    )
    checks: list[str] = []
    while True:
        value = typer.prompt(
            "Check command (Enter when done)",
            default="",
            show_default=False,
        ).strip()
        if not value:
            return checks
        try:
            parse_check_command(value)
        except RemediationError as exc:
            console.print(f"[red]{exc}[/red]")
            continue
        checks.append(value)


def _default_remediation_output(repository: Path) -> Path:
    repository = repository.resolve()
    return repository.parent / f"{repository.name}-patchtriage-remediation"


def _prompt_remediation_output(repository: Path) -> Path:
    default = _default_remediation_output(repository)
    while True:
        value = typer.prompt(
            "Output directory",
            default=str(default),
        ).strip()
        output = Path(value).expanduser().resolve()
        try:
            output.relative_to(repository.resolve())
        except ValueError:
            pass
        else:
            console.print(
                "[red]output must be outside the source repository[/red]"
            )
            continue
        if output.exists() and (
            not output.is_dir() or any(output.iterdir())
        ):
            console.print(
                "[red]output must be absent or an empty directory[/red]"
            )
            continue
        return output


def _print_remediation_result(result) -> None:
    style = "green" if result.status == "verified" else "yellow"
    console.print(
        f"[{style}]remediation: {result.status}[/{style}]\n"
        f"  action:    {result.action.summary}\n"
        f"  workspace: {result.workspace}\n"
        f"  patch:     {result.patch_file}\n"
        f"  files:     {', '.join(result.changed_files)}"
    )
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    if result.scan.remaining_cves:
        console.print(
            "[red]remaining target CVEs:[/red] "
            + ", ".join(result.scan.remaining_cves)
        )
    console.print("\n[bold]Local review commands[/bold]")
    commands = [
        f'git -C "{result.workspace}" diff --check',
        f'git -C "{result.workspace}" diff',
        f'git -C "{result.source_repository}" apply --check '
        f'"{result.patch_file}"',
        f'git -C "{result.source_repository}" apply "{result.patch_file}"',
    ]
    for command in commands:
        console.print(f"  {command}", markup=False)


def _execute_remediation_cli(
    report: Path,
    repository: Path,
    output_dir: Path,
    *,
    action_id: Optional[str],
    checks: list[str],
    refresh_lockfiles: bool,
    rescan: bool,
    scanner: Optional[str],
    timeout: int,
):
    from .remediation import RemediationError, execute_remediation

    try:
        result = execute_remediation(
            report,
            repository,
            output_dir,
            action_id=action_id,
            checks=checks,
            refresh_lockfiles=refresh_lockfiles,
            rescan=rescan,
            scanner_binary=scanner,
            timeout=timeout,
        )
    except RemediationError as exc:
        console.print(f"[red]remediation failed:[/red] {exc}")
        raise typer.Exit(code=1)
    _print_remediation_result(result)
    if result.status == "verification_failed":
        raise typer.Exit(code=2)
    return result


def _guided_remediation(
    report: Optional[Path],
    repository: Optional[Path],
    output_dir: Optional[Path],
    *,
    action_id: Optional[str],
    checks: Optional[list[str]],
    no_lock: bool,
    no_scan: bool,
    scanner: Optional[str],
    timeout: int,
):
    """Collect missing local remediation inputs and execute the patch."""
    from .remediation import RemediationError

    guided = report is None or repository is None
    console.print(
        "\n[bold]Local dependency remediation[/bold] - the source checkout "
        "stays unchanged; PatchTriage works in an isolated Git clone."
    )
    if report is None:
        report = _prompt_existing_path(
            "PatchTriage JSON report",
            default="report.json",
            directory=False,
        )
    elif not report.is_file():
        raise RemediationError(f"{report} is not an existing file")

    if repository is None:
        repository = _prompt_existing_path(
            "Local Git repository",
            default=".",
            directory=True,
        )
    elif not repository.is_dir():
        raise RemediationError(f"{repository} is not an existing directory")
    if not (repository / ".git").exists():
        raise RemediationError(
            f"{repository} is not a Git working tree"
        )

    if guided and action_id is None:
        action_id = _prompt_upgrade_action(report)
    if guided and checks is None:
        checks = _prompt_check_commands()
    checks = list(checks or ())

    if output_dir is None:
        if guided:
            output_dir = _prompt_remediation_output(repository)
        else:
            output_dir = _default_remediation_output(repository)

    refresh_lockfiles = not no_lock
    rescan = not no_scan
    if guided and not no_lock:
        refresh_lockfiles = typer.confirm(
            "Refresh a supported lockfile?", default=True
        )
    if guided and not no_scan:
        rescan = typer.confirm(
            "Rescan the isolated patch with OSV-Scanner when available?",
            default=True,
        )

    if guided:
        console.print("\n[bold]Execution plan[/bold]")
        console.print(f"  report:     {report}", markup=False)
        console.print(f"  repository: {repository}", markup=False)
        console.print(f"  output:     {output_dir}", markup=False)
        console.print(
            "  checks:     "
            + (", ".join(checks) if checks else "none"),
            markup=False,
        )
        if not typer.confirm("Create and verify this patch?", default=True):
            console.print("[yellow]remediation cancelled[/yellow]")
            return None

    return _execute_remediation_cli(
        report,
        repository,
        output_dir,
        action_id=action_id,
        checks=checks,
        refresh_lockfiles=refresh_lockfiles,
        rescan=rescan,
        scanner=scanner,
        timeout=timeout,
    )


@app.command()
def remediate(
    report: Optional[Path] = typer.Argument(
        None,
        help="PatchTriage JSON report; omit to use the local guided workflow",
    ),
    repository: Optional[Path] = typer.Option(
        None, "--repository", "-r",
        help="Local Git working tree; omit to be prompted",
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir", "-o",
        help="Empty/absent directory for the isolated workspace and artifacts",
    ),
    action_id: Optional[str] = typer.Option(
        None, "--action-id",
        help="Upgrade action to apply (default: highest-priority upgrade)",
    ),
    check: Optional[list[str]] = typer.Option(
        None, "--check",
        help="Verification command; repeat for multiple commands",
    ),
    no_lock: bool = typer.Option(
        False, "--no-lock", help="Do not refresh a detected supported lockfile",
    ),
    no_scan: bool = typer.Option(
        False, "--no-scan", help="Do not rescan the patched workspace",
    ),
    scanner: Optional[str] = typer.Option(
        None, "--scanner",
        help="OSV-Scanner executable path (auto-detected by default)",
    ),
    timeout: int = typer.Option(
        600, min=1, help="Per-command timeout in seconds",
    ),
):
    """Create and verify one dependency patch in an isolated local clone.

    The source checkout is never modified. The result directory contains a
    reviewable Git workspace, `remediation.patch`, `remediation.json`, and an
    OSV-Scanner result when the scanner is available. Nothing is pushed,
    merged, or deployed. Run without REPORT or --repository for a guided local
    workflow.
    """
    from .remediation import RemediationError

    try:
        _guided_remediation(
            report,
            repository,
            output_dir,
            action_id=action_id,
            checks=check,
            no_lock=no_lock,
            no_scan=no_scan,
            scanner=scanner,
            timeout=timeout,
        )
    except (RemediationError, ValueError, OSError) as exc:
        console.print(f"[red]remediation failed:[/red] {exc}")
        raise typer.Exit(code=1)


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

    # 1. Optional AI provider. Provider-specific credentials remain separate
    # so switching providers never silently sends evidence to another service.
    current_provider = str(cfg.get("PATCHTRIAGE_AI_PROVIDER") or "").lower()
    if not current_provider:
        if cfg.get("ANTHROPIC_API_KEY"):
            current_provider = "anthropic"
        elif cfg.get("OPENAI_API_KEY"):
            current_provider = "openai"
        else:
            current_provider = "rules"
    provider_choices = [
        "rules", "anthropic", "openai", "openai-compatible", "ollama",
    ]
    while True:
        selected_provider = typer.prompt(
            f"AI provider {provider_choices}",
            default=current_provider,
        ).strip().lower()
        if selected_provider in provider_choices:
            break
        console.print(f"[red]pick one of {provider_choices}[/red]")

    has_ai = selected_provider != "rules"
    if has_ai:
        cfg["PATCHTRIAGE_AI_PROVIDER"] = selected_provider
    else:
        cfg.pop("PATCHTRIAGE_AI_PROVIDER", None)

    if selected_provider == "anthropic":
        current = cfg.get("ANTHROPIC_API_KEY", "")
        label = "Anthropic API key (sk-ant-...)"
        if current:
            label += f" [current: {cfgmod.mask(current)}]"
        while True:
            key = typer.prompt(
                label, default="", show_default=False, hide_input=hidden
            ).strip() or current
            if not key:
                has_ai = False
                console.print("[dim]no key saved; using deterministic rules[/dim]")
                break
            with console.status("validating key against the Anthropic API..."):
                ok, msg = cfgmod.validate_anthropic_key(key)
            if ok:
                console.print(f"[green]OK: {msg}[/green]")
                cfg["ANTHROPIC_API_KEY"] = key
                break
            console.print(f"[red]{msg}[/red]")
            if not typer.confirm("Try again?", default=True):
                has_ai = bool(current)
                break
    elif selected_provider == "openai":
        current = cfg.get("OPENAI_API_KEY", "")
        label = "OpenAI API key"
        if current:
            label += f" [current: {cfgmod.mask(current)}]"
        while True:
            key = typer.prompt(
                label, default="", show_default=False, hide_input=hidden
            ).strip() or current
            if not key:
                has_ai = False
                console.print("[dim]no key saved; using deterministic rules[/dim]")
                break
            with console.status("validating key against the OpenAI API..."):
                ok, msg = cfgmod.validate_openai_key(key)
            if ok:
                console.print(f"[green]OK: {msg}[/green]")
                cfg["OPENAI_API_KEY"] = key
                break
            console.print(f"[red]{msg}[/red]")
            if not typer.confirm("Try again?", default=True):
                has_ai = bool(current)
                break
    elif selected_provider in {"openai-compatible", "ollama"}:
        default_url = (
            "http://localhost:11434/v1"
            if selected_provider == "ollama"
            else cfg.get("PATCHTRIAGE_AI_BASE_URL", "")
        )
        base_url = typer.prompt(
            "OpenAI-compatible API base URL", default=default_url
        ).strip()
        if not base_url:
            has_ai = False
            console.print("[dim]no base URL saved; using deterministic rules[/dim]")
        else:
            cfg["PATCHTRIAGE_AI_BASE_URL"] = base_url
        current = cfg.get("PATCHTRIAGE_AI_API_KEY", "")
        label = "Provider API key (Enter if the local endpoint needs no key)"
        if current:
            label += f" [current: {cfgmod.mask(current)}]"
        key = typer.prompt(
            label, default="", show_default=False, hide_input=hidden
        ).strip()
        if key:
            cfg["PATCHTRIAGE_AI_API_KEY"] = key

    if has_ai and selected_provider != "anthropic":
        model = typer.prompt(
            "AI model id",
            default=cfg.get("PATCHTRIAGE_AI_MODEL", ""),
        ).strip()
        if model:
            cfg["PATCHTRIAGE_AI_MODEL"] = model
        else:
            has_ai = False
            console.print("[dim]no model saved; using deterministic rules[/dim]")
    if not has_ai:
        cfg.pop("PATCHTRIAGE_AI_PROVIDER", None)

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
    choices = ["rules", "ai", "cascade"] if has_ai else ["rules"]
    default_backend = cfg.get("default_backend",
                              "cascade" if has_ai else "rules")
    if default_backend == "claude":
        default_backend = "ai"
    if has_ai:
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
    has_ai = has_ai_configuration()
    choices = ["rules", "ai", "cascade"] if has_ai else ["rules"]
    if not has_ai:
        console.print("[dim]no complete AI provider configuration - run "
                      "`patchtriage setup` to enable ai/cascade[/dim]")
    default_backend = cfg.get("default_backend",
                              "cascade" if has_ai else "rules")
    if default_backend == "claude":
        default_backend = "ai"
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
    if any(
        action.kind == "upgrade" and action.target_version
        for action in actions
    ):
        console.print(
            "\n[bold]5. Local patch[/bold] - PatchTriage can now prepare "
            "one confirmed dependency upgrade in an isolated Git clone."
        )
        if typer.confirm(
            "Continue to guided dependency remediation?",
            default=False,
        ):
            from .remediation import RemediationError

            try:
                _guided_remediation(
                    Path(output),
                    None,
                    None,
                    action_id=None,
                    checks=None,
                    no_lock=False,
                    no_scan=False,
                    scanner=None,
                    timeout=600,
                )
            except (RemediationError, ValueError, OSError) as exc:
                console.print(f"[red]remediation failed:[/red] {exc}")
                raise typer.Exit(code=1)


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
                  "configure a provider with `patchtriage setup` and re-run "
                  "with `patchtriage run ... --triage ai`.")


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


def _print_decision_quality(findings) -> None:
    """Say plainly how much of this run rests on authority vs assumption."""
    from .presentation import decision_quality

    quality = decision_quality(list(findings))
    if not quality["points_total"]:
        return
    console.print(
        f"\n[bold]Decision quality:[/bold] {quality['authoritative']}/"
        f"{quality['points_total']} vulnerability-specific inputs "
        f"({quality['authoritative_pct']}%) came from a published or "
        f"analyst-confirmed source; {quality['assumed']} used SSVC's "
        f"conservative default."
    )
    if quality["de_escalated"]:
        console.print(
            f"  [green]{quality['de_escalated']}[/green] finding(s) were "
            "de-escalated by a published CISA assessment (they would "
            "otherwise have been over-prioritized)."
        )
    if quality["needs_confirmation"]:
        console.print(
            f"  [yellow]{quality['needs_confirmation']}[/yellow] finding(s) "
            "need analyst confirmation."
        )


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
