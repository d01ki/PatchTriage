"""Create reviewable dependency patches from PatchTriage action reports.

Remediation is deliberately separated from repository evidence acquisition.
It operates only on a repository path explicitly supplied by the operator,
clones the current committed revision into an isolated workspace, updates
supported dependency manifests, refreshes supported lockfiles with lifecycle
scripts disabled, runs explicitly requested checks, and optionally rescans the
workspace with OSV-Scanner.

The source checkout is never modified and this module never pushes, merges, or
deploys a change.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Iterable

from pydantic import BaseModel, Field

from .ingest.parsers import load_file
from .plan import Action


DEFAULT_COMMAND_TIMEOUT = 10 * 60
_SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn", ".tox", ".venv", "node_modules", "vendor",
}
_DEPENDENCY_SECTIONS = {
    "dependencies", "devDependencies", "optionalDependencies",
    "peerDependencies",
}
_PYPROJECT_ARRAY_SECTIONS = {
    "project", "project.optional-dependencies", "dependency-groups",
}
_REQUIREMENT = re.compile(
    r"^(?P<indent>\s*)(?P<name>[A-Za-z0-9_.-]+)"
    r"(?P<extras>\[[^\]]+\])?"
    r"(?P<spec>\s*(?:(?:===|==|~=|!=|<=|>=|<|>)[^;#]*)?)"
    r"(?P<marker>\s*;[^#]*)?"
    r"(?P<comment>\s+#.*)?$"
)
_QUOTED_DEPENDENCY = re.compile(
    r"(?P<quote>['\"])(?P<name>[A-Za-z0-9_.-]+)"
    r"(?P<extras>\[[^\]]+\])?"
    r"(?P<spec>(?:(?:===|==|~=|!=|<=|>=|<|>)[^'\"]*)?)"
    r"(?P=quote)"
)
_POETRY_DEPENDENCY = re.compile(
    r"^(?P<indent>\s*)(?P<name>[A-Za-z0-9_.-]+)\s*=\s*"
    r"(?P<value>.+?)(?P<comment>\s+#.*)?$"
)


class RemediationError(RuntimeError):
    """The requested patch could not be prepared safely."""


class CommandRecord(BaseModel):
    command: list[str]
    cwd: str
    exit_code: int
    duration_seconds: float
    kind: str


class ScanRecord(BaseModel):
    status: str = "skipped"
    scanner: str = ""
    output: str = ""
    remaining_cves: list[str] = Field(default_factory=list)


class RemediationResult(BaseModel):
    status: str
    action: Action
    source_repository: str
    source_commit: str
    branch: str
    workspace: str
    changed_files: list[str]
    patch_file: str
    commands: list[CommandRecord] = Field(default_factory=list)
    scan: ScanRecord = Field(default_factory=ScanRecord)
    warnings: list[str] = Field(default_factory=list)


Runner = Callable[..., subprocess.CompletedProcess]


def _normalized_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _iter_files(root: Path, names: Iterable[str],
                prefixes: Iterable[str] = ()) -> Iterable[Path]:
    exact = {name.casefold() for name in names}
    lowered_prefixes = tuple(prefix.casefold() for prefix in prefixes)
    for directory, dirs, files in os.walk(root):
        dirs[:] = [
            name for name in dirs
            if name not in _SKIP_DIRECTORIES
        ]
        base = Path(directory)
        for filename in files:
            lowered = filename.casefold()
            if lowered in exact or lowered.startswith(lowered_prefixes):
                yield base / filename


def _write_if_changed(path: Path, before: str, after: str) -> bool:
    if after == before:
        return False
    path.write_text(after, encoding="utf-8")
    return True


def _update_package_json(path: Path, package: str,
                         target_version: str) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemediationError(f"could not read {path}: {exc}") from exc
    changed = False
    for section in _DEPENDENCY_SECTIONS:
        dependencies = data.get(section)
        if not isinstance(dependencies, dict):
            continue
        for name in list(dependencies):
            if _normalized_package(name) != _normalized_package(package):
                continue
            value = dependencies[name]
            if not isinstance(value, str):
                raise RemediationError(
                    f"{path}: dependency {name} is not a string"
                )
            if value.startswith((
                "file:", "git+", "http:", "https:", "workspace:",
            )):
                raise RemediationError(
                    f"{path}: dependency {name} uses a non-registry source"
                )
            if value != target_version:
                dependencies[name] = target_version
                changed = True
    if not changed:
        return False
    before = path.read_text(encoding="utf-8")
    indent = 4 if "\n    \"" in before else 2
    trailing_newline = "\n" if before.endswith("\n") else ""
    after = json.dumps(data, indent=indent, ensure_ascii=False) + trailing_newline
    path.write_text(after, encoding="utf-8")
    return True


def _update_requirements(path: Path, package: str,
                         target_version: str) -> bool:
    before = path.read_text(encoding="utf-8")
    output: list[str] = []
    changed = False
    for line in before.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        content = line[:-1] if newline else line
        match = _REQUIREMENT.match(content)
        if (not match or _normalized_package(match.group("name"))
                != _normalized_package(package)):
            output.append(line)
            continue
        replacement = (
            f"{match.group('indent')}{match.group('name')}"
            f"{match.group('extras') or ''}=={target_version}"
            f"{match.group('marker') or ''}{match.group('comment') or ''}"
            f"{newline}"
        )
        output.append(replacement)
        changed = changed or replacement != line
    return _write_if_changed(path, before, "".join(output)) if changed else False


def _replace_quoted_dependency(line: str, package: str,
                               target_version: str) -> tuple[str, bool]:
    changed = False

    def replace(match: re.Match) -> str:
        nonlocal changed
        if (_normalized_package(match.group("name"))
                != _normalized_package(package)):
            return match.group(0)
        changed = True
        return (
            f"{match.group('quote')}{match.group('name')}"
            f"{match.group('extras') or ''}=={target_version}"
            f"{match.group('quote')}"
        )

    return _QUOTED_DEPENDENCY.sub(replace, line), changed


def _replace_poetry_dependency(line: str, package: str,
                               target_version: str) -> tuple[str, bool]:
    match = _POETRY_DEPENDENCY.match(line.rstrip("\n"))
    if (not match or _normalized_package(match.group("name"))
            != _normalized_package(package)):
        return line, False
    value = match.group("value").strip()
    if value.startswith("{"):
        replaced, count = re.subn(
            r"(version\s*=\s*)['\"][^'\"]*['\"]",
            rf'\1"{target_version}"',
            value,
            count=1,
        )
        if count != 1:
            raise RemediationError(
                "Poetry inline dependency has no editable version field"
            )
        value = replaced
    elif value[:1] in {"'", '"'}:
        quote = value[0]
        value = f"{quote}{target_version}{quote}"
    else:
        raise RemediationError(
            "Poetry dependency uses an unsupported non-string constraint"
        )
    newline = "\n" if line.endswith("\n") else ""
    return (
        f"{match.group('indent')}{match.group('name')} = {value}"
        f"{match.group('comment') or ''}{newline}",
        True,
    )


def _update_pyproject(path: Path, package: str,
                      target_version: str) -> bool:
    before = path.read_text(encoding="utf-8")
    section = ""
    output: list[str] = []
    changed = False
    in_project_dependencies = False
    for line in before.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]").strip().casefold()
            in_project_dependencies = False
            output.append(line)
            continue
        process_array = False
        if section == "project":
            if (not in_project_dependencies
                    and re.match(r"^\s*dependencies\s*=", line)):
                in_project_dependencies = True
            process_array = in_project_dependencies
        elif (
            section in _PYPROJECT_ARRAY_SECTIONS
            or section.startswith("project.optional-dependencies")
            or section.startswith("dependency-groups")
        ):
            process_array = True
        if process_array:
            line, line_changed = _replace_quoted_dependency(
                line, package, target_version
            )
            if section == "project" and "]" in line:
                in_project_dependencies = False
        elif (
            section == "tool.poetry.dependencies"
            or (
                section.startswith("tool.poetry.group.")
                and section.endswith(".dependencies")
            )
        ):
            line, line_changed = _replace_poetry_dependency(
                line, package, target_version
            )
        else:
            line_changed = False
        changed = changed or line_changed
        output.append(line)
    return _write_if_changed(path, before, "".join(output)) if changed else False


def update_dependency_manifests(workspace: Path, action: Action) -> list[Path]:
    """Update supported direct dependency declarations for one action."""
    if action.kind != "upgrade" or not action.target_version:
        raise RemediationError("the selected action has no confirmed upgrade")
    ecosystem = action.ecosystem.casefold()
    changed: list[Path] = []
    if ecosystem in {"npm", "node", "javascript"}:
        for path in _iter_files(workspace, {"package.json"}):
            if _update_package_json(path, action.package, action.target_version):
                changed.append(path)
    elif ecosystem in {"pypi", "python", "pip"}:
        for path in _iter_files(workspace, {"pyproject.toml"}):
            if _update_pyproject(path, action.package, action.target_version):
                changed.append(path)
        for path in _iter_files(
            workspace,
            {"requirements.txt"},
            prefixes=("requirements-", "requirements."),
        ):
            if _update_requirements(path, action.package, action.target_version):
                changed.append(path)
    else:
        raise RemediationError(
            f"automatic remediation is not supported for ecosystem "
            f"{action.ecosystem!r}"
        )
    if not changed:
        raise RemediationError(
            f"no supported direct declaration of {action.package!r} was found"
        )
    return sorted(set(changed))


def _nearest_lock_root(path: Path, workspace: Path,
                       lock_names: tuple[str, ...]) -> tuple[Path, str] | None:
    directory = path.parent
    while True:
        for name in lock_names:
            if (directory / name).exists():
                return directory, name
        if directory == workspace or directory.parent == directory:
            return None
        directory = directory.parent


def lockfile_commands(workspace: Path, action: Action,
                      changed: Iterable[Path]) -> list[tuple[list[str], Path]]:
    """Return deterministic lockfile refresh commands for changed manifests."""
    commands: dict[tuple[str, str], tuple[list[str], Path]] = {}
    for path in changed:
        if path.name == "package.json":
            lock = _nearest_lock_root(
                path, workspace, ("pnpm-lock.yaml", "package-lock.json")
            )
            if not lock:
                continue
            root, name = lock
            command = (
                ["pnpm", "install", "--lockfile-only", "--ignore-scripts"]
                if name == "pnpm-lock.yaml"
                else [
                    "npm", "install", "--package-lock-only", "--ignore-scripts",
                    "--no-audit", "--no-fund",
                ]
            )
        elif path.name == "pyproject.toml":
            lock = _nearest_lock_root(path, workspace, ("uv.lock",))
            if not lock:
                continue
            root, _name = lock
            command = [
                "uv", "lock", "--upgrade-package",
                f"{action.package}=={action.target_version}",
            ]
        else:
            continue
        commands[(str(root), command[0])] = (command, root)
    return list(commands.values())


def parse_check_command(value: str) -> list[str]:
    # The option is a portable argument string, not a shell expression.
    # POSIX tokenization consistently removes quotes before shell=False
    # execution on every platform.
    command = shlex.split(value, posix=True)
    if not command:
        raise RemediationError("check command cannot be empty")
    if any(token in {"&&", "||", ";", "|", ">", ">>", "<"} for token in command):
        raise RemediationError(
            "check commands do not accept shell operators; repeat --check "
            "for multiple commands"
        )
    return command


def _run_command(
    command: list[str], *, cwd: Path, kind: str, runner: Runner,
    timeout: int, environment: dict[str, str],
) -> CommandRecord:
    executable = shutil.which(command[0])
    if not executable:
        raise RemediationError(
            f"required executable {command[0]!r} was not found"
        )
    actual = [executable, *command[1:]]
    started = time.perf_counter()
    try:
        completed = runner(
            actual,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RemediationError(
            f"{kind} command timed out after {timeout} seconds"
        ) from exc
    record = CommandRecord(
        command=command,
        cwd=str(cwd),
        exit_code=completed.returncode,
        duration_seconds=round(time.perf_counter() - started, 3),
        kind=kind,
    )
    if completed.returncode:
        raise RemediationError(
            f"{kind} command failed with exit code {completed.returncode}: "
            f"{command[0]}"
        )
    return record


def _git(git: str, args: list[str], *, cwd: Path | None = None,
         runner: Runner = subprocess.run) -> subprocess.CompletedProcess:
    completed = runner(
        [git, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=DEFAULT_COMMAND_TIMEOUT,
        check=False,
    )
    if completed.returncode:
        raise RemediationError(
            f"git command failed with exit code {completed.returncode}"
        )
    return completed


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.casefold()).strip("-._")
    return (slug or "dependency")[:48]


def load_upgrade_actions(report_path: Path) -> list[Action]:
    """Load the ordered, confirmed dependency upgrades from a JSON report."""
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemediationError(f"could not read report: {exc}") from exc
    if not isinstance(report, dict):
        raise RemediationError("report must contain a JSON object")
    try:
        actions = [
            Action.model_validate(value)
            for value in report.get("actions", [])
        ]
    except (TypeError, ValueError) as exc:
        raise RemediationError(
            "report contains an invalid remediation action"
        ) from exc
    return [
        action for action in actions
        if action.kind == "upgrade" and action.target_version
    ]


def _select_action(actions: list[Action], action_id: str | None) -> Action:
    if action_id:
        for action in actions:
            if action.action_id == action_id:
                return action
        raise RemediationError(f"no upgrade action matches {action_id!r}")
    if not actions:
        raise RemediationError("the report contains no confirmed upgrade action")
    return actions[0]


def _scan_remaining_cves(scan_path: Path, expected: Iterable[str]) -> list[str]:
    expected_ids = {value.upper() for value in expected}
    try:
        findings = load_file(scan_path, fmt="osv")
    except Exception as exc:
        raise RemediationError(
            "OSV-Scanner output could not be parsed"
        ) from exc
    observed = {
        identifier.upper()
        for finding in findings
        for identifier in (finding.vuln_id, *finding.aliases)
    }
    return sorted(expected_ids & observed)


def execute_remediation(
    report_path: Path,
    repository: Path,
    output_dir: Path,
    *,
    action_id: str | None = None,
    checks: Iterable[str] = (),
    refresh_lockfiles: bool = True,
    rescan: bool = True,
    scanner_binary: str | None = None,
    runner: Runner = subprocess.run,
    timeout: int = DEFAULT_COMMAND_TIMEOUT,
) -> RemediationResult:
    """Prepare one dependency patch in an isolated, PR-ready clone."""
    repository = repository.resolve()
    output_dir = output_dir.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise RemediationError("repository must be a local Git working tree")
    try:
        output_dir.relative_to(repository)
    except ValueError:
        pass
    else:
        raise RemediationError(
            "output directory must be outside the source repository"
        )
    if output_dir.exists():
        if not output_dir.is_dir():
            raise RemediationError("output directory path is not a directory")
        if any(output_dir.iterdir()):
            raise RemediationError("output directory must be empty or absent")
    output_dir.mkdir(parents=True, exist_ok=True)

    action = _select_action(load_upgrade_actions(report_path), action_id)

    git = shutil.which("git")
    if not git:
        raise RemediationError("git is required for remediation")
    warnings: list[str] = []
    source_status = _git(
        git,
        ["-c", f"safe.directory={repository}", "status", "--porcelain"],
        cwd=repository,
        runner=runner,
    ).stdout.strip()
    if source_status:
        warnings.append(
            "source working-tree changes were not included; remediation uses "
            "the committed HEAD"
        )
    workspace = output_dir / "workspace"
    _git(
        git,
        ["-c", f"safe.directory={repository}",
         "clone", "--quiet", "--local", "--no-hardlinks",
         str(repository), str(workspace)],
        runner=runner,
    )
    source_commit = _git(
        git, ["rev-parse", "HEAD"], cwd=workspace, runner=runner
    ).stdout.strip()
    branch = (
        f"patchtriage/{_safe_slug(action.package)}-"
        f"{_safe_slug(action.target_version)}"
    )
    _git(git, ["switch", "-c", branch], cwd=workspace, runner=runner)

    changed_manifests = update_dependency_manifests(workspace, action)
    environment = os.environ.copy()
    environment.update({
        "CI": "true",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "npm_config_ignore_scripts": "true",
    })
    command_records: list[CommandRecord] = []

    lock_commands = lockfile_commands(workspace, action, changed_manifests)
    for manifest in changed_manifests:
        unsupported: tuple[str, ...]
        if manifest.name == "package.json":
            unsupported = ("yarn.lock",)
        elif manifest.name == "pyproject.toml":
            unsupported = ("poetry.lock", "Pipfile.lock")
        else:
            unsupported = ()
        lock = _nearest_lock_root(manifest, workspace, unsupported)
        if lock:
            _root, name = lock
            warnings.append(
                f"{name} is present but its automatic refresh is not supported"
            )
    if refresh_lockfiles:
        for command, cwd in lock_commands:
            command_records.append(_run_command(
                command,
                cwd=cwd,
                kind="lockfile",
                runner=runner,
                timeout=timeout,
                environment=environment,
            ))
    elif lock_commands:
        warnings.append("lockfile refresh was explicitly skipped")

    for value in checks:
        command = parse_check_command(value)
        command_records.append(_run_command(
            command,
            cwd=workspace,
            kind="check",
            runner=runner,
            timeout=timeout,
            environment=environment,
        ))

    scan = ScanRecord()
    if rescan:
        scanner = scanner_binary or shutil.which("osv-scanner")
        if scanner:
            scan_path = output_dir / "osv-remediation.json"
            scanner_config = output_dir / "trusted-osv-scanner.toml"
            scanner_config.write_text("", encoding="utf-8")
            command = [
                scanner, "--config", str(scanner_config),
                "scan", "source", "--format", "json",
                "--output", str(scan_path), "--no-resolve", "--all-packages",
                str(workspace),
            ]
            started = time.perf_counter()
            completed = runner(
                command,
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            command_records.append(CommandRecord(
                command=["osv-scanner", *command[1:]],
                cwd=str(workspace),
                exit_code=completed.returncode,
                duration_seconds=round(time.perf_counter() - started, 3),
                kind="rescan",
            ))
            if completed.returncode not in (0, 1):
                raise RemediationError(
                    "OSV-Scanner remediation scan failed with exit code "
                    f"{completed.returncode}"
                )
            if not scan_path.exists():
                raise RemediationError(
                    "OSV-Scanner did not produce remediation output"
                )
            remaining = _scan_remaining_cves(scan_path, action.cves)
            scan = ScanRecord(
                status="failed" if remaining else "cleared",
                scanner="osv-scanner",
                output=str(scan_path),
                remaining_cves=remaining,
            )
        else:
            warnings.append("OSV-Scanner was not found; rescan skipped")

    diff = _git(
        git, ["diff", "--binary", "--no-ext-diff"],
        cwd=workspace, runner=runner,
    ).stdout
    if not diff.strip():
        raise RemediationError("remediation produced no repository diff")
    patch_file = output_dir / "remediation.patch"
    patch_file.write_text(diff, encoding="utf-8")
    status_output = _git(
        git, ["status", "--porcelain"], cwd=workspace, runner=runner
    ).stdout
    changed_files = sorted({
        line[3:].strip()
        for line in status_output.splitlines()
        if len(line) > 3
    })
    checks_requested = any(
        record.kind == "check" for record in command_records
    )
    if scan.status == "failed":
        status = "verification_failed"
    elif scan.status == "cleared" or checks_requested:
        status = "verified"
    else:
        status = "patched_unverified"

    result = RemediationResult(
        status=status,
        action=action,
        source_repository=str(repository),
        source_commit=source_commit,
        branch=branch,
        workspace=str(workspace),
        changed_files=changed_files,
        patch_file=str(patch_file),
        commands=command_records,
        scan=scan,
        warnings=warnings,
    )
    (output_dir / "remediation.json").write_text(
        result.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return result
