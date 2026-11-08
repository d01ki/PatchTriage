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
import stat
import subprocess
import time
from pathlib import Path
from typing import Callable, Iterable

from pydantic import BaseModel, Field

from .ingest.parsers import load_file_with_metadata
from .plan import Action, compare_versions
from .repository_local import osv_source_scan_command


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
    other_package_cves: list[str] = Field(default_factory=list)
    reason: str = ""


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


def _is_link(info: os.stat_result) -> bool:
    """A symlink, or on Windows any reparse point such as a junction."""
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _require_regular_file_inside(path: Path, root: Path) -> None:
    """Refuse a manifest reached through a link or leaving the clone.

    Repository content is untrusted: a committed link named ``package.json``
    would otherwise be read and rewritten at its destination.
    """
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if _is_link(os.lstat(current)):
            raise RemediationError(
                f"{relative.as_posix()}: refusing to follow a symbolic link "
                "or junction in the repository"
            )
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise RemediationError(f"{relative.as_posix()}: not a regular file")
    if not path.resolve().is_relative_to(root.resolve()):
        raise RemediationError(
            f"{relative.as_posix()}: resolves outside the repository clone"
        )


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
            if name != package:  # npm names are exact strings
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
    updates: list[tuple[Path, Callable[[Path, str, str], bool]]] = []
    if ecosystem in {"npm", "node", "javascript"}:
        updates += [(path, _update_package_json)
                    for path in _iter_files(workspace, {"package.json"})]
    elif ecosystem in {"pypi", "python", "pip"}:
        updates += [(path, _update_pyproject)
                    for path in _iter_files(workspace, {"pyproject.toml"})]
        updates += [(path, _update_requirements) for path in _iter_files(
            workspace,
            {"requirements.txt"},
            prefixes=("requirements-", "requirements."),
        )]
    else:
        raise RemediationError(
            f"automatic remediation is not supported for ecosystem "
            f"{action.ecosystem!r}"
        )
    # Check every file first so one unsafe entry leaves nothing half-updated.
    for path, _update in updates:
        _require_regular_file_inside(path, workspace)
    changed = [
        path for path, update in updates
        if update(path, action.package, action.target_version)
    ]
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


def _ecosystem_family(value: str) -> str:
    normalized = str(value or "").casefold()
    if normalized in {"npm", "node", "javascript"}:
        return "npm"
    if normalized in {"pypi", "python", "pip"}:
        return "pypi"
    return normalized


def _is_action_package(observed: dict, action: Action) -> bool:
    family = _ecosystem_family(action.ecosystem)
    if _ecosystem_family(observed.get("ecosystem", "")) != family:
        return False
    name = str(observed.get("name") or "")
    if family == "pypi":
        return _normalized_package(name) == _normalized_package(action.package)
    return name == action.package


def _evaluate_rescan(scan_path: Path, action: Action) -> ScanRecord:
    """Judge a rescan by what it observed about the upgraded package.

    A CVE's absence only counts when the scan saw the package at the target
    version and no older copy of it; an empty scan observed nothing.
    """
    try:
        loaded = load_file_with_metadata(scan_path, fmt="osv")
        data = json.loads(scan_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RemediationError(
            "OSV-Scanner output could not be parsed"
        ) from exc
    expected = {value.upper() for value in action.cves}
    versions: set[str] = set()
    remaining: set[str] = set()
    other_packages: set[str] = set()
    for result in data["results"]:
        packages = result.get("packages") if isinstance(result, dict) else None
        for entry in packages if isinstance(packages, list) else []:
            package = entry.get("package") if isinstance(entry, dict) else None
            if not isinstance(package, dict):
                continue
            hits = expected & {
                str(identifier).upper()
                for vulnerability in entry.get("vulnerabilities") or []
                if isinstance(vulnerability, dict)
                for identifier in (vulnerability.get("id", ""),
                                   *(vulnerability.get("aliases") or []))
            }
            if _is_action_package(package, action):
                versions.add(str(package.get("version") or ""))
                remaining |= hits
            else:
                other_packages |= hits

    def record(status: str, reason: str) -> ScanRecord:
        return ScanRecord(
            status=status, scanner="osv-scanner", output=str(scan_path),
            remaining_cves=sorted(remaining),
            other_package_cves=sorted(other_packages), reason=reason)

    compare = lambda version: compare_versions(
        version, action.target_version, action.ecosystem)
    if remaining:
        return record("failed", f"{action.package} is still reported as "
                                "affected by the target CVEs")
    if not loaded.coverage["complete"]:
        return record("unverified", "the scan output has malformed rows")
    if not versions:
        return record("unverified", f"the scan did not observe {action.package}")
    if not any(compare(version) == 0 for version in versions):
        return record("unverified", f"the scan did not observe {action.package} "
                                    f"at {action.target_version}")
    older = sorted(version for version in versions if compare(version) < 0)
    if older:
        return record("unverified", f"older {action.package} versions remain: "
                                    + ", ".join(older))
    return record("cleared", "")


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
            command = osv_source_scan_command(
                scanner, scan_path, scanner_config, workspace)
            started = time.perf_counter()
            try:
                completed = runner(
                    command,
                    cwd=workspace,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                scan = ScanRecord(
                    status="unverified", scanner="osv-scanner",
                    reason=f"the rescan timed out after {timeout} seconds")
            else:
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
                scan = _evaluate_rescan(scan_path, action)
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
    elif scan.status == "cleared" or (
            checks_requested and scan.status != "unverified"):
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
