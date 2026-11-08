"""Dependency remediation: manifest edits and isolated patch artifacts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchtriage.assess import Assessment
from patchtriage.cli import app
from patchtriage.plan import Action
from patchtriage.remediation import (
    RemediationError,
    _require_regular_file_inside,
    execute_remediation,
    load_upgrade_actions,
    lockfile_commands,
    package_manager_environment,
    parse_check_command,
    update_dependency_manifests,
)


def _action(**updates) -> Action:
    values = {
        "action_id": "upgrade:repo:npm::lodash:4.17.20",
        "kind": "upgrade",
        "summary": "Upgrade lodash to 4.17.21",
        "asset": "repo",
        "package": "lodash",
        "ecosystem": "npm",
        "installed_version": "4.17.20",
        "target_version": "4.17.21",
        "cves": ["CVE-2021-23337"],
    }
    values.update(updates)
    return Action(**values)


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _repository(tmp_path: Path, files: dict[str, str]) -> Path:
    repository = tmp_path / "source"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "PatchTriage Test")
    _git(repository, "config", "user.email", "patchtriage@example.invalid")
    for name, content in files.items():
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "fixture")
    return repository


def test_npm_remediation_isolated_from_source_and_emits_patch(tmp_path):
    source_manifest = json.dumps({
        "name": "fixture",
        "dependencies": {"lodash": "^4.17.20"},
    }, indent=2) + "\n"
    repository = _repository(tmp_path, {"package.json": source_manifest})
    action = _action()
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"actions": [action.model_dump(mode="json")]}),
        encoding="utf-8",
    )

    result = execute_remediation(
        report,
        repository,
        tmp_path / "result",
        rescan=False,
    )

    assert result.status == "patched_unverified"
    assert result.branch == "patchtriage/lodash-4.17.21"
    assert result.changed_files == ["package.json"]
    assert (repository / "package.json").read_text(
        encoding="utf-8"
    ) == source_manifest
    patched = json.loads(
        (Path(result.workspace) / "package.json").read_text(encoding="utf-8")
    )
    assert patched["dependencies"]["lodash"] == "4.17.21"
    patch = Path(result.patch_file).read_text(encoding="utf-8")
    assert '"lodash": "4.17.21"' in patch
    artifact = json.loads(
        (tmp_path / "result" / "remediation.json").read_text(encoding="utf-8")
    )
    assert artifact["source_commit"] == _git(repository, "rev-parse", "HEAD")


def test_python_manifests_preserve_markers_and_project_metadata(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "requirements.txt").write_text(
        'requests[security]>=2.28; python_version >= "3.10"  # runtime\n',
        encoding="utf-8",
    )
    (workspace / "pyproject.toml").write_text(
        """[project]
name = "requests"
dependencies = [
  "requests>=2.28",
]

[project.optional-dependencies]
test = ["pytest>=8"]

[tool.poetry.dependencies]
python = "^3.10"
requests = { version = "^2.28", extras = ["socks"] }
""",
        encoding="utf-8",
    )
    action = _action(
        action_id="upgrade:repo:pypi::requests:2.28",
        package="requests",
        ecosystem="pypi",
        installed_version="2.28",
        target_version="2.32.4",
    )

    changed = update_dependency_manifests(workspace, action)

    assert {path.name for path in changed} == {
        "pyproject.toml", "requirements.txt",
    }
    requirements = (workspace / "requirements.txt").read_text(encoding="utf-8")
    assert (
        'requests[security]==2.32.4; python_version >= "3.10"  # runtime'
        in requirements
    )
    pyproject = (workspace / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "requests"' in pyproject
    assert '"requests==2.32.4"' in pyproject
    assert 'requests = { version = "2.32.4", extras = ["socks"] }' in pyproject


def _rescan(tmp_path, document, checks=()):
    """Run remediation with a fake scanner that writes ``document``."""
    repository = _repository(
        tmp_path,
        {"package.json": '{"dependencies":{"lodash":"4.17.20"}}\n'},
    )
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"actions": [_action().model_dump(mode="json")]}),
        encoding="utf-8",
    )
    commands = []

    def runner(command, **kwargs):
        if command[0] == "fake-osv-scanner":
            commands.append(command)
            if isinstance(document, Exception):
                raise document
            output = Path(command[command.index("--output-file") + 1])
            output.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.run(command, **kwargs)

    result = execute_remediation(
        report,
        repository,
        tmp_path / "result",
        scanner_binary="fake-osv-scanner",
        runner=runner,
        checks=checks,
    )
    return result, commands


def _package(name, version, *cves, ecosystem="npm"):
    return {"package": {"name": name, "version": version,
                        "ecosystem": ecosystem},
            "vulnerabilities": [{"id": cve} for cve in cves]}


def _scan(*packages):
    return {"results": [{"source": {"path": "package-lock.json"},
                         "packages": list(packages)}]}


CVE = "CVE-2021-23337"


def test_rescan_clears_only_when_target_version_was_observed(tmp_path):
    result, commands = _rescan(tmp_path, _scan(_package("lodash", "4.17.21")))
    assert result.status == "verified"
    assert result.scan.status == "cleared"
    assert result.scan.remaining_cves == []
    assert any(record.kind == "rescan" for record in result.commands)
    assert "--recursive" in commands[0]


@pytest.mark.parametrize(
    ("document", "reason"),
    [({"results": []}, "did not observe lodash"),
     (_scan(_package("other", "1.0.0")), "did not observe lodash"),
     (_scan(_package("lodash", "4.17.22")), "at 4.17.21"),
     (_scan(_package("lodash", "4.17.21"), _package("lodash", "4.17.20")),
      "older lodash versions remain: 4.17.20"),
     ({"results": [
         {"source": {"path": "package-lock.json"},
          "packages": [_package("lodash", "4.17.21")]},
         {"source": {"path": "nested/package-lock.json"},
          "packages": [_package("lodash", "4.17.20")]}]},
      "older lodash versions remain"),
     (_scan(_package("lodash", "4.17.21"), "broken"), "malformed")])
def test_rescan_without_sufficient_observation_is_unverified(
        tmp_path, document, reason):
    result, _ = _rescan(tmp_path, document)
    assert result.scan.status == "unverified"
    assert reason in result.scan.reason
    assert result.status == "patched_unverified"


def test_unverified_rescan_is_not_upgraded_by_passing_checks(tmp_path):
    result, _ = _rescan(tmp_path, {"results": []}, checks=["git status"])
    assert result.status == "patched_unverified"


def test_old_version_still_affected_fails_verification(tmp_path):
    result, _ = _rescan(tmp_path, _scan(_package("lodash", "4.17.20", CVE)))
    assert result.status == "verification_failed"
    assert result.scan.remaining_cves == [CVE]


def test_same_cve_on_another_package_is_reported_separately(tmp_path):
    result, _ = _rescan(tmp_path, _scan(
        _package("lodash", "4.17.21"), _package("lodash-es", "4.17.20", CVE)))
    assert result.scan.status == "cleared"
    assert result.scan.remaining_cves == []
    assert result.scan.other_package_cves == [CVE]


def test_rescan_timeout_is_unverified(tmp_path):
    result, _ = _rescan(
        tmp_path, subprocess.TimeoutExpired("fake-osv-scanner", 1))
    assert result.status == "patched_unverified"
    assert result.scan.status == "unverified"
    assert "timed out" in result.scan.reason


def test_structurally_invalid_rescan_is_an_error(tmp_path):
    with pytest.raises(RemediationError, match="could not be parsed"):
        _rescan(tmp_path, {})


def test_lockfile_commands_cover_npm_pnpm_and_uv(tmp_path):
    workspace = tmp_path
    npm = workspace / "npm"
    pnpm = workspace / "pnpm"
    python = workspace / "python"
    for directory in (npm, pnpm, python):
        directory.mkdir()
    (npm / "package.json").write_text("{}", encoding="utf-8")
    (npm / "package-lock.json").write_text("{}", encoding="utf-8")
    (pnpm / "package.json").write_text("{}", encoding="utf-8")
    (pnpm / "pnpm-lock.yaml").write_text("", encoding="utf-8")
    (python / "pyproject.toml").write_text("", encoding="utf-8")
    (python / "uv.lock").write_text("", encoding="utf-8")

    npm_commands = lockfile_commands(workspace, _action(), [
        npm / "package.json", pnpm / "package.json",
    ])
    assert {command[0][0] for command in npm_commands} == {"npm", "pnpm"}
    python_action = _action(
        package="requests", ecosystem="pypi", target_version="2.32.4"
    )
    python_commands = lockfile_commands(
        workspace, python_action, [python / "pyproject.toml"]
    )
    assert python_commands == [(
        ["uv", "lock", "--upgrade-package", "requests==2.32.4"],
        python,
    )]


def test_output_directory_inside_source_is_rejected(tmp_path):
    repository = _repository(
        tmp_path,
        {"package.json": '{"dependencies":{"lodash":"4.17.20"}}\n'},
    )
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"actions": [_action().model_dump(mode="json")]}),
        encoding="utf-8",
    )
    with pytest.raises(RemediationError, match="outside"):
        execute_remediation(
            report,
            repository,
            repository / "result",
            rescan=False,
        )


def test_check_commands_are_tokenized_without_a_shell():
    assert parse_check_command('python -c "print(1)"') == [
        "python", "-c", "print(1)",
    ]


def test_load_upgrade_actions_filters_non_patch_actions(tmp_path):
    upgrade = _action()
    investigate = _action(
        action_id="investigate:repo:npm::lodash",
        kind="investigate",
        target_version="",
    )
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({
            "actions": [
                upgrade.model_dump(mode="json"),
                investigate.model_dump(mode="json"),
            ],
        }),
        encoding="utf-8",
    )

    assert load_upgrade_actions(report) == [upgrade]


def test_remediate_without_arguments_runs_guided_local_workflow(tmp_path):
    repository = _repository(
        tmp_path,
        {"package.json": '{"dependencies":{"lodash":"4.17.20"}}\n'},
    )
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"actions": [_action().model_dump(mode="json")]}),
        encoding="utf-8",
    )
    output = tmp_path / "source-patchtriage-remediation"
    answers = "\n".join([
        str(report),
        str(repository),
        "1",
        "",
        "",
        "y",
        "",
    ])

    result = CliRunner().invoke(
        app,
        ["remediate", "--no-lock", "--no-scan"],
        input=answers,
    )

    assert result.exit_code == 0, result.output
    assert "Confirmed dependency upgrades" in result.output
    assert "Execution plan" in result.output
    assert "Local review commands" in result.output
    assert (output / "remediation.patch").is_file()
    assert json.loads(
        (output / "workspace" / "package.json").read_text(encoding="utf-8")
    )["dependencies"]["lodash"] == "4.17.21"


def test_start_offers_guided_remediation_after_report(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")
    scan = tmp_path / "scan.json"
    scan.write_text("{}", encoding="utf-8")
    captured = {}

    monkeypatch.setattr(
        "patchtriage.cli.cfgmod.config_path", lambda: config
    )
    monkeypatch.setattr(
        "patchtriage.cli.cfgmod.apply_to_env", lambda: None
    )
    monkeypatch.setattr(
        "patchtriage.cli.cfgmod.load",
        lambda: {"default_backend": "rules"},
    )
    monkeypatch.setattr(
        "patchtriage.cli.globmod.glob", lambda _pattern: [str(scan)]
    )
    monkeypatch.setattr(
        "patchtriage.cli.has_ai_configuration", lambda: False
    )
    monkeypatch.setattr(
        "patchtriage.cli._pipeline",
        lambda *_args, **_kwargs: Assessment([], [], [_action()], [], {}),
    )
    monkeypatch.setattr(
        "patchtriage.cli._emit", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        "patchtriage.cli._offer_browser", lambda _html: None
    )

    def fake_guided(report, repository, output_dir, **kwargs):
        captured.update({
            "report": report,
            "repository": repository,
            "output_dir": output_dir,
            **kwargs,
        })

    monkeypatch.setattr(
        "patchtriage.cli._guided_remediation", fake_guided
    )
    answers = "\n".join([
        "scan.json",
        "",
        "",
        "",
        "",
        "n",
        "n",
        "",
        "n",
        "",
        "",
        "y",
        "",
    ])

    result = CliRunner().invoke(app, ["start"], input=answers)

    assert result.exit_code == 0, result.output
    assert "5. Local patch" in result.output
    assert captured["report"] == Path("report.json")
    assert captured["repository"] is None
    assert captured["checks"] is None


def test_npm_upgrade_does_not_rewrite_a_similarly_named_package(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = workspace / "package.json"
    manifest.write_text(json.dumps({"dependencies": {
        "foo-bar": "1.0.0", "foo_bar": "1.0.0", "foobar": "1.0.0"}}),
        encoding="utf-8")
    action = _action(package="foo-bar", installed_version="1.0.0",
                     target_version="2.0.0")
    update_dependency_manifests(workspace, action)
    assert json.loads(manifest.read_text(encoding="utf-8"))["dependencies"] == {
        "foo-bar": "2.0.0", "foo_bar": "1.0.0", "foobar": "1.0.0"}


MANIFEST = '{"dependencies":{"lodash":"4.17.20"}}\n'


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")


def _link_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sentinel = tmp_path / "outside.json"
    sentinel.write_text(MANIFEST, encoding="utf-8")
    return workspace, sentinel


@pytest.mark.parametrize("relative", [False, True])
def test_manifest_symlink_outside_clone_is_refused(tmp_path, relative):
    workspace, sentinel = _link_workspace(tmp_path)
    _symlink_or_skip(workspace / "package.json",
                     Path("../outside.json") if relative else sentinel)
    with pytest.raises(RemediationError, match="package.json.*link"):
        update_dependency_manifests(workspace, _action())
    assert sentinel.read_text(encoding="utf-8") == MANIFEST


def test_unsafe_entry_prevents_any_partial_update(tmp_path):
    workspace, sentinel = _link_workspace(tmp_path)
    regular = workspace / "package.json"
    regular.write_text(MANIFEST, encoding="utf-8")
    (workspace / "z").mkdir()
    _symlink_or_skip(workspace / "z" / "package.json", sentinel)
    with pytest.raises(RemediationError, match="link"):
        update_dependency_manifests(workspace, _action())
    assert regular.read_text(encoding="utf-8") == MANIFEST
    assert sentinel.read_text(encoding="utf-8") == MANIFEST


def test_symlink_ancestor_is_refused(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    real = workspace / "real"
    real.mkdir()
    manifest = real / "package.json"
    manifest.write_text(MANIFEST, encoding="utf-8")
    alias = workspace / "alias"
    _symlink_or_skip(alias, real)
    with pytest.raises(RemediationError, match="link"):
        _require_regular_file_inside(alias / "package.json", workspace)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junctions")
def test_windows_junction_cannot_reach_outside_the_clone(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "package.json"
    sentinel.write_text(MANIFEST, encoding="utf-8")
    junction = workspace / "linked"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                   check=True, capture_output=True)
    with pytest.raises(RemediationError):
        update_dependency_manifests(workspace, _action())
    with pytest.raises(RemediationError, match="link"):
        _require_regular_file_inside(junction / "package.json", workspace)
    assert sentinel.read_text(encoding="utf-8") == MANIFEST


def test_regular_manifest_inside_clone_still_updates(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "app").mkdir(parents=True)
    manifest = workspace / "app" / "package.json"
    manifest.write_text(MANIFEST, encoding="utf-8")
    assert update_dependency_manifests(workspace, _action()) == [manifest]
    assert "4.17.21" in manifest.read_text(encoding="utf-8")


def test_old_report_with_a_downgrade_target_is_not_executable(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"actions": [
        _action(installed_version="3.0.0", target_version="2.0.0")
        .model_dump(mode="json")]}), encoding="utf-8")
    assert load_upgrade_actions(report) == []


def _workspace(tmp_path, files):
    workspace = tmp_path / "workspace"
    for name, content in files.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return workspace


def _declares(version):
    return json.dumps({"dependencies": {"lodash": version}})


def test_same_dependency_in_two_workspaces_requires_a_choice(tmp_path):
    workspace = _workspace(tmp_path, {
        "a/package.json": _declares("^4.17.20"),
        "b/package.json": _declares("^4.17.20")})
    with pytest.raises(RemediationError, match="several directories.*a, b"):
        update_dependency_manifests(workspace, _action())
    for name in ("a", "b"):
        assert (workspace / name / "package.json").read_text(
            encoding="utf-8") == _declares("^4.17.20")


def test_manifest_option_changes_only_the_chosen_workspace(tmp_path):
    workspace = _workspace(tmp_path, {
        "a/package.json": _declares("^4.17.20"),
        "b/package.json": _declares("^4.17.20")})
    changed = update_dependency_manifests(
        workspace, _action(), "b/package.json")
    assert changed == [workspace / "b" / "package.json"]
    assert (workspace / "a" / "package.json").read_text(
        encoding="utf-8") == _declares("^4.17.20")


def test_unknown_manifest_choice_is_rejected(tmp_path):
    workspace = _workspace(tmp_path, {"package.json": _declares("4.17.20")})
    with pytest.raises(RemediationError, match="not a supported manifest"):
        update_dependency_manifests(workspace, _action(), "nope/package.json")


@pytest.mark.parametrize(
    ("name", "content"),
    [("package.json", _declares("3.0.0")),
     ("requirements.txt", "lodash==3.0.0\n")])
def test_pin_to_a_different_version_is_a_stale_report(tmp_path, name, content):
    ecosystem = "npm" if name == "package.json" else "pypi"
    workspace = _workspace(tmp_path, {name: content})
    with pytest.raises(RemediationError, match="pinned to 3.0.0"):
        update_dependency_manifests(workspace, _action(ecosystem=ecosystem))
    assert (workspace / name).read_text(encoding="utf-8") == content


@pytest.mark.parametrize("source", [
    "file:../x", "git+https://e.test/x.git", "github:a/b", "a/b",
    "link:../x", "npm:other@1", "workspace:*", "portal:../x"])
def test_non_registry_dependency_source_is_rejected(tmp_path, source):
    workspace = _workspace(tmp_path, {"package.json": _declares(source)})
    with pytest.raises(RemediationError, match="non-registry"):
        update_dependency_manifests(workspace, _action())


def test_tokens_reach_checks_but_not_package_managers(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "dummy-secret")
    monkeypatch.setenv("NPM_TOKEN", "dummy-secret")
    repository = _repository(tmp_path, {
        "package.json": _declares("4.17.20"), "package-lock.json": "{}"})
    report = tmp_path / "report.json"
    report.write_text(json.dumps(
        {"actions": [_action().model_dump(mode="json")]}), encoding="utf-8")
    environments = {}

    def runner(command, **kwargs):
        if command[0].lower().endswith(("npm", "npm.cmd", "python", "python.exe")):
            kind = "lock" if "install" in command else "check"
            environments[kind] = kwargs["env"]
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.run(command, **kwargs)

    execute_remediation(
        report, repository, tmp_path / "result", rescan=False, runner=runner,
        checks=['python -c "print(1)"'])
    if "lock" not in environments:
        pytest.skip("npm is not installed")
    lock = environments["lock"]
    assert "GITHUB_TOKEN" not in lock and "NPM_TOKEN" not in lock
    assert "dummy-secret" not in lock.values()
    assert str(tmp_path / "result") in lock["NPM_CONFIG_USERCONFIG"]
    assert environments["check"]["GITHUB_TOKEN"] == "dummy-secret"


def test_operator_can_pass_a_named_variable_explicitly(tmp_path, monkeypatch):
    monkeypatch.setenv("NPM_TOKEN", "operator-token")
    monkeypatch.setenv("PATCHTRIAGE_REMEDIATION_PASS_ENV", "NPM_TOKEN")
    assert package_manager_environment(tmp_path)["NPM_TOKEN"] == (
        "operator-token")


def _with_report_repository(tmp_path, repository_name):
    repository = _repository(tmp_path, {"package.json": _declares("4.17.20")})
    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "coverage": {"repository": repository_name},
        "actions": [_action().model_dump(mode="json")]}), encoding="utf-8")
    return repository, report


def test_report_for_another_repository_is_rejected(tmp_path):
    repository, report = _with_report_repository(tmp_path, "acme/widget")
    _git(repository, "remote", "add", "origin",
         "https://github.com/other/thing.git")
    with pytest.raises(RemediationError, match="does not match"):
        execute_remediation(report, repository, tmp_path / "r", rescan=False)


def test_report_for_matching_repository_is_accepted(tmp_path):
    repository, report = _with_report_repository(tmp_path, "Acme/Widget")
    _git(repository, "remote", "add", "origin",
         "git@github.com:acme/widget.git")
    result = execute_remediation(
        report, repository, tmp_path / "r", rescan=False)
    assert result.status == "patched_unverified"


def test_checkout_without_origin_warns_instead_of_guessing(tmp_path):
    repository, report = _with_report_repository(tmp_path, "acme/widget")
    result = execute_remediation(
        report, repository, tmp_path / "r", rescan=False)
    assert any("no origin remote" in w for w in result.warnings)
