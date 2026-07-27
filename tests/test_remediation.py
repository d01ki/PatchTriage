"""Dependency remediation: manifest edits and isolated patch artifacts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchtriage.cli import app
from patchtriage.plan import Action
from patchtriage.remediation import (
    RemediationError,
    execute_remediation,
    load_upgrade_actions,
    lockfile_commands,
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


def test_successful_rescan_marks_patch_verified(tmp_path):
    repository = _repository(
        tmp_path,
        {"package.json": '{"dependencies":{"lodash":"4.17.20"}}\n'},
    )
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"actions": [_action().model_dump(mode="json")]}),
        encoding="utf-8",
    )

    def runner(command, **kwargs):
        if command[0] == "fake-osv-scanner":
            output = Path(command[command.index("--output") + 1])
            output.write_text('{"results":[]}', encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.run(command, **kwargs)

    result = execute_remediation(
        report,
        repository,
        tmp_path / "result",
        scanner_binary="fake-osv-scanner",
        runner=runner,
    )

    assert result.status == "verified"
    assert result.scan.status == "cleared"
    assert result.scan.remaining_cves == []
    assert any(record.kind == "rescan" for record in result.commands)


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
        lambda *_args, **_kwargs: ([], [], [_action()], []),
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
