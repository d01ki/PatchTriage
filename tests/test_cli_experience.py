"""Regression tests for paths and explanations shown by the guided CLI."""

from __future__ import annotations

from patchtriage import cli


def test_pasted_path_quotes_are_removed(monkeypatch):
    monkeypatch.setattr(cli, "_running_under_wsl", lambda: False)
    assert cli._normalize_input_pattern('"scans/my sbom.json"') == (
        "scans/my sbom.json"
    )


def test_windows_path_is_translated_when_running_under_wsl(monkeypatch):
    monkeypatch.setattr(cli, "_running_under_wsl", lambda: True)
    monkeypatch.setattr(cli, "_in_container", lambda: False)
    assert cli._normalize_input_pattern(
        '"C:\\Users\\analyst\\Downloads\\aibom.cdx.json"'
    ) == "/mnt/c/Users/analyst/Downloads/aibom.cdx.json"


def test_windows_path_is_not_misrepresented_as_visible_in_container(
        monkeypatch):
    monkeypatch.setattr(cli, "_running_under_wsl", lambda: True)
    monkeypatch.setattr(cli, "_in_container", lambda: True)
    value = "C:\\Users\\analyst\\Downloads\\aibom.cdx.json"
    assert cli._normalize_input_pattern(value) == value


def test_outcome_table_prints_the_fraction_legend():
    with cli.console.capture() as capture:
        cli._print_eval([])
    output = capture.get()
    assert "How to read x/y" in output
    assert "one of the two target findings" in output
