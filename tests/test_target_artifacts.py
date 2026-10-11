"""Run artifacts and workspace limits remain atomic under concurrency."""

from concurrent.futures import ThreadPoolExecutor
import threading
from pathlib import Path

import pytest

from patchtriage import targets


def test_stale_run_cannot_republish_report_after_input_change(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    target = targets.add_target("service")
    targets.save_source(
        target["id"],
        '{"SchemaVersion":2,"ArtifactName":"x","Results":[]}',
        "trivy", filename="first.json",
    )
    evaluated = targets.get_target(target["id"])
    assert evaluated is not None
    targets.update_target_inputs(target["id"])

    with pytest.raises(targets.StaleInputError, match="stale result"):
        targets.save_run_artifacts(
            target["id"], {"target_id": target["id"]}, "<html>old</html>",
            evaluated["input_revision"], evaluated["source_sha256"],
        )
    assert not targets.report_path(target["id"]).exists()
    assert targets.load_summary(target["id"]) is None


def test_content_addressed_sources_switch_registry_before_old_cleanup(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    target = targets.add_target("service")
    first = targets.save_source(
        target["id"],
        '{"SchemaVersion":2,"ArtifactName":"one","Results":[]}',
        "trivy", filename="one.json",
    )
    first_record = targets.get_target(target["id"])
    second = targets.save_source(
        target["id"],
        '{"SchemaVersion":2,"ArtifactName":"two","Results":[]}',
        "trivy", filename="two.json",
    )
    second_record = targets.get_target(target["id"])

    assert first != second
    assert not first.exists()
    assert second.exists()
    assert second_record["source_file"] == str(second)
    assert second_record["source_sha256"] in second.name
    assert second_record["input_revision"] == first_record["input_revision"] + 1


def test_summary_manifest_switches_between_immutable_reports(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    target = targets.add_target("service")
    targets.save_source(
        target["id"],
        '{"SchemaVersion":2,"ArtifactName":"one","Results":[]}',
        "trivy", filename="one.json",
    )
    current = targets.get_target(target["id"])
    targets.save_run_artifacts(
        target["id"], {"target_id": target["id"]}, "<html>first</html>",
        current["input_revision"], current["source_sha256"],
    )
    first_summary = targets.load_summary(target["id"])
    first_report = targets.current_report_path(target["id"])
    assert first_report.read_text(encoding="utf-8") == "<html>first</html>"

    targets.save_run_artifacts(
        target["id"], {"target_id": target["id"]}, "<html>second</html>",
        current["input_revision"], current["source_sha256"],
    )
    second_summary = targets.load_summary(target["id"])
    second_report = targets.current_report_path(target["id"])
    assert second_summary["run_generation"] != first_summary["run_generation"]
    assert second_report.read_text(encoding="utf-8") == "<html>second</html>"
    assert not first_report.exists()


def test_concurrent_target_creates_cannot_exceed_workspace_limit(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    barrier = threading.Barrier(4)

    def create(index):
        barrier.wait()
        try:
            return targets.add_target(
                f"service-{index}", max_targets=1)["id"]
        except targets.TargetLimitError:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        created = list(executor.map(create, range(4)))
    assert len([target_id for target_id in created if target_id]) == 1
    assert len(targets.load_targets()) == 1


def test_concurrent_source_writes_cannot_exceed_workspace_quota(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    first = targets.add_target("first")
    second = targets.add_target("second")
    barrier = threading.Barrier(2)

    def attach(target):
        barrier.wait()
        try:
            targets.save_source(
                target["id"], "123456", "osv",
                max_workspace_source_bytes=10,
            )
            return True
        except targets.SourceQuotaError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        stored = list(executor.map(attach, (first, second)))
    assert sorted(stored) == [False, True]
    assert sum(int(item.get("source_size") or 0)
               for item in targets.load_targets()) == 6


def test_workspace_quota_counts_sources_created_by_older_versions(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    old = targets.add_target("old")
    targets.save_source(old["id"], "123456", "osv")
    registry = targets.load_targets()
    registry[0].pop("source_size", None)
    targets.save_targets(registry)
    current = targets.add_target("current")

    with pytest.raises(targets.SourceQuotaError):
        targets.save_source(
            current["id"], "abcdef", "osv",
            max_workspace_source_bytes=10,
        )


def test_rejected_source_update_does_not_mutate_target_context(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    occupied = targets.add_target("occupied")
    targets.save_source(occupied["id"], "123456", "osv")
    target = targets.add_target("demo", criticality="low")
    before = targets.get_target(target["id"])

    with pytest.raises(targets.SourceQuotaError):
        targets.save_source(
            target["id"], "abcdef", "osv",
            max_workspace_source_bytes=10,
            target_updates={"criticality": "critical"},
        )
    after = targets.get_target(target["id"])
    assert after["criticality"] == "low"
    assert after["input_revision"] == before["input_revision"]
    assert after["source_file"] == ""


def test_old_source_cleanup_failure_is_best_effort_and_still_counted(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "config"))
    target = targets.add_target("service")
    first = targets.save_source(target["id"], "123456", "osv")
    original_unlink = Path.unlink

    def locked_unlink(path, *args, **kwargs):
        if path == first:
            raise PermissionError("locked")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", locked_unlink)
    second = targets.save_source(target["id"], "abcdef", "osv")
    assert second.exists()
    assert first.exists()

    other = targets.add_target("other")
    with pytest.raises(targets.SourceQuotaError):
        targets.save_source(
            other["id"], "123456789", "osv",
            max_workspace_source_bytes=20,
        )
