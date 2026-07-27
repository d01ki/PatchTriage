"""A zero-finding result must say what was actually checked.

"No findings" is the most dangerous thing a scanner can display, because it
reads as safety. A GitHub Dependency Graph import of a repository without a
committed lockfile lists application dependencies with no resolved version,
so the only checkable entries are CI actions -- and the run looks identical
to a genuinely clean repository unless the message says otherwise.
"""

from __future__ import annotations

from patchtriage.report.html import render_html
from patchtriage.webapp.runner import _result_message


def _coverage(total=21, checked=10, skipped=11, names=(),
              queried_ecosystems=(), unqueryable_ecosystems=()):
    return {
        "source_type": "sbom:osv",
        "total_components": total,
        "queryable_components": checked,
        "queried_components": checked,
        "unqueryable_components": skipped,
        "unqueryable_names": list(names),
        "queried_ecosystems": list(queried_ecosystems),
        "unqueryable_ecosystems": list(unqueryable_ecosystems),
        "errors": [],
    }


def test_zero_findings_reports_what_was_and_was_not_checked():
    message = _result_message(
        [], [], True, "provider_reported",
        _coverage(names=["fastapi", "pydantic", "httpx"]),
    )
    assert "10 of 21" in message
    assert "11 component(s) could not be checked" in message
    assert "fastapi" in message
    assert "lockfile" in message


def test_names_are_truncated_with_a_count_rather_than_dumped():
    names = [f"pkg{i}" for i in range(12)]
    message = _result_message(
        [], [], True, "provider_reported", _coverage(skipped=12, names=names))
    assert "pkg0" in message
    assert "pkg11" not in message
    assert "and 7 more" in message


def test_warns_when_only_ci_tooling_could_be_checked():
    """The case that silently produces a false clean bill of health."""
    message = _result_message(
        [], [], True, "provider_reported",
        _coverage(names=["fastapi"], queried_ecosystems=["githubactions"]),
    )
    assert "no application dependency was actually assessed" in message


def test_no_ci_only_warning_when_real_dependencies_were_checked():
    message = _result_message(
        [], [], True, "provider_reported",
        _coverage(names=["fastapi"],
                  queried_ecosystems=["githubactions", "PyPI"]),
    )
    assert "no application dependency was actually assessed" not in message
    assert "10 of 21" in message


def test_fully_covered_zero_finding_run_stays_simple():
    message = _result_message(
        [], [], False, "complete", _coverage(total=5, checked=5, skipped=0))
    assert message == "The attached evidence reported no vulnerability findings."


def test_provider_reported_without_component_data_is_still_explicit():
    message = _result_message([], [], True, "provider_reported", {})
    assert "not independently verified" in message


def test_findings_present_does_not_emit_a_no_findings_message():
    message = _result_message(
        [object()], [object()], False, "complete", _coverage())
    assert message == ""


def test_report_names_skipped_components_and_the_ci_only_boundary():
    html = render_html(
        [], [],
        coverage={
            **_coverage(names=["fastapi", "pydantic"],
                        queried_ecosystems=["githubactions"]),
            "status": "provider_reported",
        },
    )
    assert "Not checked: fastapi, pydantic" in html
    assert "no application dependency was assessed" in html
