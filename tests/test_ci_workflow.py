"""Regression tests for T8/T9 — the repo has no `.github/workflows/*`
directory, so tests exist but are not gated on PR. Any regression that
touches an untested code path can land without triggering a red run.

Contract pinned:
  - A workflow file exists at `.github/workflows/tests.yml`.
  - It runs on `push` AND `pull_request` targeting main (the merge gate).
  - It invokes `pytest -m "not network"` at least once (T9 marker split).
  - It uses a supported Python floor (`3.10`, per CP3).
  - Nightly network run exists — `schedule:` block + `-m "network"`
    invocation — so live-DNS ground truth doesn't drift silently.

These are structural checks over the YAML text (not a runtime parse
via PyYAML). Keeps the test dep-graph small; the workflow file is
small enough that string presence is unambiguous.
"""
from __future__ import annotations

from pathlib import Path

import pytest


WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "tests.yml"


@pytest.fixture(scope="module")
def workflow_text() -> str:
    assert WORKFLOW_PATH.exists(), (
        f"CI workflow missing at {WORKFLOW_PATH}. T8 requires a gated "
        f"offline test run on every PR."
    )
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def test_workflow_runs_on_pull_request(workflow_text):
    """Merge gate must fire on `pull_request` — a workflow that only
    runs on `push` doesn't gate incoming contributions."""
    assert "pull_request" in workflow_text, (
        "workflow must trigger on pull_request; otherwise it does not "
        "gate PRs against main."
    )


def test_workflow_runs_on_push_to_main(workflow_text):
    """A `push` trigger on main keeps the required-status-check flag
    fresh for branch protection rules (which read from the last run
    on the target branch)."""
    assert "push:" in workflow_text and "main" in workflow_text


def test_offline_suite_uses_not_network_marker(workflow_text):
    """T9 marker split: `pytest -m "not network"` MUST be the CI gate.
    A CI that runs the whole suite would fail every time a public
    resolver rate-limits the runner — flaky PRs are worse than none."""
    assert 'pytest -m "not network"' in workflow_text, (
        'CI gate must invoke `pytest -m "not network"`; currently it '
        'does not, which risks running network-dependent tests on PR.'
    )


def test_python_floor_matches_cp3(workflow_text):
    """CP3 pinned `requires-python = ">=3.10"`. CI must actually
    exercise that floor — a workflow that only tests 3.12 lets 3.10
    incompatibilities land."""
    assert '"3.10"' in workflow_text or "'3.10'" in workflow_text, (
        "CI matrix must include Python 3.10 to validate the CP3 floor."
    )


def test_nightly_network_suite_scheduled(workflow_text):
    """Network-marked tests still exist (ground-truth domain assertions
    for cloudflare.com, google.com, etc.). Running them on schedule
    catches drift between the tool's expectations and real DNS state
    without gating PRs on public-resolver flakiness."""
    assert "schedule:" in workflow_text, (
        "workflow must define a schedule: block for the nightly network run."
    )
    assert 'pytest -m "network"' in workflow_text, (
        'nightly job must invoke `pytest -m "network"` to actually run '
        "the ground-truth checks."
    )


def test_uses_pinned_action_versions(workflow_text):
    """A `@main` or unpinned `uses:` reference on an action is a supply-
    chain footgun — the action author can push a new HEAD that runs on
    every subsequent PR. Pin to major versions at minimum."""
    for action_prefix in ("actions/checkout@", "actions/setup-python@"):
        assert action_prefix in workflow_text, (
            f"missing pinned reference for {action_prefix}"
        )
        # The pinned version follows immediately; assert the reference
        # does NOT end at the raw `@` (would mean unpinned) or `@main`.
        line = next(
            (line for line in workflow_text.splitlines()
             if action_prefix in line),
            "",
        )
        assert "@main" not in line and "@master" not in line, (
            f"{action_prefix} must be pinned to a version, not @main/@master"
        )
