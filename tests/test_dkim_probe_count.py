"""Regression tests for C3 — evaluate_dkim probed every selector twice.

Original shape (paraphrased)::

    with ThreadPoolExecutor(max_workers=12) as ex:
        found = [f for f in ex.map(probe, selectors) if f and not f.get("unretrievable")]

    # Check if any probe returned unretrievable
    any_unretrievable = any(f for f in ex.map(probe, selectors) if ...)

The second ``ex.map`` re-runs every probe. Beyond the obvious 2x DNS load,
it is called after the ``with`` block has already shut the pool down,
which historically triggered a RuntimeError on the fallback path and left
the "unretrievable" state unreachable.

Fix: consume the executor exactly once, partition results locally.
"""
from __future__ import annotations

from unittest.mock import patch

import posture.emailauth as ea
from posture.emailauth import COMMON_SELECTORS


def test_evaluate_dkim_probes_each_selector_exactly_once():
    """DNS load must scale with selector count, not double it.

    evaluate_dkim also fires a randomised 'canary' probe (wildcard guard)
    before the selector fan-out. Count only the real selector probes;
    each COMMON_SELECTORS entry must appear exactly once."""
    calls: list[str] = []

    def fake_txt(name: str):
        calls.append(name)
        return []

    with patch.object(ea, "_txt_records", side_effect=fake_txt):
        ea.evaluate_dkim("example.com")

    for sel in COMMON_SELECTORS:
        matches = [c for c in calls if c == f"{sel}._domainkey.example.com"]
        assert len(matches) == 1, (
            f"selector {sel!r} probed {len(matches)} times, expected 1. "
            f"All calls: {calls}"
        )


def test_evaluate_dkim_probes_extra_selectors_once():
    """Extras (user-supplied via --dkim-selector) also probed once each."""
    calls: list[str] = []

    def fake_txt(name: str):
        calls.append(name)
        return []

    extras = ["custom1", "custom2"]
    with patch.object(ea, "_txt_records", side_effect=fake_txt):
        ea.evaluate_dkim("example.com", extra_selectors=extras)

    for sel in extras:
        matches = [c for c in calls if c == f"{sel}._domainkey.example.com"]
        assert len(matches) == 1, (
            f"extra selector {sel!r} probed {len(matches)} times, expected 1"
        )


def test_evaluate_dkim_marks_unretrievable_when_any_selector_truncates():
    """Rule-1: an unretrievable selector must not silently collapse to
    'not found'. This exercises the second-map path that used to be
    behind a shut-down executor."""
    def fake_txt(name: str):
        # First selector probe raises unretrievable
        raise ea.TxtUnretrievable("truncated")

    with patch.object(ea, "_txt_records", side_effect=fake_txt):
        result = ea.evaluate_dkim("example.com")

    assert "unretrievable" in result, (
        f"expected unretrievable marker in result, got keys {list(result)}"
    )
