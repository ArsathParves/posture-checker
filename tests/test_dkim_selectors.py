"""Regression tests for N19 — DKIM common-selector list includes the ESPs
that dominate the India-BFSI segment this tool targets.

The tool must probe these selectors or it will silently miss DKIM records
on domains signed by regional ESPs (Netcore, Pepipost, ZeptoMail, Kaleyra,
Gupshup) and report DKIM 'not found under common selectors' when the
record is actually present.
"""
from __future__ import annotations

from posture.emailauth import COMMON_SELECTORS


INDIA_REGION_SELECTORS = [
    "netcore", "pepipost", "zeptomail", "kaleyra", "gupshup",
]

WESTERN_ESP_SELECTORS = [
    "google", "sendgrid", "amazonses", "mailjet", "mandrill",
]

GENERIC_SELECTORS = ["default", "selector1", "selector2", "mail", "dkim"]


def test_india_region_selectors_are_probed():
    """N19: India-region ESPs must be in the probe list."""
    missing = [s for s in INDIA_REGION_SELECTORS if s not in COMMON_SELECTORS]
    assert not missing, f"Missing India-region selectors: {missing}"


def test_western_esp_selectors_still_probed():
    """Regression: adding India selectors must not drop the Western ones."""
    missing = [s for s in WESTERN_ESP_SELECTORS if s not in COMMON_SELECTORS]
    assert not missing, f"Missing Western ESP selectors: {missing}"


def test_generic_selectors_still_probed():
    missing = [s for s in GENERIC_SELECTORS if s not in COMMON_SELECTORS]
    assert not missing, f"Missing generic selectors: {missing}"


def test_no_duplicate_selectors():
    """A duplicate wastes a DNS query and can double-count in reports."""
    assert len(COMMON_SELECTORS) == len(set(COMMON_SELECTORS))
