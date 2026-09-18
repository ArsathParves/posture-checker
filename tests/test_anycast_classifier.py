"""Regression tests for C4 — vergecloud.com was mis-graded as
single-point-of-failure because the anycast-operator classifier only
recognised a hardcoded set of Western brand strings.

CLAUDE.md ground truth #4::

    vergecloud.com | AS141383, IS anycast. Two NS ranges, one ASN.
    Must report 1 operator, and must NOT be penalised as a single
    point of failure. Guards against: The anycast name-list bug; the
    ASN-string-splitting bug.

Root Cause Principle: the truth is the ASN, not the brand string.
The classifier now takes both — checks the ASN table first (data-
driven, verifiable), and falls back to the brand-string set only
when no ASN is available. VergeCloud lives in the ASN table.
"""
from __future__ import annotations

import pytest

from posture.checks import (
    LARGE_ANYCAST_ASNS,
    LARGE_ANYCAST_OPERATORS,
    _is_large_anycast_operator,
)


# ---------------------------------------------------------- ground truth

def test_vergecloud_asn_is_in_the_anycast_table():
    """The single most important pin: AS141383 must be present."""
    assert 141383 in LARGE_ANYCAST_ASNS, (
        "VergeCloud (AS141383) must be recognised as a large anycast "
        "operator — see CLAUDE.md ground-truth row for vergecloud.com."
    )


def test_vergecloud_classified_as_anycast_via_asn():
    assert _is_large_anycast_operator(141383, "VergeCloud") is True


def test_vergecloud_classified_via_asn_even_without_org_string():
    """ASN alone is sufficient — Team Cymru's org lookup may fail or
    return an empty string; the ASN is still authoritative."""
    assert _is_large_anycast_operator(141383, "") is True


# ---------------------------------------- pre-existing operators (fallback)

def test_cloudflare_still_classified_via_brand_fallback():
    """Operators not yet ASN-mapped keep working through the legacy
    brand-string set. This test guards against a regression that would
    unmap Cloudflare when the ASN table was introduced."""
    assert _is_large_anycast_operator(None, "cloudflarenet, us") is True


def test_google_still_classified_via_brand_fallback():
    assert _is_large_anycast_operator(None, "AS15169 (GOOGLE, US)") is True


# --------------------------------------------------------- true negatives

def test_unknown_isp_is_not_classified_as_anycast():
    """A genuine single-operator small provider must still be flagged.
    The C4 fix must not silence legitimate correlated-failure findings."""
    assert _is_large_anycast_operator(None, "some private isp") is False
    assert _is_large_anycast_operator(64512, "generic hosting co") is False


def test_empty_inputs_return_false():
    assert _is_large_anycast_operator(None, "") is False
    assert _is_large_anycast_operator(None, None) is False


# --------------------------------------------- brand-set invariant

def test_brand_string_set_still_contains_known_entries():
    """Regression: adding the ASN table must not accidentally drop the
    legacy brand strings that other domains depend on."""
    for brand in ("cloudflare", "google", "amazon", "akamai"):
        assert brand in LARGE_ANYCAST_OPERATORS, (
            f"legacy brand {brand!r} dropped from LARGE_ANYCAST_OPERATORS"
        )
