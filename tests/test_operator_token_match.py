"""BIAS-3 — the brand-string classifier used a substring ``in`` check.

Cymru returns owner strings the way the AS registry serves them:

  ``"VERGE-AS-AP - VERGE CLOUD PRIVATE LIMITED, IN"``
  ``"CLOUDFLARENET, US"``
  ``"AMAZON-02"``

The pre-BIAS-3 fallback in ``_is_large_anycast_operator`` was
``any(k in blob for k in LARGE_ANYCAST_OPERATORS)`` — a substring
match. This works for one-word brands ("cloudflare" is a substring of
"cloudflarenet") but silently fails for any operator whose registry
name inserts a space, hyphen or extra token that breaks the substring.
``"vergecloud"`` (one word) is NOT a substring of ``"verge cloud
private limited"`` (two words) — and that's the exact fallthrough that
regressed vergecloud.com in the field even after C4 shipped.

Fix: normalise both sides to token sets and check for a token
intersection with the brand keys' tokens. That handles space / hyphen
/ punctuation variants uniformly and covers the "we've seen the same
brand written three different ways across three RIRs" reality.
"""
from __future__ import annotations

from posture.checks import _is_large_anycast_operator


# --------------------------------------------------------------------- vergecloud shapes

def test_verge_cloud_two_word_registry_string_matches():
    """The exact string Team Cymru returns for AS141383 today. Must
    match ``vergecloud`` in the brand set post-BIAS-3 even though it's
    two space-separated words."""
    assert _is_large_anycast_operator(
        None, "VERGE-AS-AP - VERGE CLOUD PRIVATE LIMITED, IN") is True, (
        "'VERGE CLOUD PRIVATE LIMITED' must match brand token 'vergecloud' "
        "via token normalisation, not substring — this is the exact "
        "fallthrough that regressed vergecloud.com."
    )


def test_verge_cloud_hyphenated_matches():
    """Same operator, hyphen-joined variant that some RIRs emit."""
    assert _is_large_anycast_operator(
        None, "VERGE-CLOUD-AP, IN") is True


def test_vergecloud_one_word_still_matches():
    """The historical form must continue to match — the fix must not
    regress the substring case."""
    assert _is_large_anycast_operator(
        None, "vergecloud pvt ltd") is True


# --------------------------------------------------------------------- cross-brand normalisation

def test_google_llc_matches():
    """Real Cymru string for AS15169. The brand key is 'google'."""
    assert _is_large_anycast_operator(
        None, "GOOGLE, US") is True


def test_cloudflarenet_matches():
    """Real Cymru string for AS13335. Substring check already handled
    this — the token match must not regress it."""
    assert _is_large_anycast_operator(
        None, "CLOUDFLARENET, US") is True


def test_amazon_registry_matches():
    """Amazon's registry name is ``AMAZON-02`` — hyphenated. Substring
    check for ``"amazon"`` inside ``"amazon-02"`` worked; token check
    must also work."""
    assert _is_large_anycast_operator(
        None, "AMAZON-02") is True


# --------------------------------------------------------------------- negative counter-invariants

def test_generic_isp_still_does_not_match():
    """The classifier must not over-widen. A generic ISP whose org name
    contains none of the brand tokens must NOT be classified as
    anycast, or the WARN case dies and every single-operator SPOF
    grades PASS silently."""
    assert _is_large_anycast_operator(
        None, "Some Regional ISP Limited, IN") is False


def test_brand_substring_inside_unrelated_word_does_not_match():
    """A token match must not fire on a random substring collision.
    'Amazon' as a token — yes; 'amazoning' as part of some fictional
    company name — no. Guards against the classic substring-match
    over-widening bug (``"google"`` matching ``"googol"``)."""
    # Fake org whose name accidentally contains the brand token as a
    # substring but not as a whole token.
    assert _is_large_anycast_operator(
        None, "amazoning ltd") is False, (
        "token match must not fire on substring-only overlap"
    )


def test_none_org_returns_false():
    """Rule-1 boundary: unknown org (Cymru failed) must not be
    classified either way — return False and let the caller emit
    WARN(low)."""
    assert _is_large_anycast_operator(None, None) is False
    assert _is_large_anycast_operator(None, "") is False


# --------------------------------------------------------------------- ASN-first still wins

def test_asn_match_short_circuits_org_check():
    """ASN is the protocol source of truth — if the AS number is in the
    table, we return True even if the org string is garbage. Keeps
    BIAS-1 semantics intact after BIAS-3."""
    assert _is_large_anycast_operator(141383, "Garbage String, XX") is True
