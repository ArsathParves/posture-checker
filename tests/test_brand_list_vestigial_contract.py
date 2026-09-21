"""BIAS-9 — LARGE_ANYCAST_OPERATORS is vestigial; ASN + wire probe
are the sources of truth.

Root cause principle (CLAUDE.md): the tool trusted a hardcoded brand
list to decide "is this operator's single-NS estate a legitimate
anycast deployment, or a real single point of failure?". That list
was implicitly Western — 18 mostly-US names — and every new regional
anycast operator (VergeCloud among them) required a code change to
be recognised at all.

Two structural fixes replaced that trust:

  1. BIAS-3: pinned ASN table (``LARGE_ANYCAST_ASNS``). ASN is the
     protocol source of truth for network identity; Team Cymru's
     lookup returns it directly. An ASN match yields ``high``
     confidence.

  2. BIAS-4: wire-level ``id.server`` CH TXT probe. Any operator
     answering RFC 4892 with a PoP identifier is observably running
     professional authoritative infrastructure. A wire hit upgrades
     brand-only confidence from ``medium`` to ``high``.

With those two mechanisms in place, ``LARGE_ANYCAST_OPERATORS`` has
become a **fallback safety net**, not a truth source. Its job now is
only to keep pre-BIAS-3 test-domain grades stable while operators
migrate into the ASN table. New operators MUST NOT be added to it —
they must be added to ``LARGE_ANYCAST_ASNS`` with a verified AS number
or, failing that, be discovered by the wire probe.

Invariants this test locks:

  A. A brand-only match (no ASN, no wire hit) can produce **at most
     ``medium`` confidence**. It must never yield ``high``.
  B. The brand fallback still exists for the pre-BIAS-3 domains
     (cloudflare, google, akamai, …) so removing BIAS-3 or BIAS-4
     doesn't silently downgrade every existing anycast finding to
     ``low``.
  C. Contribution policy is documented in the module: new entries go
     to ``LARGE_ANYCAST_ASNS``, not to the brand set. The docstring
     comment for the constant is the pin the reader lands on.
"""
from __future__ import annotations

import re
from pathlib import Path

from posture.checks import (
    LARGE_ANYCAST_ASNS,
    LARGE_ANYCAST_OPERATORS,
    _anycast_confidence_tier,
    _is_large_anycast_operator,
)


CHECKS_SRC = Path(__file__).resolve().parents[1] / "posture" / "checks.py"


# --------------------------------------------------------- invariant A

def test_brand_only_match_maps_to_medium_confidence():
    """A brand hit WITHOUT an ASN in the pinned table must produce
    exactly ``medium`` — the tier that says "we recognise the name,
    but the wire hasn't confirmed it". The wire-probe upgrade to
    ``high`` is tested elsewhere; here we lock the pre-upgrade
    fallback ceiling."""
    host_info = {
        "ns1.example.": {"asn": None, "org": "CLOUDFLARENET, US"},
        "ns2.example.": {"asn": None, "org": "CLOUDFLARENET, US"},
    }
    assert _anycast_confidence_tier(host_info) == "medium", (
        "brand-only match must yield medium (not high) — an ASN "
        "pin is required for high confidence pre-wire-probe"
    )


def test_asn_verified_maps_to_high_confidence():
    """Complement of the invariant above: ASN pins are the ONLY
    thing that produces ``high`` pre-wire-probe. Locks the tier
    boundary so a future 'promote brand match to high' shortcut
    would fail this test."""
    host_info = {
        "ns1.vergecloud.": {"asn": 141383,
                             "org": "VERGE-AS-AP - VERGE CLOUD, IN"},
    }
    assert _anycast_confidence_tier(host_info) == "high"


def test_unknown_operator_yields_empty_tier():
    """Genuine single-operator small provider — no ASN pin, no brand
    match — must return the empty tier so the topology finding
    grades as a legitimate WARN (single point of failure), not a
    false-negative PASS."""
    host_info = {
        "ns1.small-isp.": {"asn": 64512, "org": "some private isp, in"},
        "ns2.small-isp.": {"asn": 64512, "org": "some private isp, in"},
    }
    assert _anycast_confidence_tier(host_info) == ""


# --------------------------------------------------------- invariant B

def test_pre_bias3_brands_still_fall_back_cleanly():
    """The brand set was the ONLY mechanism before BIAS-3. Removing
    it silently would downgrade every pre-BIAS-3 test-domain grade.
    Keep the classifier honest: with only a brand hit available, the
    verdict is still ``True`` (fallback works)."""
    for org in (
        "CLOUDFLARENET, US",
        "AS15169 (GOOGLE, US)",
        "AS16509 (AMAZON-02, US)",
        "AS20940 (AKAMAI-ASN1, US)",
    ):
        assert _is_large_anycast_operator(None, org) is True, (
            f"brand-fallback lost recognition for {org!r} — the "
            "vestigial safety net has stopped catching pre-BIAS-3 "
            "test domains"
        )


# --------------------------------------------------------- invariant C

def test_brand_set_is_documented_as_phase_out_target():
    """The comment block above the two constants must call out the
    brand set as a phase-out target — otherwise a contributor adds
    a new regional operator to the brand list instead of the ASN
    table, reintroducing the bias we already fixed.

    Wording-flexible: we require the substring 'phase-out' AND a
    mention of ``LARGE_ANYCAST_ASNS`` in the same paragraph, so
    future copy-edits can reword freely without regressing the pin."""
    src = CHECKS_SRC.read_text()
    # Grab the doc comment block that immediately precedes the two
    # constants — everything from the first line documenting
    # LARGE_ANYCAST_ASNS to the constant declaration itself.
    m = re.search(
        r"(#[^\n]*LARGE_ANYCAST_ASNS[^\n]*\n(?:#[^\n]*\n)*)"
        r"LARGE_ANYCAST_ASNS",
        src,
    )
    assert m is not None, (
        "could not locate the LARGE_ANYCAST_ASNS/OPERATORS comment "
        "block — the module structure changed; update this test to "
        "point at the new documentation location before re-running"
    )
    doc = m.group(1).lower()
    assert "phase-out" in doc or "phase out" in doc, (
        "the LARGE_ANYCAST_OPERATORS docstring must call the brand "
        "set a phase-out target so contributors know new operators "
        "belong in LARGE_ANYCAST_ASNS. Current doc:\n" + m.group(1)
    )
    assert "large_anycast_asns" in doc, (
        "the brand-set doc must reference LARGE_ANYCAST_ASNS as the "
        "preferred target for new operators. Current doc:\n"
        + m.group(1)
    )


def test_asn_table_is_the_primary_source():
    """VergeCloud (AS141383) — the operator whose omission triggered
    the whole BIAS sweep — must be classified via the ASN path, NOT
    the brand path. If someone regresses the classifier to check
    brand first, this test still passes (because the brand set now
    contains 'vergecloud' as a safety net), so we assert on the
    tier: ASN match yields ``high``; a brand match alone would yield
    ``medium``."""
    host_info = {
        "ns.vergecloud.": {"asn": 141383,
                            "org": "VERGE-AS-AP - VERGE CLOUD, IN"},
    }
    assert _anycast_confidence_tier(host_info) == "high", (
        "AS141383 must classify as 'high' via the ASN table — the "
        "topology-check bias fix depends on ASN being the primary "
        "source of truth"
    )


# ---------------------------------------------- policy pin (soft)

def test_new_operators_should_migrate_to_asn_table():
    """A soft pin: the vestigial brand set should be SHORTER over
    time, not longer. This test doesn't fail on growth — but it does
    fail if someone silently REMOVES the ASN table, which would
    revert us to the pre-BIAS-3 brand-only world.

    The count check is defensive: if a future refactor merges the
    two tables the test above catches it; if a future refactor
    deletes the ASN table this test catches it."""
    assert len(LARGE_ANYCAST_ASNS) >= 1, (
        "LARGE_ANYCAST_ASNS is empty — BIAS-3's pinned-ASN mechanism "
        "has been removed. Restore it or update this test to point "
        "at the replacement source of truth"
    )
    # VergeCloud (AS141383) is the canonical entry — its removal is
    # a regression per CLAUDE.md ground-truth #4.
    assert 141383 in LARGE_ANYCAST_ASNS
