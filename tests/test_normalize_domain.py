"""Regression tests for posture.core.normalize_domain (N6, N7, N9, N21).

The normaliser is the API boundary — bad input rejected here can never reach
DNS. These tests pin the rejection contract that N6/N7/N9 fixed.
"""
from __future__ import annotations

import pytest

from posture.core import normalize_domain


class TestIpRejection:
    """N9, N21 — IPv4/IPv6 must be rejected, not silently used as a domain."""

    def test_ipv4_is_rejected(self):
        with pytest.raises(ValueError, match="IP address"):
            normalize_domain("192.0.2.1")

    def test_ipv6_is_rejected(self):
        with pytest.raises(ValueError, match="IP address"):
            normalize_domain("2001:db8::1")


class TestLabelLength:
    """N6 — RFC 1035 s2.3.4: labels must be <=63 octets."""

    def test_label_over_63_octets_rejected(self):
        oversized = "a" * 64
        with pytest.raises(ValueError, match="63 octets"):
            normalize_domain(f"{oversized}.example.com")

    def test_label_exactly_63_octets_accepted(self):
        ok_label = "a" * 63
        display, puny, _ = normalize_domain(f"{ok_label}.example.com")
        assert display == f"{ok_label}.example.com"
        assert puny == f"{ok_label}.example.com"


class TestTldLength:
    """N7 — TLDs must be at least 2 characters."""

    def test_single_char_tld_rejected(self):
        with pytest.raises(ValueError, match="TLD"):
            normalize_domain("example.a")


class TestUrlStripping:
    """Input hygiene — scheme/path/userinfo/port stripped before puny encode."""

    def test_scheme_stripped(self):
        display, puny, _ = normalize_domain("https://example.com/path?q=1")
        assert display == "example.com"
        assert puny == "example.com"

    def test_userinfo_stripped(self):
        _, puny, _ = normalize_domain("user@example.com")
        assert puny == "example.com"

    def test_port_stripped(self):
        _, puny, _ = normalize_domain("example.com:8443")
        assert puny == "example.com"

    def test_www_prefix_stripped_with_note(self):
        _, _, notes = normalize_domain("www.example.com")
        assert any("www" in n.lower() for n in notes)


class TestIdn:
    """Punycode form must be produced and shown to guard against homographs."""

    def test_idn_produces_xn_punycode(self):
        display, puny, notes = normalize_domain("münchen.de")
        assert display != puny
        assert puny.startswith("xn--")
        assert any("punycode" in n.lower() for n in notes)


class TestBidiIdn:
    """E2 — Bidirectional IDN (Arabic/Hebrew labels).

    Homograph safety requires that RTL labels round-trip cleanly through
    the punycode pipeline. If any encoding step silently mangles a script
    with strong-right characters, the display form and puny form drift
    apart and downstream findings render one thing while querying
    another. Pin the round-trip for a handful of RTL scripts."""

    def test_arabic_label_round_trips(self):
        """Arabic label under an ASCII TLD must produce an xn-- puny form
        distinct from the display form. Ground truth verified with the
        `idna` codec: 'يمن' → xn--hhbck."""
        display, puny, notes = normalize_domain("يمن.ye")
        assert display == "يمن.ye"
        assert puny == "xn--hhbck.ye"
        assert display != puny
        assert any("punycode" in n.lower() for n in notes)

    def test_arabic_label_and_arabic_tld(self):
        """Both label and TLD in Arabic — every dot-separated segment
        must be encoded independently, none silently dropped."""
        display, puny, _ = normalize_domain("مثال.إختبار")
        assert display == "مثال.إختبار"
        # Two xn-- segments, one per label. This shape guards against
        # the codec eating the TLD or joining the labels.
        assert puny.count("xn--") == 2
        assert "." in puny

    def test_hebrew_label_under_ascii_tld(self):
        """Hebrew (also RTL) under .co.il — three-label form must not
        confuse the puny encoder."""
        display, puny, _ = normalize_domain("ישראל.co.il")
        assert display == "ישראל.co.il"
        assert puny.startswith("xn--") and puny.endswith(".co.il")

    def test_bidi_puny_is_ascii_only(self):
        """The puny form is the string that hits DNS. It MUST be ASCII —
        any non-ASCII byte leaking through would fail the wire encoding
        and defeat the homograph guard the puny form exists to provide."""
        _, puny, _ = normalize_domain("טעסט.co.il")
        assert puny.isascii(), f"puny form must be ASCII, got {puny!r}"


class TestObviousGarbage:
    """No dot means not a domain."""

    def test_bare_word_rejected(self):
        with pytest.raises(ValueError):
            normalize_domain("localhost")

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            normalize_domain("")


class TestBoundaryLengths:
    """E1 — RFC 1035 §2.3.4 total-length limit (253 octets excluding
    the trailing dot) must be enforced at the API boundary, and the
    exact boundary values must behave correctly. The v0.5 normaliser
    checked per-label length but had NO total-length check — a domain
    of 4×63-char labels (255 chars including 3 dots) would slip through
    and hit `idna` / dnspython downstream where the errors are less
    helpful."""

    def test_total_length_exactly_253_accepted(self):
        """The maximum-legal FQDN: labels chosen so the total is 253.
        Use 3×63-char labels (189) + a 60-char label + 3 dots = 252,
        add one char = 253. Must be accepted."""
        parts = ["a" * 63, "a" * 63, "a" * 63, "a" * 61]
        name = ".".join(parts)  # 63+63+63+61 + 3 dots = 253
        assert len(name) == 253
        _, puny, _ = normalize_domain(name)
        assert puny == name

    def test_total_length_over_253_rejected(self):
        """One char over the limit must fail with a clear message
        naming the 253-octet cap, not an obscure downstream error."""
        parts = ["a" * 63, "a" * 63, "a" * 63, "a" * 62]
        name = ".".join(parts)  # 63+63+63+62 + 3 dots = 254
        assert len(name) == 254
        with pytest.raises(ValueError, match=r"253|total length|too long"):
            normalize_domain(name)

    def test_label_exactly_63_octets_at_the_start_accepted(self):
        """Belt-and-braces on N6: the 63-char boundary works at every
        position, not just the leading label."""
        _, puny, _ = normalize_domain(f"example.{'a' * 63}.com")
        assert f"{'a' * 63}" in puny
