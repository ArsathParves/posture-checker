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


class TestObviousGarbage:
    """No dot means not a domain."""

    def test_bare_word_rejected(self):
        with pytest.raises(ValueError):
            normalize_domain("localhost")

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            normalize_domain("")
