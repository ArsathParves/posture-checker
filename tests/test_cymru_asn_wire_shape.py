"""BIAS-1 — Cymru returns ASN as a string; our anycast table is keyed on int.

Every prior test of the anycast classifier stubbed ``ip_rdap`` with a
pre-parsed ``{"asn": 141383, ...}`` (int). Production stubs the DNS
resolver, which means `cymru_asn` parses the RAW TXT record that Team
Cymru actually serves — and there, the ASN is a string (`"141383"`).

That string flows straight into ``LARGE_ANYCAST_ASNS: dict[int, str]``
via ``asn in LARGE_ANYCAST_ASNS`` in ``_is_large_anycast_operator`` —
``"141383" in {141383: "VergeCloud"}`` is **False**. The ASN-first
check silently misses, we fall through to the brand-string set, and
because Team Cymru returns the org string with a space
(``"VERGE-AS-AP - VERGE CLOUD PRIVATE LIMITED, IN"``) the substring
match against ``"vergecloud"`` (one word) also misses — so
``vergecloud.com`` grades as ``Network diversity: WARN`` in real life
while every test grades it INFO. Classic wire-vs-test divergence.

This test file locks the fix at the API boundary: ``cymru_asn`` must
return ``asn`` as ``int`` (not ``str``, not ``None``), and the raw TXT
wire shape must round-trip through the classifier all the way to the
"large anycast operator" verdict.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from posture import core, checks


# --------------------------------------------------------------------- helpers

def _fake_txt_answer(text: str):
    """Build a dnspython-answer-like object whose str() is a TXT record.

    ``cymru_asn`` reads ``ans[0]`` and casts to ``str``; that is enough
    surface for the parser (the real dnspython Answer type is heavier).
    """
    class _Item:
        def __init__(self, s):
            self._s = s

        def __str__(self):
            return self._s

    return [_Item(text)]


def _patch_resolver(monkeypatch, txt_by_query: dict[str, str]):
    """Route ``dns.resolver.Resolver.resolve`` at the raw wire layer.

    Every call in ``cymru_asn`` goes through
    ``dns.resolver.Resolver(configure=False).resolve(name, "TXT")`` —
    intercepting this returns the TXT bytes exactly as Cymru would.
    """
    import dns.resolver

    def _fake_resolve(self, name, rdtype):
        # dnspython accepts str or dns.name.Name; str(Name) has a trailing
        # dot, str-arg calls do not. Normalise both to the trailing-dot form
        # so the fixture keys are unambiguous.
        key = str(name).rstrip(".") + "."
        if key in txt_by_query:
            return _fake_txt_answer(txt_by_query[key])
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)


# --------------------------------------------------------------------- wire shape

def test_cymru_asn_returns_asn_as_int_not_string():
    """The boundary contract: ``cymru_asn(ip)["asn"]`` MUST be an ``int``.

    Cymru serves the ASN as a decimal string inside a TXT record; the
    tool must coerce at the boundary so downstream tables keyed on int
    (``LARGE_ANYCAST_ASNS``) actually match.
    """
    import pytest

    monkeypatch = pytest.MonkeyPatch()
    try:
        _patch_resolver(monkeypatch, {
            "1.113.0.203.origin.asn.cymru.com.":
                '"141383 | 203.0.113.0/24 | IN | apnic | 2019-05-30"',
            "AS141383.asn.cymru.com.":
                '"141383 | IN | apnic | 2019-05-30 | '
                'VERGE-AS-AP - VERGE CLOUD PRIVATE LIMITED, IN"',
        })
        got = core.cymru_asn("203.0.113.1")
    finally:
        monkeypatch.undo()

    assert got["ok"] is True, f"expected ok=True, got {got!r}"
    assert isinstance(got["asn"], int), (
        f"cymru_asn must coerce ASN to int at the boundary; got "
        f"{got['asn']!r} (type={type(got['asn']).__name__}). "
        f"This is what makes 'asn in LARGE_ANYCAST_ASNS' silently miss "
        f"for vergecloud.com."
    )
    assert got["asn"] == 141383
    assert "VERGE" in got["owner"].upper(), f"owner missing; got {got!r}"


def test_cymru_asn_int_flows_through_to_anycast_classifier(monkeypatch):
    """End-to-end plumbing test. The int ASN must survive the round trip
    through ``ip_rdap`` all the way to ``_is_large_anycast_operator``,
    or the fix doesn't actually change behaviour."""
    _patch_resolver(monkeypatch, {
        "1.113.0.203.origin.asn.cymru.com.":
            '"141383 | 203.0.113.0/24 | IN | apnic | 2019-05-30"',
        "AS141383.asn.cymru.com.":
            '"141383 | IN | apnic | 2019-05-30 | '
            'VERGE-AS-AP - VERGE CLOUD PRIVATE LIMITED, IN"',
    })

    info = core.ip_rdap("203.0.113.1")
    assert info["ok"] is True
    assert isinstance(info["asn"], int), (
        f"ip_rdap must propagate int asn from cymru_asn; got "
        f"{info['asn']!r} (type={type(info['asn']).__name__})"
    )

    is_anycast = checks._is_large_anycast_operator(
        info["asn"], info.get("org"))
    assert is_anycast is True, (
        f"AS141383 must classify as large anycast operator. "
        f"info={info!r}. If this fails, the ASN table lookup is still "
        f"defeated by str-vs-int mismatch — the same silent fall-through "
        f"that regressed vergecloud.com to WARN in real-life runs."
    )


def test_cymru_asn_none_when_wire_lookup_fails(monkeypatch):
    """When every resolver in the fallback list fails, ``cymru_asn`` must
    return the sentinel ``{"ok": False, ...}`` — not raise, not return a
    misleading partial dict. The classifier reads ``info.get("ok")`` and
    would happily anycast-flag garbage otherwise."""
    import dns.resolver

    def _always_nxdomain(self, name, rdtype):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _always_nxdomain)

    got = core.cymru_asn("192.0.2.1")
    assert got["ok"] is False
    assert "asn" not in got or got.get("asn") is None, (
        f"failure path must not leak a bogus asn value; got {got!r}"
    )


# --------------------------------------------------------------------- regression

def test_multiple_origin_asns_uses_first_and_coerces(monkeypatch):
    """Cymru's ``origin.asn`` TXT can carry MULTIPLE ASNs when an IP is
    announced by more than one AS (multi-origin IPs are legitimate on
    the internet). The parser already handles this via ``split()[0]``;
    the type coercion must apply to that first element."""
    _patch_resolver(monkeypatch, {
        "1.113.0.203.origin.asn.cymru.com.":
            '"141383 65001 | 203.0.113.0/24 | IN | apnic | 2019-05-30"',
        "AS141383.asn.cymru.com.":
            '"141383 | IN | apnic | 2019-05-30 | '
            'VERGE-AS-AP - VERGE CLOUD PRIVATE LIMITED, IN"',
    })

    got = core.cymru_asn("203.0.113.1")
    assert got["ok"] is True
    assert got["asn"] == 141383
    assert isinstance(got["asn"], int)
