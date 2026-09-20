"""B29 — extend authoritative-vs-cached parity to MX/TXT/CAA/NS.

`authoritative_vs_cached` previously only compared A and AAAA
between the authoritative NS and the public-resolver (cached)
view. That missed the whole class of "cache lag or geo-steering
on the records that matter for posture" — MX (mail routing), TXT
(SPF/DKIM/DMARC), CAA (CA policy), and NS (delegation drift).

Rule 1 preserved: the `records[rdtype].error` per-rdtype error
path already handles unreachable authoritative NS; that behaviour
is unchanged. These tests exercise the happy paths where the
authoritative UDP round-trip completes and answers differ from
the cached view.
"""
from __future__ import annotations

import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rrset

import posture.dnsmod as dnsmod


class _FakeResponse:
    """Minimal stand-in for `dns.query.udp`'s return object. Only the
    `.answer` iterable is inspected by `authoritative_vs_cached`."""
    def __init__(self, rdtype_str, records):
        self._rdtype_str = rdtype_str
        self._records = records

    @property
    def answer(self):
        if not self._records:
            return []
        rdtype = getattr(dns.rdatatype, self._rdtype_str)
        rrset = dns.rrset.from_text_list(
            dns.name.from_text("example.com."), 300,
            dns.rdataclass.IN, rdtype, self._records,
        )
        return [rrset]


def _install_fakes(monkeypatch, cached, authoritative):
    """Stub `dnsmod.query` (cached view) and `dns.query.udp`
    (authoritative view) with per-rdtype record lists."""
    def _fake_query(name, rdtype, nameservers=None):
        return {"ok": True, "records": cached.get(rdtype, []), "ttl": 300}

    monkeypatch.setattr(dnsmod, "query", _fake_query)

    def _fake_udp(q, ns_ip, timeout=None, **kwargs):
        rdtype_num = q.question[0].rdtype
        rdtype_str = dns.rdatatype.to_text(rdtype_num)
        return _FakeResponse(rdtype_str, authoritative.get(rdtype_str, []))

    monkeypatch.setattr(dns.query, "udp", _fake_udp)


_NS_MAP = {"ns1.example.com": {"ipv4": ["192.0.2.1"]}}
_EMPTY_TYPES = {"A": [], "AAAA": [], "MX": [], "TXT": [], "CAA": [], "NS": []}


def _view(**overrides):
    """Merge overrides onto an all-empty base — keeps each test to
    just the type it cares about."""
    v = dict(_EMPTY_TYPES)
    v.update(overrides)
    return v


# --------------------------------------------------------------------- MX

def test_mx_disagreement_surfaces(monkeypatch):
    """Cache serves the old MX target; authoritative serves the new
    one. This is a real drift scenario during mail-provider migration
    and must be surfaced."""
    _install_fakes(
        monkeypatch,
        cached=_view(MX=['10 old.example.com.']),
        authoritative=_view(MX=['10 new.example.com.']),
    )
    result = dnsmod.authoritative_vs_cached("example.com", _NS_MAP)
    assert result["checked"] is True
    assert result["agree"] is False
    assert "MX" in result["disagreements"]


# --------------------------------------------------------------------- TXT

def test_txt_disagreement_surfaces(monkeypatch):
    """SPF-relevant: cache has stale `include:` set, authoritative has
    the new one. A cache-vs-auth drift on TXT can leave email auth
    silently broken for a portion of the internet."""
    _install_fakes(
        monkeypatch,
        cached=_view(TXT=['"v=spf1 include:_spf.old.com ~all"']),
        authoritative=_view(TXT=['"v=spf1 include:_spf.new.com ~all"']),
    )
    result = dnsmod.authoritative_vs_cached("example.com", _NS_MAP)
    assert "TXT" in result["disagreements"]


# --------------------------------------------------------------------- CAA

def test_caa_disagreement_surfaces(monkeypatch):
    """CAA cache drift means a CA that WAS allowed at issuance time
    may no longer be — or a CA that IS forbidden may still succeed
    if the CA hits a stale resolver. Surface it."""
    _install_fakes(
        monkeypatch,
        cached=_view(CAA=['0 issue "letsencrypt.org"']),
        authoritative=_view(CAA=['0 issue "digicert.com"']),
    )
    result = dnsmod.authoritative_vs_cached("example.com", _NS_MAP)
    assert "CAA" in result["disagreements"]


# --------------------------------------------------------------------- NS

def test_ns_disagreement_surfaces(monkeypatch):
    """NS drift between the authoritative NS and cached view = classic
    delegation-migration halfway state. Ops needs to see this named
    explicitly."""
    _install_fakes(
        monkeypatch,
        cached=_view(NS=["ns1.example.com.", "ns2.example.com."]),
        authoritative=_view(NS=["ns1.example.com.", "ns3.example.com."]),
    )
    result = dnsmod.authoritative_vs_cached("example.com", _NS_MAP)
    assert "NS" in result["disagreements"]


# --------------------------------------------------------------------- happy path

def test_all_agree_reports_agree(monkeypatch):
    """Rule 1 sanity: if every rdtype matches, `agree=True` and
    `disagreements` is empty — otherwise every domain false-positives."""
    same = _view(A=["1.1.1.1"], NS=["ns1.example.com."])
    _install_fakes(monkeypatch, cached=same, authoritative=same)
    result = dnsmod.authoritative_vs_cached("example.com", _NS_MAP)
    assert result["agree"] is True
    assert result["disagreements"] == []


def test_result_records_include_all_extended_types(monkeypatch):
    """Structural: `records` dict must key on A, AAAA, MX, TXT, CAA, NS
    — the checks.py renderer needs per-type entries to show detail."""
    same = _view(A=["1.1.1.1"], NS=["ns1.example.com."])
    _install_fakes(monkeypatch, cached=same, authoritative=same)
    result = dnsmod.authoritative_vs_cached("example.com", _NS_MAP)
    for rdtype in ("A", "AAAA", "MX", "TXT", "CAA", "NS"):
        assert rdtype in result["records"], (
            f"missing {rdtype} in records dict; got "
            f"{list(result['records'])}"
        )


# --------------------------------------------------------------------- multi-type disagreement

def test_multiple_disagreements_reported_individually(monkeypatch):
    """A migration in flight can drift multiple rdtypes at once
    (MX + NS is very common during a provider swap). Each affected
    rdtype must land in `disagreements` — not collapsed into one."""
    _install_fakes(
        monkeypatch,
        cached=_view(
            MX=['10 old.example.com.'],
            NS=["ns-old.example.com."],
        ),
        authoritative=_view(
            MX=['10 new.example.com.'],
            NS=["ns-new.example.com."],
        ),
    )
    result = dnsmod.authoritative_vs_cached("example.com", _NS_MAP)
    assert "MX" in result["disagreements"]
    assert "NS" in result["disagreements"]
