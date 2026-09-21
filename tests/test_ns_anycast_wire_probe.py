"""BIAS-4 — wire-level anycast signal detection.

Post-BIAS-3 the classifier still leans on a hardcoded brand list to
tell "single operator that runs anycast" apart from "genuine single
point of failure". The brand list has an implicit Western bias
(``LARGE_ANYCAST_OPERATORS`` is 18 names, most US-based) and every new
regional anycast operator (VergeCloud among them) has to be added by
hand.

BIAS-4 introduces a **wire-level signal**: query the CH-class TXT
record ``id.server`` (RFC 4892 / BCP 178) at the NS IP directly.
Every professional authoritative DNS platform (BIND, NSD, PowerDNS,
Knot, Cloudflare's fork, AWS Route 53's fork, and yes, VergeCloud
ADNS) exposes this and returns a PoP identifier like ``"fra01.…"``
or ``"iad.…"``. A well-formed CH TXT ``id.server`` response is
observable ground truth that the operator runs proper authoritative
infrastructure — a much stronger signal than "the org name matches
a string in our list".

This test file locks the ``probe_ns_id_server`` helper and its
downstream use in ``_nameservers`` — a brand-string-only match that
gets a wire-level CH TXT hit upgrades the topology finding's
confidence tier from ``medium`` to ``high``.

Rule-5 boundary: this probe hits the NS IP directly and MUST be
suppressed when ``env.safe_for_per_ns_checks`` is False (the same
gate that already protects per-NS SOA probes).
"""
from __future__ import annotations

import pytest

from posture import checks, dnsmod
from posture.core import Report


# --------------------------------------------------------------------- helpers

class _FakeAnswer:
    """Minimal dnspython-Message stand-in for the CH TXT path.

    ``probe_ns_id_server`` reads ``resp.rcode()`` first, then iterates
    ``resp.answer`` yielding RRsets whose items have a ``to_text()``.
    """
    def __init__(self, txt_value: str):
        self._txt = txt_value

    def rcode(self):
        import dns.rcode
        return dns.rcode.NOERROR

    @property
    def answer(self):
        class _RR:
            def __init__(self, s):
                self._s = s
            def to_text(self):
                return f'"{self._s}"'
            def __iter__(self):
                return iter([self])
        return [_RR(self._txt)]


# --------------------------------------------------------------------- probe primitive

def test_probe_ns_id_server_returns_identifier_on_wire_hit(monkeypatch):
    """When the NS at ``ns_ip`` answers CH TXT ``id.server`` with a
    non-empty payload, the probe returns that payload verbatim. This
    is the positive-signal path — any well-formed response confirms
    the operator runs authoritative infrastructure that supports
    RFC 4892."""

    def _fake_udp(query, ip, timeout=None):
        # Assert the query is asking for id.server CH TXT — the whole
        # point is to be selective.
        qname = str(query.question[0].name)
        assert qname.lower().rstrip(".") == "id.server", (
            f"probe must ask for id.server, not {qname!r}"
        )
        return _FakeAnswer("fra01.vergecloud")

    monkeypatch.setattr(dnsmod.dns.query, "udp", _fake_udp)
    got = dnsmod.probe_ns_id_server("203.0.113.1")
    assert got["ok"] is True
    assert got["identifier"] == "fra01.vergecloud"


def test_probe_ns_id_server_returns_ok_false_on_refused(monkeypatch):
    """Many authoritative servers REFUSE CH-class queries (default
    BIND config). That is NOT evidence against anycast — just an
    unresponsive probe. Rule 1: unretrievable must not collapse into
    'not anycast'."""

    def _fake_udp(query, ip, timeout=None):
        import dns.rcode
        resp = dnsmod.dns.message.Message()
        resp.set_rcode(dns.rcode.REFUSED)
        return resp

    monkeypatch.setattr(dnsmod.dns.query, "udp", _fake_udp)
    got = dnsmod.probe_ns_id_server("203.0.113.1")
    assert got["ok"] is False
    assert "identifier" not in got or got.get("identifier") in (None, "")


def test_probe_ns_id_server_returns_ok_false_on_timeout(monkeypatch):
    """UDP timeout is another unretrievable path — same rule-1
    treatment. The classifier reads ok=False and stays at its
    pre-probe confidence tier."""

    def _fake_udp(query, ip, timeout=None):
        raise dnsmod.dns.exception.Timeout()

    monkeypatch.setattr(dnsmod.dns.query, "udp", _fake_udp)
    got = dnsmod.probe_ns_id_server("203.0.113.1")
    assert got["ok"] is False


def test_probe_ns_id_server_returns_ok_false_on_empty_txt(monkeypatch):
    """A CH TXT response with an empty payload is legal but useless as
    a signal. Treat it as ok=False so the classifier doesn't upgrade
    confidence on the strength of an empty string."""

    def _fake_udp(query, ip, timeout=None):
        return _FakeAnswer("")

    monkeypatch.setattr(dnsmod.dns.query, "udp", _fake_udp)
    got = dnsmod.probe_ns_id_server("203.0.113.1")
    assert got["ok"] is False


# --------------------------------------------------------------------- caller integration

def _stub_ns_and_ips(_domain):
    return {
        "ok": True,
        "ttl": 3600,
        "ns": {
            "ns1.example.": {"ipv4": ["203.0.113.1"], "ipv6": []},
            "ns2.example.": {"ipv4": ["203.0.113.2"], "ipv6": []},
        },
    }


def _stub_parent_delegation(_domain):
    return {"ok": True, "nameservers": ["ns1.example", "ns2.example"],
            "queried_via": ["a.tld-server.example"], "consensus": True}


def _stub_probe_each_ns(_domain, ns_map):
    return {h: {"reachable": True, "authoritative": True,
                "serial": 1, "rtt_ms": 12, "error": None}
            for h in ns_map}


def _install_stubs(monkeypatch, ip_rdap_map, id_server_by_ip):
    monkeypatch.setattr(checks.dnsmod, "get_ns_and_ips", _stub_ns_and_ips)
    monkeypatch.setattr(checks.dnsmod, "parent_delegation",
                        _stub_parent_delegation)
    monkeypatch.setattr(checks.dnsmod, "probe_each_ns", _stub_probe_each_ns)
    monkeypatch.setattr(checks.dnsmod, "tcp53_support",
                        lambda d, m: {"ok": True, "all_supported": True,
                                      "supported": list(m),
                                      "unsupported": [], "skipped": []})
    monkeypatch.setattr(checks.dnsmod, "edns_cookie_support",
                        lambda d, m: {"ok": True, "all_supported": True,
                                      "supported": list(m),
                                      "unsupported": [], "skipped": []})
    monkeypatch.setattr(checks, "ip_rdap",
                        lambda ip: ip_rdap_map.get(ip, {"ok": False}))

    def _fake_probe(ip):
        v = id_server_by_ip.get(ip)
        if v:
            return {"ok": True, "identifier": v}
        return {"ok": False}

    monkeypatch.setattr(checks.dnsmod, "probe_ns_id_server", _fake_probe)


def _new_report() -> Report:
    rep = Report(domain_input="example.test", domain="example.test",
                 punycode="example.test")
    rep.data["environment"] = {"safe_for_per_ns_checks": True, "notes": []}
    return rep


def test_brand_only_match_with_id_server_hit_upgrades_to_high(monkeypatch):
    """The BIAS-4 payoff: a single-operator zone whose ASN is NOT in
    the pinned table but whose CH TXT ``id.server`` returns a
    well-formed identifier grades ``PASS(high)`` — the wire is the
    protocol source of truth, and it just told us "yes, this is a
    real anycast estate", overriding the brand-only-heuristic
    downgrade to ``medium``."""
    _install_stubs(monkeypatch,
                   ip_rdap_map={
                       "203.0.113.1": {"ok": True, "asn": None,
                                       "org": "CLOUDFLARENET, US"},
                       "203.0.113.2": {"ok": True, "asn": None,
                                       "org": "CLOUDFLARENET, US"},
                   },
                   id_server_by_ip={
                       "203.0.113.1": "fra01.cloudflare",
                       "203.0.113.2": "iad.cloudflare",
                   })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = [f for f in rep.findings
               if f.label == "Nameserver topology"][0]
    assert finding.status == "PASS"
    assert finding.confidence == "high", (
        f"CH TXT id.server hit must upgrade brand-only confidence to "
        f"high; got {finding.confidence!r}. detail={finding.detail!r}"
    )


def test_brand_only_match_without_id_server_stays_medium(monkeypatch):
    """Counter-invariant: when the CH TXT probe fails (REFUSED,
    timeout, etc.) confidence must NOT upgrade. The upgrade is a
    signal, not an assumption."""
    _install_stubs(monkeypatch,
                   ip_rdap_map={
                       "203.0.113.1": {"ok": True, "asn": None,
                                       "org": "CLOUDFLARENET, US"},
                       "203.0.113.2": {"ok": True, "asn": None,
                                       "org": "CLOUDFLARENET, US"},
                   },
                   id_server_by_ip={})  # no wire hits
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = [f for f in rep.findings
               if f.label == "Nameserver topology"][0]
    assert finding.confidence == "medium", (
        f"no CH TXT signal must not upgrade confidence; got "
        f"{finding.confidence!r}. detail={finding.detail!r}"
    )


def test_env_unsafe_skips_id_server_probe(monkeypatch):
    """Rule-5 gate. When ``safe_for_per_ns_checks`` is False the tool
    MUST NOT emit direct probes to the NS IPs — the network path is
    untrustworthy. The probe function must not be called at all."""
    called = []

    def _tracked_probe(ip):
        called.append(ip)
        return {"ok": True, "identifier": "shouldnt-see-this"}

    _install_stubs(monkeypatch,
                   ip_rdap_map={
                       "203.0.113.1": {"ok": True, "asn": None,
                                       "org": "CLOUDFLARENET, US"},
                       "203.0.113.2": {"ok": True, "asn": None,
                                       "org": "CLOUDFLARENET, US"},
                   },
                   id_server_by_ip={})
    # Override the probe to track invocation
    monkeypatch.setattr(checks.dnsmod, "probe_ns_id_server", _tracked_probe)

    rep = _new_report()
    rep.data["environment"] = {"safe_for_per_ns_checks": False,
                               "notes": ["fake"]}
    checks._nameservers(rep, "example.test")

    assert called == [], (
        f"CH TXT probe must be suppressed under env-unsafe; got "
        f"probes to {called!r}"
    )


def test_asn_verified_high_confidence_skips_probe(monkeypatch):
    """When the ASN is already in the pinned table, confidence is
    already high — no need to probe. Guards against wasteful extra
    network traffic on the happy path."""
    called = []

    def _tracked_probe(ip):
        called.append(ip)
        return {"ok": False}

    _install_stubs(monkeypatch,
                   ip_rdap_map={
                       "203.0.113.1": {"ok": True, "asn": 141383,
                                       "org": "VERGE CLOUD PRIVATE LIMITED"},
                       "203.0.113.2": {"ok": True, "asn": 141383,
                                       "org": "VERGE CLOUD PRIVATE LIMITED"},
                   },
                   id_server_by_ip={})
    monkeypatch.setattr(checks.dnsmod, "probe_ns_id_server", _tracked_probe)

    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = [f for f in rep.findings
               if f.label == "Nameserver topology"][0]
    assert finding.confidence == "high"
    assert called == [], (
        f"ASN-verified anycast must not incur a CH TXT probe; got "
        f"probes to {called!r}"
    )
