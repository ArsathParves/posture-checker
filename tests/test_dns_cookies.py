"""B27 — DNS cookie support (RFC 7873).

RFC 7873 (May 2016) defines DNS Cookies: a lightweight EDNS0 option
where the client sends an 8-byte cookie, and the server echoes it back
alongside a 8-16 byte server cookie. On subsequent queries the client
replays the server cookie; the server can then distinguish established
peers from off-path spoofers.

DNS cookies are the cheapest defence against:
  - Off-path cache poisoning (transaction-ID guessing) — a spoofed
    response lacks a matching server cookie and is discarded.
  - Reflection / amplification (used-in-DDoS) — a resolver querying
    behind a spoofed source IP won't receive a valid server cookie
    on the first attempt, so subsequent probes are rate-limited
    without impacting legitimate clients.

Cookies are OPTIONAL per RFC 7873, so absence is a hardening gap, not
a correctness bug. But an authoritative NS refusing cookies leaves the
zone marginally more amplifiable, and modern BIND / Knot / PowerDNS
enable them by default — non-support is a signal of a stale server.

Rule 1 sanity:
  - Env self-test blocks direct DNS → UNKNOWN (rule 5).
  - All NSes echo a COOKIE OPT option → PASS (hardening).
  - Some NSes respond without COOKIE → WARN hardening=True (adoption
    gap on those specific NSes; not a correctness failure).
  - No NS supports COOKIE → WARN hardening=True.
  - Probe raised → UNKNOWN (never absent).
"""
from __future__ import annotations

import dns.edns
import dns.message

from posture import dnsmod, checks as c
from posture.core import Report


def _mk_response_with_cookie(server_cookie=b"\x11" * 16):
    """Synthesise a response that echoes a COOKIE OPT option — the
    shape a cookie-supporting NS returns."""
    resp = dns.message.QueryMessage()
    opt = dns.edns.GenericOption(
        dns.edns.OptionType.COOKIE,
        b"\x00" * 8 + server_cookie,  # client + server
    )
    resp.use_edns(0, options=[opt], payload=4096)
    return resp


def _mk_response_no_cookie():
    resp = dns.message.QueryMessage()
    resp.use_edns(0, options=[], payload=4096)
    return resp


def test_edns_cookie_all_ns_support(monkeypatch):
    """Every NS echoes a COOKIE option → all supported."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_response_with_cookie())
    ns_map = {
        "ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []},
        "ns2.example.com.": {"ipv4": ["192.0.2.2"], "ipv6": []},
    }
    result = dnsmod.edns_cookie_support("example.com", ns_map)
    assert result["ok"] is True
    assert result["all_supported"] is True
    assert set(result["supported"]) == {"ns1.example.com.", "ns2.example.com."}


def test_edns_cookie_partial(monkeypatch):
    """One NS responds with COOKIE, the other without. Both must be
    classified correctly (rule 1: absence per-NS is a real per-NS
    signal, distinct from probe failure)."""
    def _fake_udp(q, ip, **kw):
        if ip == "192.0.2.2":
            return _mk_response_no_cookie()
        return _mk_response_with_cookie()
    monkeypatch.setattr(dnsmod.dns.query, "udp", _fake_udp)
    ns_map = {
        "ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []},
        "ns2.example.com.": {"ipv4": ["192.0.2.2"], "ipv6": []},
    }
    result = dnsmod.edns_cookie_support("example.com", ns_map)
    assert result["ok"] is True
    assert result["all_supported"] is False
    assert result["supported"] == ["ns1.example.com."]
    assert result["unsupported"] == ["ns2.example.com."]


def test_edns_cookie_none_supported(monkeypatch):
    """Zero NS support cookies. Not a probe failure — the servers
    answered, they just didn't echo the option."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_response_no_cookie())
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    result = dnsmod.edns_cookie_support("example.com", ns_map)
    assert result["ok"] is True
    assert result["all_supported"] is False
    assert result["unsupported"] == ["ns1.example.com."]


def test_edns_cookie_probe_failure(monkeypatch):
    """UDP query raises → per-NS `probe_error`, not misclassified as
    'no cookie support' (rule 1)."""
    def _boom(*a, **kw):
        raise Exception("simulated failure")
    monkeypatch.setattr(dnsmod.dns.query, "udp", _boom)
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    result = dnsmod.edns_cookie_support("example.com", ns_map)
    # Every probe raised → the whole check is unretrievable.
    assert result["ok"] is False


def test_edns_cookie_skips_ns_with_no_ips(monkeypatch):
    """NS with no addresses → `skipped`, not `unsupported` — rule 1."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_response_with_cookie())
    ns_map = {
        "ns-no-ip.example.com.": {"ipv4": [], "ipv6": []},
        "ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []},
    }
    result = dnsmod.edns_cookie_support("example.com", ns_map)
    assert "ns-no-ip.example.com." in result["skipped"]
    assert result["supported"] == ["ns1.example.com."]


# --------------------------------------------------------------------- integration: _nameservers emission

_CLEAN_ENV = {
    "safe": True, "notes": [],
    "safe_for_per_ns_checks": True, "safe_for_axfr": True,
    "safe_for_direct_dns": True,
}


def _run_nameservers(monkeypatch, cookie_out):
    """Drive `_nameservers` with all other DNS sub-checks stubbed so
    only the cookie emission path exercises the finding."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": ns_map})
    monkeypatch.setattr(c.dnsmod, "parent_delegation",
                        lambda d: {"ok": False, "error": "stub"})
    monkeypatch.setattr(c.dnsmod, "probe_each_ns",
                        lambda d, m: {h: {"reachable": True,
                                          "authoritative": True,
                                          "serial": 1, "rtt_ms": 10}
                                      for h in m})
    monkeypatch.setattr(c.dnsmod, "tcp53_support",
                        lambda d, m: {"ok": True, "all_supported": True,
                                      "supported": list(m),
                                      "unsupported": [], "skipped": []})
    monkeypatch.setattr(c.dnsmod, "edns_cookie_support",
                        lambda d, m: cookie_out)
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = _CLEAN_ENV
    c._nameservers(rep, "example.com", skip_asn=True)
    return rep


def _findings(rep, label):
    return [f for f in rep.findings if f.label == label]


def test_all_cookie_support_is_pass(monkeypatch):
    """Load-bearing hardening signal: every NS supports DNS cookies."""
    rep = _run_nameservers(monkeypatch,
                           {"ok": True, "all_supported": True,
                            "supported": ["ns1.example.com."],
                            "unsupported": [], "skipped": []})
    findings = _findings(rep, "DNS cookie support")
    assert findings, (
        f"expected `DNS cookie support` finding; got labels: "
        f"{[f.label for f in rep.findings]}"
    )
    assert findings[0].status == "PASS"


def test_no_cookie_support_is_hardening_warn(monkeypatch):
    """DNS cookies are optional (RFC 7873) so lack of support is a
    hardening gap, not correctness. hardening=True keeps this out of
    the correctness grade — an old NS never adopting cookies must not
    tank a zone that otherwise resolves fine."""
    rep = _run_nameservers(monkeypatch,
                           {"ok": True, "all_supported": False,
                            "supported": [],
                            "unsupported": ["ns1.example.com."],
                            "skipped": []})
    findings = _findings(rep, "DNS cookie support")
    assert findings
    f = findings[0]
    assert f.status == "WARN"
    assert f.hardening is True, (
        "DNS cookies are optional per RFC 7873 — non-support is an "
        "adoption gap, not a correctness failure"
    )
    assert "7873" in f.detail or "RFC 7873" in f.detail


def test_partial_cookie_support_is_hardening_warn(monkeypatch):
    """A single NS without cookies is still a hardening gap on that NS
    — surface it so the operator sees which server is stale."""
    rep = _run_nameservers(monkeypatch,
                           {"ok": True, "all_supported": False,
                            "supported": ["ns1.example.com."],
                            "unsupported": ["ns2.example.com."],
                            "skipped": []})
    findings = _findings(rep, "DNS cookie support")
    assert findings
    f = findings[0]
    assert f.status == "WARN"
    assert f.hardening is True
    assert "ns2.example.com" in f.detail


def test_cookie_probe_failure_produces_unknown(monkeypatch):
    """Every probe raised → UNKNOWN, never fall through to 'no cookies
    supported' (rule 1)."""
    rep = _run_nameservers(monkeypatch,
                           {"ok": False, "error": "all_probes_failed"})
    findings = _findings(rep, "DNS cookie support")
    assert findings
    assert findings[0].status == "UNKNOWN"
