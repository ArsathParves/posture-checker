"""B28 — negative-answer correctness (RFC 2308 / 8020).

A well-configured zone returns NXDOMAIN when asked for a name that
does not exist. Two common misbehaviours:

  - NODATA (NOERROR + empty answer) instead of NXDOMAIN — indicates
    an empty non-terminal that the signer didn't collapse, or a
    misconfigured wildcard that catches the type but not the name.
    RFC 8020 §3 says a resolver treats these differently for
    downstream negative caching, so the wire signal genuinely matters.
  - Lie: NOERROR with an injected A record for random labels. This
    is what upstream ISPs used to do for "search assist"; on an
    authoritative NS it usually means a catch-all wildcard, but a
    catch-all wildcard covering nonexistent subdomain hierarchies can
    hide typos and aid subdomain abuse (already covered by the
    existing `Wildcard record` finding — B28 doesn't duplicate that).

B28 focuses on the RCODE distinction. The zone-file question of what
SOA `minimum` value governs negative caching is already covered by
the existing SOA `Minimum / negative TTL` finding — B28 doesn't
duplicate it.

Rule 1 sanity:
  - Random-label probe returned NXDOMAIN → PASS.
  - Random-label probe returned NOERROR + records → skipped (the
    wildcard finding is authoritative for that path).
  - Random-label probe returned NOERROR + no answer (NODATA on a
    name that manifestly should not exist) → WARN.
  - Probe raised / TIMEOUT / SERVFAIL → UNKNOWN (rule 1: never
    absent).
"""
from __future__ import annotations

import dns.message
import dns.rcode
import dns.rrset

from posture import dnsmod, checks as c
from posture.core import Report


def _mk_response(rcode=0, records=()):
    resp = dns.message.QueryMessage()
    resp.set_rcode(rcode)
    if records:
        resp.answer.append(dns.rrset.from_text_list(
            "abc.example.com.", 3600, "IN", "A", list(records)
        ))
    return resp


# --------------------------------------------------------------------- unit: dnsmod.negative_answer_probe

def test_negative_probe_detects_nxdomain(monkeypatch):
    """Load-bearing: a well-configured zone must return NXDOMAIN for
    random names. The probe reports rcode=3 and has_answer=False."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_response(rcode=3))
    result = dnsmod.negative_answer_probe("example.com")
    assert result["ok"] is True
    assert result["rcode_name"] == "NXDOMAIN"
    assert result["has_answer"] is False


def test_negative_probe_detects_nodata(monkeypatch):
    """A NOERROR + empty answer for a random label is NODATA — a subtle
    misconfiguration that resolvers cache differently than NXDOMAIN
    (RFC 8020). Must be distinguished from NXDOMAIN."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_response(rcode=0))
    result = dnsmod.negative_answer_probe("example.com")
    assert result["ok"] is True
    assert result["rcode_name"] == "NOERROR"
    assert result["has_answer"] is False


def test_negative_probe_detects_wildcard_answer(monkeypatch):
    """A NOERROR + answer for a random label is a wildcard or an
    injected lie. Existing `Wildcard record` finding handles the
    action side; B28 just surfaces the fact."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_response(rcode=0,
                                                     records=["192.0.2.1"]))
    result = dnsmod.negative_answer_probe("example.com")
    assert result["ok"] is True
    assert result["has_answer"] is True


def test_negative_probe_handles_query_failure(monkeypatch):
    """Rule 1: probe timeout must not fall through to 'no NXDOMAIN'."""
    def _boom(*a, **kw):
        raise Exception("simulated failure")
    monkeypatch.setattr(dnsmod.dns.query, "udp", _boom)
    result = dnsmod.negative_answer_probe("example.com")
    assert result["ok"] is False


# --------------------------------------------------------------------- integration: _soa emission

def _run_soa(monkeypatch, neg_out, wildcard_records=None):
    """Drive `_soa` with a stubbed `get_soa` and stubbed
    `negative_answer_probe`. `wildcard_records` controls what the
    existing wildcard check inside `_soa` sees (kept separate so B28
    tests don't collide with the wildcard finding)."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    monkeypatch.setattr(c.dnsmod, "get_soa",
                        lambda d: {"ok": True, "mname": "ns1.example.com.",
                                   "rname": "hostmaster.example.com.",
                                   "serial": 1, "refresh": 3600,
                                   "retry": 900, "expire": 604800,
                                   "minimum": 300})
    monkeypatch.setattr(c.dnsmod, "negative_answer_probe",
                        lambda d: neg_out)
    monkeypatch.setattr(c.dnsmod, "query",
                        lambda d, rd, **kw: {"ok": True,
                                             "records": wildcard_records or []})
    rep = Report(domain_input="example.com", domain="example.com")
    c._soa(rep, "example.com", ns_map)
    return rep


def _findings(rep, label):
    return [f for f in rep.findings if f.label == label]


def test_nxdomain_is_pass(monkeypatch):
    """Load-bearing: a zone that correctly returns NXDOMAIN for random
    names surfaces as PASS."""
    rep = _run_soa(monkeypatch,
                   {"ok": True, "rcode_name": "NXDOMAIN",
                    "has_answer": False})
    findings = _findings(rep, "Negative-answer correctness")
    assert findings, (
        f"expected `Negative-answer correctness` finding; got labels: "
        f"{[f.label for f in rep.findings]}"
    )
    assert findings[0].status == "PASS"


def test_nodata_is_warn(monkeypatch):
    """NODATA on a random label is broken behaviour: the zone
    signalled 'the name exists but has no A record' for a name that
    should not exist at all. Real correctness signal — resolvers
    cache NODATA differently than NXDOMAIN."""
    rep = _run_soa(monkeypatch,
                   {"ok": True, "rcode_name": "NOERROR",
                    "has_answer": False})
    findings = _findings(rep, "Negative-answer correctness")
    assert findings
    f = findings[0]
    assert f.status == "WARN"
    assert f.hardening is False, (
        "NODATA vs NXDOMAIN divergence is a real correctness signal, "
        "not a hardening adoption gap"
    )
    assert "NODATA" in f.detail or "NOERROR" in f.detail


def test_wildcard_answer_no_separate_finding(monkeypatch):
    """When the random label returns an A record, the existing
    `Wildcard record` WARN is authoritative — B28 must not
    double-count by emitting its own row. Doing so would clutter the
    finding surface with two nearly-identical WARNs on the same
    underlying signal."""
    rep = _run_soa(monkeypatch,
                   {"ok": True, "rcode_name": "NOERROR",
                    "has_answer": True},
                   wildcard_records=["192.0.2.99"])
    b28 = _findings(rep, "Negative-answer correctness")
    wc = _findings(rep, "Wildcard record")
    assert not b28, (
        f"B28 must not emit when the wildcard finding covers this "
        f"path; got: {[(f.status, f.detail) for f in b28]}"
    )
    assert wc, "wildcard finding must still fire"


def test_probe_failure_is_unknown(monkeypatch):
    """Rule 1: probe timeout / SERVFAIL → UNKNOWN, never fall through
    to 'no NXDOMAIN observed' (which would look like a WARN)."""
    rep = _run_soa(monkeypatch,
                   {"ok": False, "error": "timeout"})
    findings = _findings(rep, "Negative-answer correctness")
    assert findings
    assert findings[0].status == "UNKNOWN"
