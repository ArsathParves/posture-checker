"""B22 — bogon / private-space sanity for apex A / AAAA records.

If the authoritative apex A or AAAA records for a public-facing
domain resolve to RFC 1918 (10/8, 172.16/12, 192.168/16), RFC 6598
CGN space (100.64/10), loopback, link-local, documentation ranges
(192.0.2/24, 198.51.100/24, 203.0.113/24), multicast, IPv6 ULA
(fc00::/7), IPv6 link-local (fe80::/10) or the IPv6 documentation
range (2001:db8::/32) — that's almost always a misconfiguration.

Concrete failure modes this catches:

  * Internal staging leaked to public DNS by a copy-paste in a
    zone file (`bank.internal.acme.com` accidentally published on
    `bank.acme.com`).
  * `A 127.0.0.1` left over from a `/etc/hosts` -> DNS refactor.
  * IPv6 ULA (`fdxx::…`) emitted by an IPAM tool that assumed the
    zone was private.
  * Documentation-range addresses copy-pasted from an RFC example
    into a real zone (yes, this happens).

Nothing in the current tool flags any of these. `_records` emits
`A record PASS` on any well-formed A response, regardless of what
the address actually points at.

Rule 1 is preserved: bogon detection is a *content* check on
records that WERE retrieved. If A / AAAA was unretrievable the
existing code path already reports UNKNOWN (the section-level
Unretrievable propagation), and the bogon check is skipped.
"""
from __future__ import annotations

import posture.checks as checks
from posture.core import Report


def _fake_query(records_by_qtype):
    """Return a stub for `dnsmod.query(name, qtype)` that reads the
    (records, ttl) shape from the provided per-qtype table."""
    def _q(name, qtype, **kwargs):
        got = records_by_qtype.get(qtype, {})
        if not got:
            return {"ok": True, "records": [], "ttl": None}
        return {"ok": True, "records": got.get("records", []),
                "ttl": got.get("ttl", 300)}
    return _q


def _run_records(a_records, aaaa_records, monkeypatch):
    """Drive `_records` with fake A/AAAA payloads and empty MX/CAA/
    CNAME so we don't have to fake unrelated sections."""
    rep = Report(domain_input="example.com", domain="example.com",
                 punycode="example.com")
    monkeypatch.setattr(checks.dnsmod, "query",
                        _fake_query({
                            "A": {"records": a_records, "ttl": 300},
                            "AAAA": {"records": aaaa_records, "ttl": 300},
                            "MX": {"records": []},
                            "CAA": {"records": []},
                            "CNAME": {"records": []},
                        }))
    checks._records(rep, "example.com")
    return rep


def _labels(rep):
    return {f.label: f for f in rep.findings if f.section == "Core records"}


# --------------------------------------------------------------------- IPv4

def test_rfc1918_addresses_surface_as_bogon_fail(monkeypatch):
    """10.0.0.1 in an apex A record is almost certainly an internal
    address leaked to public DNS. FAIL, not WARN — a public client
    reaching this cannot route the packet."""
    rep = _run_records(["10.0.0.1"], [], monkeypatch)
    findings = _labels(rep)
    assert "A record bogon check" in findings, (
        f"RFC 1918 address must surface as bogon finding; "
        f"got labels {list(findings)}"
    )
    f = findings["A record bogon check"]
    assert f.status == "FAIL"
    assert "10.0.0.1" in f.detail


def test_loopback_address_is_bogon_fail(monkeypatch):
    """127.0.0.1 is the canonical `/etc/hosts` leftover — same
    treatment as RFC 1918."""
    rep = _run_records(["127.0.0.1"], [], monkeypatch)
    f = _labels(rep)["A record bogon check"]
    assert f.status == "FAIL"


def test_documentation_range_is_bogon_fail(monkeypatch):
    """192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 are RFC 5737
    documentation-only. If they appear in a real zone someone
    copy-pasted from an example."""
    for bad in ("192.0.2.5", "198.51.100.5", "203.0.113.5"):
        rep = _run_records([bad], [], monkeypatch)
        f = _labels(rep)["A record bogon check"]
        assert f.status == "FAIL", f"{bad} must be flagged as bogon"


def test_public_ipv4_produces_no_bogon_finding(monkeypatch):
    """Sanity: a real public IP (1.1.1.1) MUST NOT trip the
    bogon check — otherwise every domain would false-positive."""
    rep = _run_records(["1.1.1.1"], [], monkeypatch)
    findings = _labels(rep)
    assert "A record bogon check" not in findings


def test_mixed_public_and_private_only_flags_private(monkeypatch):
    """If a zone publishes both 1.1.1.1 and 10.0.0.1, the finding
    detail must name only the offending address — otherwise ops
    can't tell what to remove."""
    rep = _run_records(["1.1.1.1", "10.0.0.1"], [], monkeypatch)
    f = _labels(rep)["A record bogon check"]
    assert f.status == "FAIL"
    assert "10.0.0.1" in f.detail
    assert "1.1.1.1" not in f.detail


# --------------------------------------------------------------------- IPv6

def test_ipv6_ula_is_bogon_fail(monkeypatch):
    """fc00::/7 is RFC 4193 Unique Local — the IPv6 equivalent of
    RFC 1918. Public DNS should never point at one."""
    rep = _run_records([], ["fd12::1"], monkeypatch)
    findings = _labels(rep)
    assert "AAAA record bogon check" in findings
    assert findings["AAAA record bogon check"].status == "FAIL"


def test_ipv6_link_local_is_bogon_fail(monkeypatch):
    """fe80::/10 is link-local — same treatment as loopback."""
    rep = _run_records([], ["fe80::1"], monkeypatch)
    assert _labels(rep)["AAAA record bogon check"].status == "FAIL"


def test_ipv6_documentation_range_is_bogon_fail(monkeypatch):
    """2001:db8::/32 is RFC 3849 documentation — same class as
    192.0.2.0/24 for IPv4."""
    rep = _run_records([], ["2001:db8::1"], monkeypatch)
    assert _labels(rep)["AAAA record bogon check"].status == "FAIL"


def test_public_ipv6_produces_no_bogon_finding(monkeypatch):
    """Sanity: a real public IPv6 (2606:4700::1111 — Cloudflare)
    MUST NOT trip the bogon check."""
    rep = _run_records([], ["2606:4700::1111"], monkeypatch)
    findings = _labels(rep)
    assert "AAAA record bogon check" not in findings


# --------------------------------------------------------------------- rule 1

def test_no_records_produces_no_bogon_finding(monkeypatch):
    """If no A/AAAA records exist, the bogon check must not fire.
    Rule 1: absent ≠ broken. A domain with no A record is not
    'bogon' — it's just IPv4-less."""
    rep = _run_records([], [], monkeypatch)
    findings = _labels(rep)
    assert "A record bogon check" not in findings
    assert "AAAA record bogon check" not in findings
