"""B21 — MX target sanity: IP literal, CNAME target, dangling, redundancy.

RFC 1035 §3.3.9 defines MX RDATA as `<preference> <hostname>` — a
`<domain-name>`, not an IP. RFC 2181 §10.3 forbids the hostname
from being a CNAME. A dangling target (hostname with no A / AAAA
and no CNAME) means the domain publishes MX but mail cannot be
delivered — the worst-of-both-worlds: senders will attempt
delivery and it will fail rather than being rejected up front.

Rule 1 preserved: null MX (`0 .`) exempts all of these — the domain
has explicitly declared "no mail", so target-side checks do not
apply. A domain with no MX at all likewise skips these (not a
mail domain to begin with).

Redundancy is a separate WARN: a single MX is valid, just fragile
— no failover if the sole target is down.
"""
from __future__ import annotations

import posture.checks as checks
from posture.core import Report


def _fake_query(table):
    """Per-(name, qtype) fake for `dnsmod.query`. `table[name][qtype]`
    holds the `{records, ttl?}` payload. Missing keys → empty
    records (caller sees "no record here")."""
    def _q(name, qtype, **kwargs):
        got = table.get(name, {}).get(qtype, {})
        return {"ok": True, "records": got.get("records", []),
                "ttl": got.get("ttl", 300)}
    return _q


def _run_records(table, monkeypatch):
    rep = Report(domain_input="example.com", domain="example.com",
                 punycode="example.com")
    monkeypatch.setattr(checks.dnsmod, "query", _fake_query(table))
    checks._records(rep, "example.com")
    return rep


def _labels(rep):
    return {f.label: f for f in rep.findings if f.section == "Core records"}


def _apex(mx_records):
    """Boilerplate apex block used by every case — one A record and
    empty AAAA/CAA/CNAME so we don't have to repeat it."""
    return {
        "A": {"records": ["1.1.1.1"]},
        "AAAA": {"records": []},
        "MX": {"records": mx_records},
        "CAA": {"records": []},
        "CNAME": {"records": []},
    }


# --------------------------------------------------------------------- IP literal target

def test_mx_target_ip_literal_is_fail(monkeypatch):
    """`10 1.2.3.4` violates RFC 1035 §3.3.9 — MX RDATA target is a
    hostname, not an IP. RFC-compliant mail servers reject this."""
    rep = _run_records(
        {"example.com": _apex(["10 1.2.3.4"])},
        monkeypatch,
    )
    f = _labels(rep)["MX target"]
    assert f.status == "FAIL"
    assert "1.2.3.4" in f.detail


# --------------------------------------------------------------------- CNAME target

def test_mx_target_that_is_a_cname_is_fail(monkeypatch):
    """RFC 2181 §10.3: no CNAME may be used as an MX target. If the
    target hostname has a CNAME record, resolvers are permitted to
    reject the mail path and delivery is not guaranteed."""
    rep = _run_records(
        {
            "example.com": _apex(["10 mail.example.com."]),
            "mail.example.com": {
                "CNAME": {"records": ["actual-mail.example.net."]},
                "A": {"records": []},
                "AAAA": {"records": []},
            },
        },
        monkeypatch,
    )
    f = _labels(rep)["MX target"]
    assert f.status == "FAIL"
    assert "mail.example.com" in f.detail


# --------------------------------------------------------------------- dangling target

def test_mx_target_that_does_not_resolve_is_fail(monkeypatch):
    """A dangling MX target (no A/AAAA/CNAME) is worse than no MX
    at all — senders attempt delivery and it fails. FAIL, not WARN."""
    rep = _run_records(
        {"example.com": _apex(["10 nowhere.example.com."])},
        # nowhere.example.com absent from table → empty records
        monkeypatch,
    )
    f = _labels(rep)["MX target"]
    assert f.status == "FAIL"
    assert "nowhere.example.com" in f.detail


def test_mx_target_partial_dangling_only_flags_the_bad_one(monkeypatch):
    """If a zone publishes two MX and only one is dangling, the FAIL
    detail must name only the offending target — otherwise ops can't
    tell which record to fix."""
    rep = _run_records(
        {
            "example.com": _apex(["10 good.example.com.",
                                  "20 bad.example.com."]),
            "good.example.com": {"A": {"records": ["1.2.3.4"]}},
            # bad.example.com absent — dangling
        },
        monkeypatch,
    )
    f = _labels(rep)["MX target"]
    assert f.status == "FAIL"
    assert "bad.example.com" in f.detail
    assert "good.example.com" not in f.detail


# --------------------------------------------------------------------- clean case

def test_mx_target_that_resolves_produces_no_target_finding(monkeypatch):
    """Well-formed MX with a target that has A records must NOT trip
    the target FAIL — sanity backstop, otherwise every mail-serving
    domain would false-positive."""
    rep = _run_records(
        {
            "example.com": _apex(["10 mail.example.com.",
                                  "20 mail2.example.com."]),
            "mail.example.com": {"A": {"records": ["1.2.3.4"]}},
            "mail2.example.com": {"A": {"records": ["1.2.3.5"]}},
        },
        monkeypatch,
    )
    findings = _labels(rep)
    assert "MX target" not in findings, (
        f"clean MX should not emit MX target finding; got {list(findings)}"
    )


# --------------------------------------------------------------------- redundancy

def test_single_mx_produces_redundancy_warn(monkeypatch):
    """A single MX is valid but has no failover. WARN — not FAIL,
    because a single-MX zone can still deliver mail."""
    rep = _run_records(
        {
            "example.com": _apex(["10 mail.example.com."]),
            "mail.example.com": {"A": {"records": ["1.2.3.4"]}},
        },
        monkeypatch,
    )
    f = _labels(rep)["MX redundancy"]
    assert f.status == "WARN"


def test_two_mx_produces_no_redundancy_warn(monkeypatch):
    """Two MX with distinct targets = redundant. No WARN."""
    rep = _run_records(
        {
            "example.com": _apex(["10 mail1.example.com.",
                                  "20 mail2.example.com."]),
            "mail1.example.com": {"A": {"records": ["1.2.3.4"]}},
            "mail2.example.com": {"A": {"records": ["1.2.3.5"]}},
        },
        monkeypatch,
    )
    findings = _labels(rep)
    assert "MX redundancy" not in findings


# --------------------------------------------------------------------- rule 1 exemption

def test_null_mx_skips_all_target_and_redundancy_checks(monkeypatch):
    """Rule 1: null MX (0 .) declares "no mail"; the target-side and
    redundancy checks must not fire, otherwise a domain publishing
    the RFC-7505 opt-out grades FAIL for "dangling target `.`"."""
    rep = _run_records(
        {"example.com": _apex(["0 ."])},
        monkeypatch,
    )
    findings = _labels(rep)
    for absent in ("MX target", "MX redundancy"):
        assert absent not in findings, (
            f"{absent!r} must not appear when domain publishes null MX"
        )


def test_no_mx_skips_all_target_and_redundancy_checks(monkeypatch):
    """No MX at all → not a mail domain → target-side checks do not
    apply. Rule 1: absent ≠ broken."""
    rep = _run_records(
        {"example.com": _apex([])},
        monkeypatch,
    )
    findings = _labels(rep)
    for absent in ("MX target", "MX redundancy"):
        assert absent not in findings, (
            f"{absent!r} must not appear when domain has no MX"
        )
