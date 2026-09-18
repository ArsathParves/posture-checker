"""Regression tests for FP5 — a subdomain with no CAA record but a
parent zone that DOES publish CAA was reported as `CAA record: WARN
none — any public CA may issue certificates for this domain
(RFC 8659)`. That is misleading in two directions:

  1. RFC 8659 §3 defines how CAs check CAA: they query the FQDN, and
     if the response is empty, they climb toward the root one label
     at a time, honoring the first CAA set they find. So the parent's
     CAA IS effective for the child — "any CA may issue" is factually
     wrong when a parent zone constrains issuance.
  2. Emitting WARN on a domain whose issuance IS constrained (just
     inherited via tree-climb) collapses "not applicable / already
     covered" into "broken" — rule 1 violation on the hardening axis.

Fix contract:
  - `_records()` queries CAA at the target, then walks up parent
    labels until it finds a CAA set OR runs out of labels (stopping
    before the DNS root).
  - Target has CAA → PASS with the target's records (unchanged
    behavior; regression guard).
  - Target has no CAA, a parent does → PASS with a note naming which
    ancestor the policy came from (so an operator reading the report
    understands "you inherit this from example.com").
  - Nothing anywhere up the chain → WARN with the RFC-8659 text
    (still hardening — a domain with no CAA policy anywhere is
    genuinely under any-CA-may-issue).
  - The walk stops at ≥2-label parents; we don't probe the eTLD
    (`com`, `co.in`) — TLDs practically never publish CAA and adding
    a query per check is not worth the marginal correctness.
"""
from __future__ import annotations

from unittest.mock import patch

from posture.checks import _records
from posture.core import Report


def _make_report(domain: str) -> Report:
    return Report(domain_input=domain, domain=domain, punycode=domain)


def _caa_finding(rep: Report):
    return next((f for f in rep.findings if f.label == "CAA record"), None)


def _stub_query(answers: dict):
    """Build a fake `dnsmod.query` that returns `answers[(name, rdtype)]`
    on match, or a permissive empty-answer `{"ok": True, "records": []}`
    on miss (so unrelated queries like A/AAAA/MX don't crash the run)."""
    def fake(name, rdtype, nameservers=None):
        key = (name.lower(), rdtype)
        if key in answers:
            return answers[key]
        return {"ok": True, "records": [], "ttl": None}
    return patch("posture.checks.dnsmod.query", side_effect=fake)


def test_target_has_caa_pass_unchanged():
    """Regression guard: pre-FP5 behaviour on a domain that publishes
    its own CAA must be preserved — PASS with the target's records."""
    rep = _make_report("example.com")
    answers = {
        ("example.com", "CAA"): {
            "ok": True, "records": ['0 issue "letsencrypt.org"'], "ttl": 300},
    }
    with _stub_query(answers):
        _records(rep, "example.com")

    caa = _caa_finding(rep)
    assert caa is not None and caa.status == "PASS"
    assert "letsencrypt.org" in caa.detail


def test_subdomain_inherits_parent_caa_is_pass():
    """FP5: `www.example.com` has no CAA, but `example.com` does.
    Per RFC 8659 §3, CAs walk up and honor the parent's policy — the
    subdomain IS constrained. Reporting WARN was misleading. Must
    surface PASS with a note naming the ancestor that supplied the
    policy."""
    rep = _make_report("www.example.com")
    answers = {
        ("www.example.com", "CAA"): {"ok": True, "records": [], "ttl": None},
        ("example.com", "CAA"): {
            "ok": True, "records": ['0 issue "digicert.com"'], "ttl": 300},
    }
    with _stub_query(answers):
        _records(rep, "www.example.com")

    caa = _caa_finding(rep)
    assert caa is not None, "expected a CAA finding"
    assert caa.status == "PASS", (
        f"subdomain inheriting parent CAA must be PASS, got "
        f"{caa.status}: {caa.detail!r}"
    )
    assert "example.com" in caa.detail or "example.com" in (caa.why or ""), (
        f"finding must name the ancestor that supplied the policy. "
        f"Got detail={caa.detail!r} why={caa.why!r}"
    )
    assert "digicert.com" in caa.detail, (
        f"finding must include the inherited record content. "
        f"Got detail={caa.detail!r}"
    )


def test_no_caa_anywhere_still_warns():
    """Regression guard: a domain with no CAA at any level up the tree
    still deserves the RFC-8659 WARN. Fix must not silence the genuine
    'any CA may issue' case."""
    rep = _make_report("www.example.com")
    answers = {
        ("www.example.com", "CAA"): {"ok": True, "records": [], "ttl": None},
        ("example.com", "CAA"): {"ok": True, "records": [], "ttl": None},
    }
    with _stub_query(answers):
        _records(rep, "www.example.com")

    caa = _caa_finding(rep)
    assert caa is not None and caa.status == "WARN"
    assert "RFC 8659" in (caa.why or "")


def test_walkup_stops_at_etld():
    """The walk must stop before probing the eTLD (`com`) — TLDs
    practically never publish CAA and the extra query is not worth
    the correctness marginal. Verified by asserting no CAA query
    was issued for a bare-TLD label."""
    rep = _make_report("example.com")
    seen_names = []

    def fake(name, rdtype, nameservers=None):
        if rdtype == "CAA":
            seen_names.append(name.lower())
        return {"ok": True, "records": [], "ttl": None}

    with patch("posture.checks.dnsmod.query", side_effect=fake):
        _records(rep, "example.com")

    assert "com" not in seen_names, (
        f"walk-up must stop before probing the eTLD. Got CAA probes "
        f"for: {seen_names}"
    )


def test_walkup_finds_grandparent_caa():
    """Deep-subdomain case: `a.b.example.com` has no CAA, `b.example.com`
    has no CAA, but `example.com` does. The walk must reach the
    grandparent and treat its CAA as authoritative for the child."""
    rep = _make_report("a.b.example.com")
    answers = {
        ("a.b.example.com", "CAA"): {"ok": True, "records": [], "ttl": None},
        ("b.example.com", "CAA"): {"ok": True, "records": [], "ttl": None},
        ("example.com", "CAA"): {
            "ok": True, "records": ['0 issue "sectigo.com"'], "ttl": 300},
    }
    with _stub_query(answers):
        _records(rep, "a.b.example.com")

    caa = _caa_finding(rep)
    assert caa is not None and caa.status == "PASS", (
        f"deep subdomain must inherit grandparent CAA, got "
        f"status={caa.status if caa else None}"
    )
    assert "sectigo.com" in caa.detail
    assert "example.com" in caa.detail or "example.com" in (caa.why or "")
