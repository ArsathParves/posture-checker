"""Regression tests for G2 — HARDENING_ABSENCE was a fixed label set
defined in `checks.grade`. Any new hardening check (e.g. "DNS COOKIE
support", "QNAME minimisation upstream", "TLS 1.3 on responsive
resolvers") would be silently classified as *correctness* unless the
author remembered to update the global set. Nothing in the check-emit
API telegraphed that the classification even existed — the emit-site
author has no reason to look at `grade()`.

Fix: hardening classification lives on the Finding itself. The emit
site knows whether the finding represents an optional-hardening
feature or a real correctness signal, so it declares that with
`hardening=True` when calling `Report.add()`. `grade()` reads
`f.hardening` directly; the global set is gone.

Preserved semantics from the old label-based logic:
  - hardening PASS: counts in BOTH correctness AND hardening buckets
    (adopting an optional feature is credit toward posture correctness
    too, not just hardening).
  - hardening WARN/FAIL: counts in the hardening bucket ONLY —
    non-adoption of an optional feature must never drag correctness.
  - non-hardening findings: counted only in correctness, as before.

DNSSEC is the state-conditional case: `state=not_configured` (or
`unknown`) and `state=validating` are hardening; `state=broken` and
`state=incomplete` are real misconfigurations and must count in
correctness. The emit site (`_dnssec`) makes that decision — no
special-casing inside `grade()`.
"""
from __future__ import annotations

from posture.checks import grade
from posture.core import Finding, Report


# ---------------------------- data-class contract ------------------------

def test_finding_exposes_hardening_field_default_false():
    """A finding emitted without the hardening flag must default to False —
    the attribute must be part of the dataclass, not stashed elsewhere.
    Otherwise callers that construct Finding directly (tests, downstream
    tooling) would get an AttributeError from grade()."""
    f = Finding("Sec", "Some check", "PASS")
    assert hasattr(f, "hardening"), "Finding must expose a `hardening` attribute"
    assert f.hardening is False, "default hardening flag must be False"


def test_report_add_accepts_hardening_kwarg():
    """The check-emit API is `Report.add(...)`. Emit sites must be able
    to declare hardening at emit time; a decorator or post-hoc mutation
    would separate the classification from the code that knows the
    answer."""
    rep = Report(domain_input="x", domain="x")
    rep.add("Sec", "New hardening check", "FAIL",
            "not enabled", "why", hardening=True)
    assert rep.findings[-1].hardening is True


# ---------------------------- classification tests -----------------------

def test_novel_hardening_label_is_isolated_from_correctness():
    """The concrete G2 regression: a hardening check with a label that
    was NEVER in the old `HARDENING_ABSENCE` set (imagine "DNS COOKIE
    support") must still be routed to the hardening bucket when its
    emit site declares `hardening=True`. Under the old model this would
    silently drop into correctness and produce a false FAIL grade."""
    rep = Report(domain_input="x", domain="x")
    rep.findings = [
        Finding("Nameservers", "Nameserver count", "PASS", "4 NS"),
        Finding("Nameservers", "Nameserver reachability", "PASS", "4/4"),
        # Novel hardening label — not in any global set.
        Finding("Security posture", "DNS COOKIE support", "FAIL",
                "no COOKIE option observed", hardening=True),
    ]
    g = grade(rep)
    assert g["correctness_grade"] == "A", (
        f"a novel hardening FAIL must not drag correctness below A "
        f"(got {g['correctness_grade']!r}) — G2 refactor regression"
    )
    assert g["hardening_grade"] in {"D", "F"}, (
        f"the novel hardening FAIL must land in the hardening bucket "
        f"and drop that letter (got {g['hardening_grade']!r})"
    )


def test_non_hardening_finding_with_legacy_label_still_correctness():
    """The attribute wins over any historical label heuristic. A
    finding labelled "CAA record" that is emitted with `hardening=False`
    must be counted as correctness — the emit site is the authority on
    classification. This locks in the "no more global set" contract."""
    rep = Report(domain_input="x", domain="x")
    rep.findings = [
        Finding("Nameservers", "Nameserver count", "PASS", "4 NS"),
        # Intentionally emitted as non-hardening even though the label
        # was in the old HARDENING_ABSENCE set. Attribute must win.
        Finding("Core records", "CAA record", "FAIL",
                "spurious FAIL", hardening=False),
    ]
    g = grade(rep)
    assert g["correctness_grade"] in {"C", "D", "F"}, (
        f"CAA FAIL emitted with hardening=False MUST hit correctness "
        f"(the attribute is authoritative); got {g['correctness_grade']!r}"
    )
    assert g["hardening_grade"] == "—", (
        f"with no hardening=True findings, hardening grade must be "
        f"'—', not derived from the label; got {g['hardening_grade']!r}"
    )


# ---------------------------- DNSSEC state routing -----------------------

def test_dnssec_not_configured_routes_to_hardening():
    """Regression guard for the state-conditional emit: state=not_configured
    must set hardening=True so DNSSEC absence does not tank correctness.
    (This is the mechanism google.com relies on — see G3 test.)"""
    from posture import checks
    rep = Report(domain_input="google.com", domain="google.com")
    rep.data["ns_map"] = {}

    # Fake the dnsmod call: return an unsigned zone shape.
    orig = checks.dnsmod.dnssec_status
    checks.dnsmod.dnssec_status = lambda d: {
        "state": "not_configured", "ds": False, "dnskey": False,
        "self_signed": None, "ds_matches_dnskey": None,
        "ad_authenticated": None, "algorithms": [], "notes": [],
    }
    try:
        checks._dnssec(rep, "google.com")
    finally:
        checks.dnsmod.dnssec_status = orig

    dnssec = [f for f in rep.findings if f.label == "DNSSEC status"]
    assert dnssec, "expected a DNSSEC status finding"
    assert dnssec[0].hardening is True, (
        "state=not_configured must emit with hardening=True so absence "
        "does not penalise correctness — the whole google.com invariant "
        "depends on this."
    )


def test_dnssec_broken_stays_in_correctness():
    """The complement: state=broken is a real misconfiguration —
    resolvers will SERVFAIL. It MUST hit correctness. Emitting it as
    hardening would let broken zones (e.g. dnssec-failed.org) grade A."""
    from posture import checks
    rep = Report(domain_input="dnssec-failed.org", domain="dnssec-failed.org")
    rep.data["ns_map"] = {}

    orig_dnssec = checks.dnsmod.dnssec_status
    orig_nsec = checks.dnsmod.nsec_type
    orig_cds = checks.dnsmod.cds_cdnskey_status
    checks.dnsmod.dnssec_status = lambda d: {
        "state": "broken", "ds": True, "dnskey": False,
        "self_signed": None, "ds_matches_dnskey": False,
        "ad_authenticated": False, "algorithms": [], "notes": [],
    }
    checks.dnsmod.nsec_type = lambda d: {"ok": False, "error": "stub"}
    checks.dnsmod.cds_cdnskey_status = lambda d: {"ok": False, "error": "stub"}
    try:
        checks._dnssec(rep, "dnssec-failed.org")
    finally:
        checks.dnsmod.dnssec_status = orig_dnssec
        checks.dnsmod.nsec_type = orig_nsec
        checks.dnsmod.cds_cdnskey_status = orig_cds

    dnssec = [f for f in rep.findings if f.label == "DNSSEC status"]
    assert dnssec, "expected a DNSSEC status finding"
    assert dnssec[0].hardening is False, (
        "state=broken is a real misconfiguration and MUST count in "
        "correctness — routing it to hardening would allow "
        "dnssec-failed.org to grade A."
    )


# ---------------------------- google.com still A -------------------------

def test_google_shape_still_grades_A_after_refactor():
    """Belt-and-braces cross-link to G3: the whole point of G2 is to
    refactor without regressing google.com. Duplicated here so that if
    G2 breaks, the failure names G2 explicitly rather than blaming G3."""
    rep = Report(domain_input="google.com", domain="google.com")
    rep.findings = [
        Finding("Nameservers", "Nameserver count", "PASS", "4"),
        Finding("Nameservers", "Nameserver reachability", "PASS", "4/4"),
        Finding("Nameservers", "IPv6 (AAAA) on nameservers", "PASS",
                "4/4", hardening=True),
        Finding("Core records", "AAAA record (IPv6)", "PASS",
                "1", hardening=True),
        Finding("Core records", "CAA record", "PASS", "present", hardening=True),
        Finding("DNSSEC", "DNSSEC status", "FAIL", "unsigned", hardening=True),
        Finding("Email authentication", "SPF", "PASS", "-all"),
        Finding("Email authentication", "DMARC policy", "PASS", "p=reject"),
        Finding("Email authentication", "DMARC reporting", "PASS",
                "rua present", hardening=True),
        Finding("Security posture", "MTA-STS", "PASS",
                "enforce", hardening=True),
        Finding("Security posture", "TLS-RPT", "PASS", "present", hardening=True),
    ]
    rep.data["dnssec"] = {"state": "not_configured"}

    g = grade(rep)
    assert g["overall"] == "A", (
        f"G2 refactor must not regress google.com A-overall guardrail; "
        f"got overall={g['overall']!r}, correctness={g['correctness_grade']!r}, "
        f"hardening={g['hardening_grade']!r}"
    )
