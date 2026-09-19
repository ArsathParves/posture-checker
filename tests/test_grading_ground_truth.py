"""T2 — Ground-truth grading fixtures for the CLAUDE.md test domains.

The audit item asks for fixture reports covering the four ground-truth
domains listed in `CLAUDE.md`. `google.com` is already covered by
`test_grading_google_unsigned.py` (the DNSSEC-absent-by-choice case).
This file layers on the other three:

  - `cloudflare.com` — all-PASS baseline. DNSSEC fully validating;
    anycast operator; SPF present. Must grade A overall, A correctness,
    A hardening.

  - `dnssec-failed.org` — DNSSEC broken (DS present, DNSKEY absent,
    resolver SERVFAILs). Must produce a correctness FAIL — this is a
    genuine misconfiguration, NOT an optional-feature non-adoption. The
    hardening router in `checks.grade` must NOT catch it via the
    "state=not_configured" path; a broken chain is state=broken and
    belongs to correctness.

  - `vergecloud.com` — the tool's own home domain. Two NS ranges, one
    ASN (AS141383). Must report 1 operator (C4 fix pinned by
    `test_anycast_classifier.py`) — this test confirms the downstream
    grading treats 1-operator anycast as PASS and grades A overall.
    The audit's biggest concern is that vergecloud.com would fail a
    check the tool is meant to authoritatively answer; this test pins
    the successful classification through to the grade output.

The tests use synthetic `Report` fixtures — they do NOT hit the network.
They pin the *grade function's* handling of realistic report shapes.
The parallel `network`-marked suite (see CI) hits the live domains.

Design constraints:
  - Every finding's `hardening` flag mirrors the emit site in
    `posture/checks.py` (CAA/AAAA/MTA-STS/TLS-RPT/DNSSEC-when-absent
    are hardening; SPF/DMARC-policy/AXFR/parent-delegation are
    correctness). This keeps the fixtures a faithful stand-in for
    what `run()` would produce.
  - The DNSSEC state key (`rep.data["dnssec"]["state"]`) is set on each
    fixture with the value the corresponding emit site would set:
    "signed" (cloudflare, vergecloud), "broken" (dnssec-failed),
    "not_configured" (google — see the other file).
"""
from __future__ import annotations

from posture.checks import grade
from posture.core import Finding, Report


# --------------------------------------------------------------------- helpers

def _pass(section, label, hardening=False):
    return Finding(section, label, "PASS", detail="ok", hardening=hardening)


def _fail(section, label, detail, hardening=False):
    return Finding(section, label, "FAIL", detail=detail, hardening=hardening)


# --------------------------------------------------------------------- cloudflare

def _cloudflare_shaped_report() -> Report:
    """cloudflare.com: fully-adopted posture. Signed zone, dual-stack NS,
    CAA, MTA-STS, TLS-RPT, DMARC with rua, SPF hard-fail. Every scored
    finding is PASS. Guards A-band assumptions from an all-PASS input."""
    rep = Report(domain_input="cloudflare.com", domain="cloudflare.com",
                 punycode="cloudflare.com")
    rep.findings = [
        _pass("Registration & delegation", "Domain resolves"),
        _pass("Registration & delegation", "Registration record found"),
        _pass("Registration & delegation", "Registrar lock"),
        _pass("Registration & delegation", "Expiry"),
        _pass("Registration & delegation", "Parent delegation vs zone NS"),

        _pass("Nameserver posture", "Nameserver count"),
        _pass("Nameserver posture", "Nameserver reachability"),
        _pass("Nameserver posture", "Network diversity"),  # 1 anycast operator
        _pass("Nameserver posture", "IPv6 (AAAA) on nameservers", hardening=True),

        _pass("SOA & zone hygiene", "SOA present"),
        _pass("SOA & zone hygiene", "SOA MNAME reachable"),

        _pass("Core records", "A record (apex)"),
        _pass("Core records", "AAAA record (IPv6)", hardening=True),
        _pass("Core records", "CNAME at apex"),
        _pass("Core records", "CAA record", hardening=True),
        _pass("Core records", "MX record"),

        # DNSSEC PASS is scored as correctness credit AND hardening credit.
        _pass("DNSSEC", "DNSSEC status", hardening=True),

        _pass("Email authentication", "SPF"),
        _pass("Email authentication", "SPF 'all' qualifier"),
        _pass("Email authentication", "SPF DNS lookup count"),
        _pass("Email authentication", "DKIM"),
        _pass("Email authentication", "DMARC policy"),
        _pass("Email authentication", "DMARC reporting", hardening=True),

        _pass("Security posture", "MTA-STS", hardening=True),
        _pass("Security posture", "TLS-RPT", hardening=True),
        _pass("Security posture", "AXFR (zone transfer)"),
        _pass("Security posture", "Open recursive resolver"),
    ]
    rep.data["dnssec"] = {"state": "signed"}
    return rep


def test_cloudflare_all_pass_is_A_overall():
    g = grade(_cloudflare_shaped_report())
    assert g["overall"] == "A", (
        f"all-PASS report must grade A overall; got {g['overall']!r}. "
        f"correctness={g.get('correctness_grade')!r}, "
        f"hardening={g.get('hardening_grade')!r}"
    )


def test_cloudflare_correctness_and_hardening_both_A():
    g = grade(_cloudflare_shaped_report())
    assert g["correctness_grade"] == "A"
    assert g["hardening_grade"] == "A"


def test_cloudflare_no_provisional_flag():
    g = grade(_cloudflare_shaped_report())
    assert g["provisional"] is False


def test_cloudflare_no_hardening_gaps():
    """Every hardening-eligible finding PASSes → the caption list of
    "un-adopted features" must be empty. A non-empty list here would
    mean the hardening bucket is mis-attributing PASS as absence."""
    g = grade(_cloudflare_shaped_report())
    assert g["hardening_gaps"] == [], (
        f"all-PASS report must expose no hardening gaps; "
        f"got {g['hardening_gaps']!r}"
    )


# --------------------------------------------------------------------- dnssec-failed.org

def _dnssec_failed_shaped_report() -> Report:
    """dnssec-failed.org: signed but broken chain. DS in parent points to
    a DNSKEY that no longer answers → resolvers SERVFAIL on the zone.
    Everything else in this fixture is PASS-shaped so the DNSSEC FAIL
    is the sole driver of the grade drop — that isolates the "broken
    DNSSEC drags CORRECTNESS, not just hardening" invariant.

    dnssec-failed.org is a test domain; its non-DNSSEC posture is not a
    contract this repo owns. We shape the fixture around what the
    invariant needs: a single correctness FAIL on DNSSEC, everything
    else PASS. If the operator adds real misconfigurations later, this
    fixture is still the right shape for the invariant."""
    rep = Report(domain_input="dnssec-failed.org",
                 domain="dnssec-failed.org",
                 punycode="dnssec-failed.org")
    rep.findings = [
        _pass("Registration & delegation", "Domain resolves"),
        _pass("Registration & delegation", "Registration record found"),
        _pass("Registration & delegation", "Registrar lock"),
        _pass("Registration & delegation", "Expiry"),
        _pass("Registration & delegation", "Parent delegation vs zone NS"),

        _pass("Nameserver posture", "Nameserver count"),
        _pass("Nameserver posture", "Nameserver reachability"),
        _pass("Nameserver posture", "Network diversity"),

        _pass("SOA & zone hygiene", "SOA present"),
        _pass("SOA & zone hygiene", "SOA MNAME reachable"),

        _pass("Core records", "A record (apex)"),
        _pass("Core records", "CNAME at apex"),

        # THE bug being pinned. state=broken → emit site does NOT set
        # hardening=True (it's a misconfiguration, not non-adoption).
        # grade() must route this into the correctness bucket.
        _fail("DNSSEC", "DNSSEC status",
              "DS in parent but DNSKEY absent — chain broken (SERVFAIL)",
              hardening=False),
    ]
    # Mirror the emit site: broken chain writes state=broken. The
    # hardening router keys off state=not_configured only.
    rep.data["dnssec"] = {"state": "broken"}
    return rep


def test_dnssec_failed_correctness_fails():
    """A broken DNSSEC chain is a real misconfiguration and MUST drag
    correctness. If this passes as correctness A, the hardening router
    has swallowed a genuine failure."""
    g = grade(_dnssec_failed_shaped_report())
    # correctness has 1 FAIL out of ~13 correctness findings, pct high but
    # has_fail=True. Per `_band`: has_fail with pct<0.75 → D floor;
    # otherwise the FAIL is scored but doesn't trip the floor. Either way
    # it must NOT be A.
    assert g["correctness_grade"] != "A", (
        f"broken DNSSEC leaked past correctness — should never grade A. "
        f"correctness={g['correctness_grade']!r}, "
        f"hardening={g['hardening_grade']!r}, overall={g['overall']!r}"
    )


def test_dnssec_failed_overall_reflects_correctness_fail():
    """Overall = 0.8*correctness + 0.2*hardening. A correctness sub-A
    grade must pull overall below A. A domain with broken DNSSEC
    grading A overall would be the same false-negative failure mode
    google.com had — but in the opposite direction."""
    g = grade(_dnssec_failed_shaped_report())
    assert g["overall"] != "A", (
        f"broken-DNSSEC domain graded A overall — the FAIL is being "
        f"silently absorbed. Got: {g}"
    )


def test_dnssec_failed_dnssec_status_in_unknown_in_or_correctness():
    """The DNSSEC section grade itself must reflect the FAIL. This
    catches a class of bugs where a section is scored PASS on the
    balance of findings but a lone FAIL in it should still make
    that section band D or below."""
    g = grade(_dnssec_failed_shaped_report())
    dnssec_band, _pct = g["sections"]["DNSSEC"]
    assert dnssec_band in {"D", "F"}, (
        f"DNSSEC section must land in the has_fail-driven D/F band; "
        f"got {dnssec_band!r}. Section-level scoring must honour "
        f"has_fail even when it's the only finding in the section."
    )


# --------------------------------------------------------------------- vergecloud

def _vergecloud_shaped_report() -> Report:
    """vergecloud.com: 1 anycast operator (AS141383) with two NS ranges,
    signed zone, adopted hardening features. This fixture pins the
    grade-side of C4: the operator classifier fix flows through to a
    PASS on "Network diversity" — this test asserts the grade
    downstream is A, not the false single-point-of-failure D.

    The audit called this the tool's biggest correctness embarrassment
    (vergecloud.com failing a check the tool authoritatively answers).
    Even after the anycast fix, a grade-model regression could
    silently reintroduce the D — hence this end-of-pipe pin."""
    rep = Report(domain_input="vergecloud.com", domain="vergecloud.com",
                 punycode="vergecloud.com")
    rep.findings = [
        _pass("Registration & delegation", "Domain resolves"),
        _pass("Registration & delegation", "Registration record found"),
        _pass("Registration & delegation", "Registrar lock"),
        _pass("Registration & delegation", "Expiry"),
        _pass("Registration & delegation", "Parent delegation vs zone NS"),

        _pass("Nameserver posture", "Nameserver count"),
        _pass("Nameserver posture", "Nameserver reachability"),
        # The bug this whole file most cares about: "Network diversity"
        # must be PASS despite 2 NS-IP ranges, because ASN classifies
        # AS141383 as one large anycast operator.
        _pass("Nameserver posture", "Network diversity"),
        _pass("Nameserver posture", "IPv6 (AAAA) on nameservers", hardening=True),

        _pass("SOA & zone hygiene", "SOA present"),
        _pass("SOA & zone hygiene", "SOA MNAME reachable"),

        _pass("Core records", "A record (apex)"),
        _pass("Core records", "AAAA record (IPv6)", hardening=True),
        _pass("Core records", "CNAME at apex"),
        _pass("Core records", "CAA record", hardening=True),

        _pass("DNSSEC", "DNSSEC status", hardening=True),

        _pass("Security posture", "AXFR (zone transfer)"),
        _pass("Security posture", "Open recursive resolver"),
    ]
    rep.data["dnssec"] = {"state": "signed"}
    return rep


def test_vergecloud_grades_A_overall():
    """1-operator anycast + adopted hardening → A. This is the ground
    truth CLAUDE.md pins the whole anycast fix against."""
    g = grade(_vergecloud_shaped_report())
    assert g["overall"] == "A", (
        f"vergecloud.com-shape must grade A overall; got {g['overall']!r}. "
        f"If this fails with a D, the anycast classifier (C4) has "
        f"regressed OR the grade model is dragging correctness on a "
        f"single-operator diversity WARN. correctness={g.get('correctness_grade')!r}, "
        f"hardening={g.get('hardening_grade')!r}"
    )


def test_vergecloud_correctness_is_A():
    g = grade(_vergecloud_shaped_report())
    assert g["correctness_grade"] == "A", (
        f"vergecloud.com fixture is all-PASS on correctness; got "
        f"{g['correctness_grade']!r}"
    )


def test_vergecloud_no_hardening_gaps_for_adopted_features():
    """Every hardening finding in the fixture is PASS — hardening_gaps
    must be empty. If it isn't, PASS + hardening=True is leaking into
    the "unadopted" list, which would misrepresent the domain."""
    g = grade(_vergecloud_shaped_report())
    assert g["hardening_gaps"] == [], (
        f"hardening_gaps should be empty when every hardening-eligible "
        f"finding PASSes; got {g['hardening_gaps']!r}"
    )
