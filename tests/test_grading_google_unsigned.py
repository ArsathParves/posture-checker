"""Regression test for G3 — pin the google.com "A overall despite
DNSSEC absent" guardrail.

Context: google.com serves an unsigned zone. That is a deliberate
operator choice, not a misconfiguration — a huge fraction of the
internet is in the same position. The grading model must not flatten
"chose not to adopt an optional hardening feature" into the same
letter as "misconfigured a hardening feature". CLAUDE.md ground-truth
test-domains table is explicit:

    google.com — DNSSEC unsigned by choice; must grade **A overall**
    (correctness A, hardening B) — NOT D. Guards against grade model
    punishing non-adoption.

The mechanism is `HARDENING_ABSENCE` (in `posture.checks.grade`) —
"DNSSEC status" with state=not_configured is routed to the hardening
sub-grade, not the correctness sub-grade. Overall is then
correctness*0.8 + hardening*0.2, so a single unadopted hardening
feature can pull hardening to B without dragging overall below A.

The audit called out that this behaviour was implemented but
unpinned. G2's upcoming refactor of `HARDENING_ABSENCE` from a global
set to a per-check attribute is exactly the sort of change that could
silently re-route DNSSEC into the correctness bucket and turn
google.com into a D-graded domain again. This test locks the
invariant in place first.

The finding shape used here mirrors google.com's live posture as of
2026-09: apex A + AAAA present, dual-stack nameservers, SPF present
with hard fail, DMARC with reporting, DKIM (Google's known selectors
answer), MTA-STS and TLS-RPT published, CAA record present. DNSSEC is
the sole non-adoption. No misconfigurations.
"""
from __future__ import annotations

from posture.checks import grade
from posture.core import Finding, Report


def _google_shaped_report() -> Report:
    """Report whose finding-set matches google.com's live posture: all
    correctness checks PASS, all optional hardening features adopted
    EXCEPT DNSSEC (state=not_configured). No misconfigurations."""
    rep = Report(domain_input="google.com", domain="google.com",
                 punycode="google.com")

    rep.findings = [
        # ---- Registration & delegation (all PASS) ----
        Finding("Registration & delegation", "Domain resolves", "PASS", "resolves"),
        Finding("Registration & delegation", "Registration record found",
                "PASS", "RDAP OK"),
        Finding("Registration & delegation", "Registrar lock", "PASS",
                "clientTransferProhibited, clientUpdateProhibited, clientDeleteProhibited"),
        Finding("Registration & delegation", "Expiry", "PASS",
                "renewed regularly"),
        Finding("Registration & delegation", "Parent delegation vs zone NS",
                "PASS", "parent and zone NS match"),

        # ---- Nameserver posture ----
        Finding("Nameserver posture", "Nameserver count", "PASS",
                "4 nameservers"),
        Finding("Nameserver posture", "Nameserver reachability", "PASS",
                "4/4 nameservers responded"),
        Finding("Nameserver posture", "Network diversity", "PASS",
                "1 operator (Google, AS15169) — large anycast estate"),
        # Hardening-eligible: PASS here because google.com's nameservers
        # ARE dual-stack. hardening=True mirrors the emit site (checks._nameservers).
        Finding("Nameserver posture", "IPv6 (AAAA) on nameservers", "PASS",
                "4/4 nameservers have AAAA", hardening=True),

        # ---- SOA & zone hygiene ----
        Finding("SOA & zone hygiene", "SOA present", "PASS", "SOA OK"),
        Finding("SOA & zone hygiene", "SOA MNAME reachable", "PASS", "reachable"),

        # ---- Core records ----
        Finding("Core records", "A record (apex)", "PASS", "1 A record"),
        # Hardening-eligible: PASS because google.com has AAAA. Emit site sets hardening=True.
        Finding("Core records", "AAAA record (IPv6)", "PASS",
                "1 AAAA record", hardening=True),
        Finding("Core records", "CNAME at apex", "PASS",
                "no CNAME at apex (compliant)"),
        # Hardening-eligible: PASS because google.com publishes CAA.
        Finding("Core records", "CAA record", "PASS",
                "CAA records present", hardening=True),
        Finding("Core records", "MX record", "PASS", "5 MX records"),

        # ---- DNSSEC ----
        # This is the sole non-adoption. state=not_configured → emit site
        # sets hardening=True; grade() routes it into the hardening bucket
        # via the attribute, NOT correctness.
        Finding("DNSSEC", "DNSSEC status", "FAIL",
                "Zone not signed — DS/DNSKEY absent", hardening=True),

        # ---- Email authentication ----
        Finding("Email authentication", "SPF", "PASS",
                "v=spf1 include:_spf.google.com ~all"),
        Finding("Email authentication", "SPF 'all' qualifier", "PASS",
                "-all (hard fail)"),
        Finding("Email authentication", "SPF DNS lookup count", "PASS",
                "4/10 lookups"),
        Finding("Email authentication", "DKIM", "PASS",
                "known selector answered"),
        Finding("Email authentication", "DMARC policy", "PASS",
                "p=reject"),
        # Hardening-eligible: PASS because google.com publishes rua.
        Finding("Email authentication", "DMARC reporting", "PASS",
                "rua=mailto:mailauth-reports@google.com", hardening=True),

        # ---- Security posture ----
        # Hardening-eligible: PASS because google.com publishes both.
        Finding("Security posture", "MTA-STS", "PASS",
                "policy present, mode=enforce", hardening=True),
        Finding("Security posture", "TLS-RPT", "PASS",
                "rua=mailto:...", hardening=True),
        Finding("Security posture", "AXFR (zone transfer)", "PASS",
                "refused on all 4 nameservers"),
        Finding("Security posture", "Open recursive resolver", "PASS",
                "no open recursion on 4 tested nameservers"),
    ]

    # Required for the DNSSEC-hardening-absence classifier: it reads
    # rep.data["dnssec"]["state"] to distinguish "not configured" (a
    # deliberate non-adoption, hardening bucket) from "broken" (a real
    # misconfiguration, correctness bucket). Without state=not_configured,
    # `is_hardening_absence` would fall through and DNSSEC would penalise
    # correctness. This is exactly the failure mode the test is guarding.
    rep.data["dnssec"] = {"state": "not_configured"}

    return rep


def test_google_unsigned_grades_A_overall():
    """Non-negotiable per CLAUDE.md test-domain table: unsigned by
    choice must be A overall, not D."""
    rep = _google_shaped_report()
    g = grade(rep)

    assert g["overall"] == "A", (
        f"google.com-shape must grade A overall (DNSSEC-absent is hardening, "
        f"not misconfiguration). Got overall={g['overall']!r} with "
        f"correctness={g.get('correctness_grade')!r}, "
        f"hardening={g.get('hardening_grade')!r}. "
        f"If HARDENING_ABSENCE was refactored, verify DNSSEC state="
        f"not_configured still routes into the hardening bucket."
    )


def test_google_unsigned_correctness_is_clean_A():
    """The correctness sub-grade must reflect that there is nothing
    actually misconfigured. The user's operational posture is clean;
    only an optional feature has been opted out of."""
    rep = _google_shaped_report()
    g = grade(rep)
    assert g["correctness_grade"] == "A", (
        f"correctness must be A when no genuine misconfiguration exists "
        f"(all correctness findings PASS); got {g['correctness_grade']!r}"
    )


def test_google_unsigned_dnssec_penalty_is_isolated_to_hardening():
    """The FAIL on DNSSEC must show up in the hardening sub-grade only.
    If it leaked into correctness, correctness would drop below A —
    which is exactly the false-D failure mode this test guards."""
    rep = _google_shaped_report()
    g = grade(rep)
    # Correctness must not be dragged down by the DNSSEC FAIL.
    assert g["correctness_grade"] == "A", \
        "DNSSEC FAIL leaked into correctness — HARDENING_ABSENCE routing broken"
    # Hardening reflects the DNSSEC non-adoption. With 6 hardening-eligible
    # PASSes and 1 hardening-eligible FAIL, expected: 12/(2*7) ≈ 0.857 → B.
    assert g["hardening_grade"] in {"B", "C"}, (
        f"hardening must reflect one unadopted hardening feature; "
        f"got {g['hardening_grade']!r}. If this loosens to A, the "
        f"hardening signal is being lost; if it tightens to D/F, the "
        f"hardening bucket was misclassified."
    )


def test_no_provisional_flag_when_all_findings_scored():
    """Belt-and-braces: the google-shape report has zero UNKNOWNs and
    no degraded modules, so grade()'s `provisional` flag must be
    False. A True here would mean a scored finding was silently
    demoted to UNKNOWN, which would itself be a bug."""
    rep = _google_shaped_report()
    g = grade(rep)
    assert g["provisional"] is False, \
        f"unexpected provisional flag: {g}"
