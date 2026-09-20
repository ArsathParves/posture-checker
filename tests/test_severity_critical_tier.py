"""T2 — CRITICAL severity tier.

Findings are flat PASS/WARN/FAIL. An open AXFR (full zone leak, every
subdomain revealed) currently weighs the same as a missing AAAA record —
both are a single FAIL in the same section. A section with one
zone-file-leaking FAIL and eight passing checks lands somewhere in the
B/C band by percentage math, which mis-represents the situation to a
Solutions Engineer briefing a customer.

T2 introduces a `severity="CRITICAL"` marker on `rep.add`. Semantics:

  - `severity` is orthogonal to `status`. A CRITICAL is still a
    real finding with PASS/WARN/FAIL; the marker adds "this specific
    finding is bad enough that the surrounding PASSes cannot dilute it".
  - Any section with a CRITICAL-marked FAIL grades **F** for that
    section, regardless of surrounding PASS count.
  - Overall grade floors at **F** whenever any section carries a
    CRITICAL FAIL (both correctness and overall bands).
  - CRITICAL PASS is legal but has no floor effect — you PASSED the
    critical check, so the section is fine.
  - CRITICAL WARN is treated the same as CRITICAL FAIL for the floor
    (a CRITICAL check that couldn't decide between FAIL and WARN is
    still bad enough to floor).
  - UNKNOWN never scores — a CRITICAL UNKNOWN is documented but does
    NOT floor (rule 1: unretrievable stays unretrievable; the tool
    cannot know if the CRITICAL fired).

These tests pin the mechanism only. Migration of specific existing
findings (open AXFR, EPP hold, open resolver) to CRITICAL are separate
commits — the mechanism must land first so callers have somewhere
to route to.
"""
from __future__ import annotations

from posture import checks as c
from posture.core import Report, Finding


# --------------------------------------------------------------------- Finding + Report.add support

def test_finding_accepts_severity():
    """The severity field is available on the dataclass and defaults
    to empty (backward compatible — every existing rep.add call
    stays green)."""
    f = Finding("Registration & delegation", "test", "FAIL", "detail")
    assert f.severity == ""


def test_report_add_accepts_severity_kwarg():
    """rep.add must forward severity to the Finding. Load-bearing:
    every migrated caller needs to pass severity="CRITICAL" at the
    emit site — a global label map would drift out of sync."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Registration & delegation", "Registry hold", "FAIL",
            "clientHold", "domain is suspended", severity="CRITICAL")
    assert len(rep.findings) == 1
    f = rep.findings[0]
    assert f.severity == "CRITICAL"
    assert f.status == "FAIL"


def test_critical_pass_is_valid():
    """A CRITICAL check that PASSED is still a PASS. The marker
    doesn't invert semantics — it says 'this finding is critical
    enough that its FAIL floors the grade', not 'this finding is
    always bad'."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Nameserver posture", "AXFR", "PASS", "closed",
            severity="CRITICAL")
    f = rep.findings[0]
    assert f.status == "PASS"
    assert f.severity == "CRITICAL"


# --------------------------------------------------------------------- grade() floor behaviour

def _fill_section(rep, section, statuses):
    """Populate a section with N findings of given statuses."""
    for i, status in enumerate(statuses):
        rep.add(section, f"check-{i}", status, "detail")


def test_critical_fail_floors_section_to_F():
    """T2 acceptance: one CRITICAL FAIL + eight PASSes → section
    grade F. Percentage math would give ~90% and a B, but the
    CRITICAL marker overrides that."""
    rep = Report(domain_input="example.com", domain="example.com")
    _fill_section(rep, "Nameserver posture", ["PASS"] * 8)
    rep.add("Nameserver posture", "AXFR open", "FAIL",
            "leaks entire zone", severity="CRITICAL")
    result = c.grade(rep)
    ns_band = result["sections"]["Nameserver posture"][0]
    assert ns_band == "F", (
        f"CRITICAL FAIL must floor section to F even with 8 surrounding "
        f"PASSes; got {ns_band}. Section bands: "
        f"{ {k: v[0] for k, v in result['sections'].items()} }"
    )


def test_critical_warn_also_floors():
    """A CRITICAL check that couldn't decide between FAIL and WARN is
    still bad enough to floor. Otherwise callers would be tempted to
    downgrade CRITICAL findings to WARN to soften the report — the
    exact opposite of the mechanism's intent."""
    rep = Report(domain_input="example.com", domain="example.com")
    _fill_section(rep, "Nameserver posture", ["PASS"] * 8)
    rep.add("Nameserver posture", "AXFR partial", "WARN",
            "one NS allows transfer", severity="CRITICAL")
    result = c.grade(rep)
    assert result["sections"]["Nameserver posture"][0] == "F"


def test_critical_pass_does_not_floor():
    """CRITICAL PASS = you PASSED the critical check → no floor. This
    guards the definition: CRITICAL marks "the finding matters", not
    "the finding is always bad"."""
    rep = Report(domain_input="example.com", domain="example.com")
    _fill_section(rep, "Nameserver posture", ["PASS"] * 8)
    rep.add("Nameserver posture", "AXFR closed", "PASS",
            "all NSes refused transfer", severity="CRITICAL")
    result = c.grade(rep)
    # 9 PASSes → A. CRITICAL PASS must not degrade it.
    assert result["sections"]["Nameserver posture"][0] == "A"


def test_critical_unknown_does_not_floor():
    """Rule 1: UNKNOWN never scores, and a CRITICAL UNKNOWN doesn't
    floor either — the tool cannot know if the CRITICAL condition
    fired. Otherwise a network hiccup during the AXFR probe would
    grade every zone F, which is the exact false-broken class
    CLAUDE.md rule 1 forbids."""
    rep = Report(domain_input="example.com", domain="example.com")
    _fill_section(rep, "Nameserver posture", ["PASS"] * 8)
    rep.add("Nameserver posture", "AXFR probe failed", "UNKNOWN",
            "TCP timeout", severity="CRITICAL")
    result = c.grade(rep)
    # 8 PASSes → A; UNKNOWN doesn't score.
    assert result["sections"]["Nameserver posture"][0] == "A"


def test_critical_floors_overall_to_F():
    """Overall grade floors at F when any section carries a CRITICAL
    FAIL. A CRITICAL is by definition worse than percentage math would
    otherwise indicate — it can't leave the overall in the B/C band."""
    rep = Report(domain_input="example.com", domain="example.com")
    _fill_section(rep, "Nameserver posture", ["PASS"] * 8)
    _fill_section(rep, "Registration & delegation", ["PASS"] * 8)
    _fill_section(rep, "DNSSEC", ["PASS"] * 8)
    rep.add("Registration & delegation", "Registry hold", "FAIL",
            "clientHold — domain suspended", severity="CRITICAL")
    result = c.grade(rep)
    assert result["overall"] == "F", (
        f"CRITICAL FAIL in any section must floor overall to F; "
        f"got overall={result['overall']}, "
        f"correctness_grade={result.get('correctness_grade')}"
    )


def test_no_critical_preserves_existing_grading():
    """Regression backstop: absent any CRITICAL marker, grading
    behaves exactly as it did before T2 — including for FAIL findings
    in a section otherwise full of PASSes."""
    rep = Report(domain_input="example.com", domain="example.com")
    # 9 PASSes, 1 non-CRITICAL FAIL. Percentage math places this in
    # the D band under `has_fail`.
    _fill_section(rep, "Nameserver posture", ["PASS"] * 9 + ["FAIL"])
    result = c.grade(rep)
    ns_band = result["sections"]["Nameserver posture"][0]
    assert ns_band != "F", (
        f"a non-CRITICAL FAIL surrounded by 9 PASSes must NOT floor "
        f"to F (that's the whole point of the severity distinction); "
        f"got {ns_band}"
    )


def test_critical_hardening_still_floors_correctness():
    """A CRITICAL finding is by nature correctness, not hardening — a
    CRITICAL-marked "optional adoption gap" is a contradiction. If a
    caller passes both `severity="CRITICAL"` and `hardening=True`, the
    CRITICAL floor still applies to correctness (defensive: prefer the
    stronger signal). Load-bearing: this prevents the "hardening
    hides critical" false-negative class."""
    rep = Report(domain_input="example.com", domain="example.com")
    _fill_section(rep, "Nameserver posture", ["PASS"] * 8)
    rep.add("Nameserver posture", "AXFR open", "FAIL",
            "leak", hardening=True, severity="CRITICAL")
    result = c.grade(rep)
    # CRITICAL wins over hardening classification.
    assert result["correctness_grade"] == "F"
