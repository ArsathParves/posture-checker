"""B5 — per-section vs overall grade reconciliation.

A user reading the report sees per-section grades (e.g. "Nameserver
posture: A", "Email authentication: D") AND an overall grade
(e.g. "Overall: C"). Without a reconciliation line, that gap looks
like a bug: "how does A + A + A + D become C?"

The answer is that overall does NOT average sections. It grades
the two orthogonal buckets — CORRECTNESS (misconfiguration
severity) and HARDENING (optional-feature adoption) — across the
WHOLE report, then blends them 0.8/0.2 with a CRITICAL floor.
Per-section grades are informational, not aggregable.

`grade()` already returns `correctness_grade`, `hardening_grade`,
`hardening_gaps`, and per-section bands, but the RECONCILIATION
between them is implicit — every renderer has to reconstruct the
formula. B5's mechanism step ships the reconciliation as data so
the CLI header and web SPA can display it without re-deriving.

This test pins the mechanism only (the `grade_reconciliation` key
and its sub-shape). CLI/web rendering of the reconciliation is
follow-up work — same mechanism-first pattern as T2/T5.
"""
from __future__ import annotations

from posture import checks as c
from posture.core import Report


# --------------------------------------------------------------------- shape

def test_grade_output_has_grade_reconciliation_key():
    """The reconciliation key is load-bearing: every renderer that
    wants to explain the overall grade reads it. Its absence would
    force renderers to hard-code the 0.8/0.2 formula, which drifts
    from the actual grading code."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Nameserver posture", "check", "PASS", "")
    result = c.grade(rep)
    assert "grade_reconciliation" in result, (
        "grade() must return grade_reconciliation for downstream renderers"
    )


def test_grade_reconciliation_has_stable_subshape():
    """The reconciliation sub-dict is a contract. Renaming a key
    would break every renderer at the same time."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Nameserver posture", "check", "PASS", "")
    r = c.grade(rep)["grade_reconciliation"]
    expected = {"formula", "correctness_weight", "hardening_weight",
                "critical_present", "critical_floors_to",
                "correctness_findings_count", "hardening_findings_count",
                "sections_note"}
    assert set(r.keys()) == expected, (
        f"grade_reconciliation shape drift: "
        f"added={set(r) - expected}, dropped={expected - set(r)}"
    )


# --------------------------------------------------------------------- semantics

def test_reconciliation_names_the_0_8_0_2_split():
    """The formula string carries the actual weights the code uses.
    A future refactor that changes the weights (e.g. to 0.7/0.3)
    without updating this string would ship a UI that lies about
    the formula."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Nameserver posture", "check", "PASS", "")
    r = c.grade(rep)["grade_reconciliation"]
    assert r["correctness_weight"] == 0.8
    assert r["hardening_weight"] == 0.2


def test_reconciliation_counts_correctness_vs_hardening_findings():
    """Counts drive the renderer's ability to say things like
    'overall reflects 3 correctness checks (A) and 2 hardening
    checks (C)'. Wrong counts → misleading legend."""
    rep = Report(domain_input="example.com", domain="example.com")
    # 3 correctness findings, 2 hardening findings.
    rep.add("Core records", "IPv4 (A)", "PASS", "")
    rep.add("SOA & health", "SOA readable", "PASS", "")
    rep.add("DNSSEC", "Chain validates", "FAIL", "")
    rep.add("Core records", "IPv6 (AAAA)", "WARN", "", hardening=True)
    rep.add("Email authentication", "MTA-STS policy", "WARN", "",
            hardening=True)
    r = c.grade(rep)["grade_reconciliation"]
    assert r["correctness_findings_count"] == 3
    assert r["hardening_findings_count"] == 2


def test_reconciliation_flags_critical_when_present():
    """CRITICAL findings floor overall to F. The reconciliation
    must surface this so the renderer can say 'overall is F because
    of the CRITICAL finding in Security posture', not just 'F'."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Nameserver posture", "check", "PASS", "")
    rep.add("Security posture", "AXFR open", "FAIL", "",
            severity="CRITICAL")
    r = c.grade(rep)["grade_reconciliation"]
    assert r["critical_present"] is True
    assert r["critical_floors_to"] == "F"


def test_reconciliation_critical_absent_when_no_critical_finding():
    """A clean report — no CRITICAL, no FAIL — must NOT claim
    critical_present. A false positive here would cause the
    renderer to display 'CRITICAL floor active' when it isn't."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Nameserver posture", "check", "PASS", "")
    r = c.grade(rep)["grade_reconciliation"]
    assert r["critical_present"] is False


def test_reconciliation_sections_note_names_per_section_as_informational():
    """The whole point of the reconciliation is to explain that
    per-section grades don't average into overall. The note must
    say so verbatim enough that a renderer can inline it, and a
    future refactor that starts averaging sections into overall
    trips the assertion below."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Nameserver posture", "check", "PASS", "")
    r = c.grade(rep)["grade_reconciliation"]
    note = r["sections_note"].lower()
    assert "informational" in note or "not aggregable" in note or "not a per-section average" in note


# --------------------------------------------------------------------- edge

def test_reconciliation_present_even_when_report_empty():
    """B6 short-circuits `overall` to '—' on an empty report. The
    reconciliation dict must still be present (so renderers don't
    KeyError) and its counts must be zero."""
    rep = Report(domain_input="example.com", domain="example.com")
    result = c.grade(rep)
    assert "grade_reconciliation" in result
    r = result["grade_reconciliation"]
    assert r["correctness_findings_count"] == 0
    assert r["hardening_findings_count"] == 0
    assert r["critical_present"] is False


def test_reconciliation_does_not_change_overall_grade():
    """Adding the reconciliation field must not change the overall
    grade — this is data-model exposure only, not a grading policy
    change. Regression backstop for the 'mechanism-only' claim."""
    rep = Report(domain_input="example.com", domain="example.com")
    for _ in range(9):
        rep.add("Nameserver posture", "check", "PASS", "")
    result = c.grade(rep)
    assert result["overall"] == "A", (
        "9-PASS baseline must still grade A — reconciliation is data-only"
    )
